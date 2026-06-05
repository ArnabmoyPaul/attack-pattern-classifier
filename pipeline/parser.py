"""
Cowrie Honeypot JSON Log Parser
Memory-efficient streaming parser for large log files.
"""

import json
import gzip
from pathlib import Path
from typing import Iterator, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class CowrieLogParser:
    """
    Streaming parser for Cowrie honeypot JSON logs.

    Handles:
    - Plain JSON (.json) and gzipped (.json.gz) files
    - Line-by-line streaming for memory efficiency
    - Timestamp parsing and validation
    - Event filtering by type
    """

    VALID_EVENT_IDS = {
        "cowrie.command.input",
        "cowrie.command.failed",
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.session.connect",
        "cowrie.session.closed",
        "cowrie.client.version",
        "cowrie.client.size",
    }

    DEFAULT_EVENT_FILTER = VALID_EVENT_IDS - {"cowrie.login.failed"}

    def __init__(self, event_filter: Optional[set] = None):
        """
        Initialize parser.

        Args:
            event_filter: Set of event IDs to include. If None, includes the default event filter.
        """
        self.event_filter = event_filter or self.DEFAULT_EVENT_FILTER
        self.parsed_count = 0
        self.error_count = 0

    def parse_file(self, filepath: str) -> Iterator[Dict[str, Any]]:
        """
        Parse a single log file (plain or gzipped).

        Args:
            filepath: Path to .json or .json.gz file

        Yields:
            Dict containing parsed event data
        """
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        opener = gzip.open if filepath.endswith('.gz') else open

        with opener(filepath, 'rt', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)

                    # Filter by event type
                    if event.get("eventid") not in self.event_filter:
                        continue

                    # Parse and validate timestamp
                    event = self._normalize_event(event)

                    self.parsed_count += 1
                    yield event

                except json.JSONDecodeError as e:
                    self.error_count += 1
                    logger.warning(f"JSON parse error at line {line_num}: {e}")
                    continue
                except Exception as e:
                    self.error_count += 1
                    logger.error(f"Unexpected error at line {line_num}: {e}")
                    continue

    def parse_directory(self, directory: str, pattern: str = "cowrie*.json*") -> Iterator[Dict[str, Any]]:
        """
        Parse all matching log files in a directory.

        Args:
            directory: Directory path containing log files
            pattern: Glob pattern for matching files

        Yields:
            Dict containing parsed event data
        """
        dir_path = Path(directory)

        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        files = list(dir_path.glob(pattern))
        logger.info(f"Found {len(files)} log files matching '{pattern}'")

        for filepath in sorted(files):
            logger.info(f"Parsing: {filepath}")
            yield from self.parse_file(str(filepath))

    def _normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize and validate event fields.

        Args:
            event: Raw event dict

        Returns:
            Normalized event dict
        """
        # Parse timestamp
        ts_str = event.get("timestamp", "")
        if isinstance(ts_str, str):
            try:
                event["timestamp"] = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except ValueError:
                event["timestamp"] = datetime.utcnow()
        elif isinstance(ts_str, (int, float)):
            # Unix timestamp
            event["timestamp"] = datetime.utcfromtimestamp(ts_str)

        # Ensure required fields exist
        event.setdefault("session", "unknown")
        event.setdefault("src_ip", "0.0.0.0")
        event.setdefault("input", "")
        event.setdefault("duration", 0.0)

        # Clean input command
        if "input" in event and event["input"]:
            event["input"] = event["input"].strip()

        return event

    def get_stats(self) -> Dict[str, int]:
        """Return parsing statistics."""
        return {
            "parsed": self.parsed_count,
            "errors": self.error_count,
            "success_rate": self.parsed_count / (self.parsed_count + self.error_count) 
                           if (self.parsed_count + self.error_count) > 0 else 0.0
        }
