
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict

from .parser import CowrieLogParser
from .cleanser import LogCleanser
from .deduplicator import SessionDeduplicator

logger = logging.getLogger(__name__)


class HoneypotPipeline:
    """Main pipeline orchestrator for honeypot log processing."""

    def __init__(self, 
                 log_path: str,
                 deduplicate: bool = True,
                 noise_filter: bool = True,
                 output_dir: str = "data/processed"):
        self.log_path = log_path
        self.deduplicate = deduplicate
        self.noise_filter = noise_filter
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.parser = CowrieLogParser()
        self.cleanser = LogCleanser(noise_filter=noise_filter)
        self.deduplicator = SessionDeduplicator() if deduplicate else None

        self.sessions: Dict[str, List[Dict]] = defaultdict(list)
        self.processed_sessions: List[Dict[str, Any]] = []

    def run(self) -> List[Dict[str, Any]]:
        """Run the full pipeline."""
        logger.info("Starting honeypot pipeline...")

        # Parse logs
        events = self._parse_logs()

        # Clean events
        cleaned = self._clean_events(events)

        # Build sessions
        self._build_sessions(cleaned)

        # Deduplicate
        if self.deduplicate:
            self._deduplicate_sessions()

        logger.info(f"Pipeline complete: {len(self.processed_sessions)} sessions")
        return self.processed_sessions

    def _parse_logs(self) -> List[Dict[str, Any]]:
        """Parse raw log files."""
        path = Path(self.log_path)
        events = []

        if path.is_file():
            for event in self.parser.parse_file(str(path)):
                events.append(event)
        elif path.is_dir():
            for event in self.parser.parse_directory(str(path)):
                events.append(event)
        else:
            raise FileNotFoundError(f"Log path not found: {self.log_path}")

        logger.info(f"Parsed {len(events)} events")
        return events

    def _clean_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Clean and filter events."""
        cleaned = self.cleanser.cleanse_events(events)
        logger.info(f"Cleaned: {len(cleaned)} events (removed {len(events) - len(cleaned)} noise)")
        return cleaned

    def _build_sessions(self, events: List[Dict[str, Any]]):
        """Group events into sessions."""
        for event in events:
            session_id = event.get("session", "unknown")
            self.sessions[session_id].append(event)

        # Sort events within each session by timestamp
        for session_id in self.sessions:
            self.sessions[session_id].sort(key=lambda e: e.get("timestamp", datetime.min))

        # Convert to session dicts
        for session_id, events in self.sessions.items():
            if not events:
                continue

            commands = [e.get("input", "") for e in events if e.get("input")]

            session = {
                "session_id": session_id,
                "src_ip": events[0].get("src_ip", "unknown"),
                "start_time": events[0].get("timestamp"),
                "end_time": events[-1].get("timestamp"),
                "commands": commands,
                "command_count": len(commands),
                "events": events
            }
            self.processed_sessions.append(session)

        logger.info(f"Built {len(self.processed_sessions)} sessions")

    def _deduplicate_sessions(self):
        """Remove duplicate sessions."""
        original_count = len(self.processed_sessions)
        self.processed_sessions = self.deduplicator.deduplicate_sessions(self.processed_sessions)
        logger.info(f"Deduplicated: {original_count} -> {len(self.processed_sessions)} sessions")

    def save_sessions(self, filename: str = "sessions.json"):
        """Save processed sessions to JSON."""
        output_path = self.output_dir / filename
        with open(output_path, "w") as f:
            json.dump(self.processed_sessions, f, indent=2, default=str)
        logger.info(f"Saved sessions to {output_path}")

    def get_stats(self) -> Dict[str, Any]:
        """Return pipeline statistics."""
        stats = {
            "parser": self.parser.get_stats(),
            "cleanser": self.cleanser.get_stats(),
            "sessions": len(self.processed_sessions),
        }
        if self.deduplicate:
            stats["deduplicator"] = self.deduplicator.get_stats()
        return stats
