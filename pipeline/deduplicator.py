
import hashlib
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class SessionDeduplicator:
    """Deduplicates attack sessions using cryptographic hashing."""

    def __init__(self, strategy: str = "exact", keep_metadata: bool = True):
        self.strategy = strategy
        self.keep_metadata = keep_metadata
        self.seen_hashes: Set[str] = set()
        self.duplicate_count = 0
        self.unique_count = 0
        self._session_metadata: Dict[str, Dict] = defaultdict(
            lambda: {"src_ips": set(), "timestamps": [], "count": 0}
        )

    def deduplicate_sessions(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique_sessions = []
        for session in sessions:
            session_hash = self._compute_hash(session)
            if session_hash in self.seen_hashes:
                self.duplicate_count += 1
                if self.keep_metadata:
                    self._merge_metadata(session_hash, session)
                continue
            self.seen_hashes.add(session_hash)
            self.unique_count += 1
            if self.keep_metadata:
                self._merge_metadata(session_hash, session)
                session["duplicate_metadata"] = dict(self._session_metadata[session_hash])
            unique_sessions.append(session)
        logger.info(f"Deduplication: {self.unique_count} unique, {self.duplicate_count} removed")
        return unique_sessions

    def _compute_hash(self, session: Dict[str, Any]) -> str:
        commands = session.get("commands", [])
        if self.strategy == "exact":
            command_str = "|".join(commands)
        elif self.strategy == "fuzzy":
            command_str = "|".join(sorted(set(commands)))
        else:
            raise ValueError(f"Unknown strategy: {self.strategy}")
        return hashlib.sha256(command_str.encode("utf-8")).hexdigest()

    def _merge_metadata(self, session_hash: str, session: Dict[str, Any]):
        meta = self._session_metadata[session_hash]
        meta["src_ips"].add(session.get("src_ip", "unknown"))
        meta["timestamps"].append(session.get("start_time", ""))
        meta["count"] += 1

    def get_stats(self) -> Dict[str, Any]:
        total = self.unique_count + self.duplicate_count
        return {
            "unique_sessions": self.unique_count,
            "duplicate_sessions": self.duplicate_count,
            "deduplication_ratio": self.duplicate_count / total if total > 0 else 0.0,
            "strategy": self.strategy
        }

    def reset(self):
        self.seen_hashes.clear()
        self.duplicate_count = 0
        self.unique_count = 0
        self._session_metadata.clear()
