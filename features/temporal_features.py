
import numpy as np
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta


class TemporalFeatureExtractor:
    """Extract temporal features from session command sequences."""

    def __init__(self, idle_threshold: float = 5.0):
        """
        Initialize extractor.

        Args:
            idle_threshold: Seconds between commands to consider as idle period
        """
        self.idle_threshold = idle_threshold

    def extract(self, session: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract temporal features from a session.

        Args:
            session: Session dict with 'events' (list of events with timestamps)

        Returns:
            Dict of temporal feature values
        """
        events = session.get("events", [])

        if not events:
            return self._empty_features()

        # Extract timestamps
        timestamps = []
        for event in events:
            ts = event.get("timestamp")
            if isinstance(ts, datetime):
                timestamps.append(ts)
            elif isinstance(ts, str):
                try:
                    timestamps.append(datetime.fromisoformat(ts.replace('Z', '+00:00')))
                except ValueError:
                    continue

        if len(timestamps) < 2:
            return self._empty_features()

        timestamps.sort()

        # Time deltas between consecutive commands
        deltas = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                  for i in range(len(timestamps) - 1)]

        # Session duration
        duration = (timestamps[-1] - timestamps[0]).total_seconds()

        # Burst analysis
        burst_commands = [d for d in deltas if d <= 1.0]  # Commands within 1 second

        # Idle periods
        idle_periods = [d for d in deltas if d >= self.idle_threshold]

        features = {
            "session_duration": duration,
            "command_count": len(events),
            "mean_delta": np.mean(deltas) if deltas else 0.0,
            "median_delta": np.median(deltas) if deltas else 0.0,
            "std_delta": np.std(deltas) if deltas else 0.0,
            "min_delta": min(deltas) if deltas else 0.0,
            "max_delta": max(deltas) if deltas else 0.0,
            "burst_rate": len(burst_commands) / duration * 60 if duration > 0 else 0.0,
            "idle_period_count": len(idle_periods),
            "idle_period_mean": np.mean(idle_periods) if idle_periods else 0.0,
            "idle_period_total": sum(idle_periods) if idle_periods else 0.0,
            "commands_per_minute": len(events) / duration * 60 if duration > 0 else 0.0,
            "start_hour": timestamps[0].hour,
            "start_day_of_week": timestamps[0].weekday(),
            "is_weekend": 1 if timestamps[0].weekday() >= 5 else 0,
            "coefficient_of_variation": np.std(deltas) / np.mean(deltas) 
                                       if deltas and np.mean(deltas) > 0 else 0.0,
        }

        return features

    def extract_batch(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, float]]:
        """Extract temporal features for multiple sessions."""
        return [self.extract(session) for session in sessions]

    def _empty_features(self) -> Dict[str, float]:
        """Return empty feature dict with all keys."""
        return {
            "session_duration": 0.0,
            "mean_delta": 0.0,
            "median_delta": 0.0,
            "std_delta": 0.0,
            "min_delta": 0.0,
            "max_delta": 0.0,
            "burst_rate": 0.0,
            "idle_period_count": 0.0,
            "idle_period_mean": 0.0,
            "idle_period_total": 0.0,
            "commands_per_minute": 0.0,
            "start_hour": 0.0,
            "start_day_of_week": 0.0,
            "is_weekend": 0.0,
            "coefficient_of_variation": 0.0,
        }
