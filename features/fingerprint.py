
import hashlib
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta


class FingerprintGenerator:
    """Generate behavior fingerprints and correlate botnet campaigns."""

    def __init__(self, 
                 include_temporal: bool = True,
                 include_count: bool = True):
        """
        Initialize fingerprint generator.

        Args:
            include_temporal: Include session duration in hash
            include_count: Include command count in hash
        """
        self.include_temporal = include_temporal
        self.include_count = include_count

    def generate(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate behavior fingerprints for all sessions.

        Args:
            sessions: List of session dicts

        Returns:
            List of sessions with fingerprint added
        """
        fingerprinted = []

        for session in sessions:
            fp = self._generate_single(session)
            session["behavior_fingerprint"] = fp
            fingerprinted.append(session)

        return fingerprinted

    def _generate_single(self, session: Dict[str, Any]) -> str:
        """Generate fingerprint for a single session."""
        commands = session.get("commands", [])

        # Step 1: Normalize commands
        normalized = self._normalize_commands(commands)

        # Step 2: Categorize (MITRE ATT&CK mapping)
        categories = self._categorize_commands(normalized)

        # Step 3: Build hash input
        hash_parts = ["|".join(sorted(set(categories)))]

        if self.include_temporal:
            duration = session.get("session_duration", 0.0)
            hash_parts.append(f"duration={duration:.0f}s")

        if self.include_count:
            cmd_count = len(commands)
            hash_parts.append(f"cmd_count={cmd_count}")

        hash_input = "|".join(hash_parts)

        # Step 4: Generate SHA-256 hash
        return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

    def correlate_campaigns(self, 
                           sessions: List[Dict[str, Any]], 
                           time_window: str = "24h",
                           min_ips: int = 3) -> Dict[str, Dict[str, Any]]:
        """
        Correlate sessions into botnet campaigns.

        Args:
            sessions: List of fingerprinted sessions
            time_window: Time window for correlation (e.g., "24h", "7d")
            min_ips: Minimum unique IPs to qualify as campaign

        Returns:
            Dict of campaign_id -> campaign info
        """
        # Parse time window
        window_hours = self._parse_time_window(time_window)

        # Group by fingerprint
        fingerprint_groups = defaultdict(list)
        for session in sessions:
            fp = session.get("behavior_fingerprint")
            if fp:
                fingerprint_groups[fp].append(session)

        # Identify campaigns
        campaigns = {}
        campaign_counter = 0

        for fp, group in fingerprint_groups.items():
            # Get unique IPs and time range
            unique_ips = set(s.get("src_ip", "unknown") for s in group)

            if len(unique_ips) < min_ips:
                continue

            timestamps = []
            for s in group:
                ts = s.get("start_time")
                if isinstance(ts, datetime):
                    timestamps.append(ts)
                elif isinstance(ts, str):
                    try:
                        timestamps.append(datetime.fromisoformat(ts.replace('Z', '+00:00')))
                    except ValueError:
                        pass

            if not timestamps:
                continue

            timestamps.sort()
            duration_days = (timestamps[-1] - timestamps[0]).total_seconds() / 86400

            campaign_counter += 1
            campaign_id = f"CAMPAIGN_{campaign_counter:04d}"

            # Determine campaign type from commands
            all_commands = []
            for s in group:
                all_commands.extend(s.get("commands", []))

            campaign_type = self._classify_campaign(all_commands)

            campaigns[campaign_id] = {
                "fingerprint": fp,
                "unique_ips": len(unique_ips),
                "ip_list": list(unique_ips),
                "session_count": len(group),
                "first_seen": timestamps[0].isoformat() if timestamps else None,
                "last_seen": timestamps[-1].isoformat() if timestamps else None,
                "duration_days": duration_days,
                "campaign_type": campaign_type,
                "sample_commands": all_commands[:5] if all_commands else []
            }

        return campaigns

    def _normalize_commands(self, commands: List[str]) -> List[str]:
        """Normalize command list for fingerprinting."""
        normalized = []
        for cmd in commands:
            if not cmd:
                continue
            # Lowercase, strip args, canonicalize
            parts = cmd.split()
            if parts:
                base = parts[0].lower()
                normalized.append(base)
        return normalized

    def _categorize_commands(self, commands: List[str]) -> List[str]:
        """Map commands to MITRE ATT&CK-like categories."""
        categories = []
        category_map = {
            'wget': 'T1105', 'curl': 'T1105', 'fetch': 'T1105',
            'chmod': 'T1222', 'chown': 'T1222',
            'crontab': 'T1053', 'systemctl': 'T1053',
            'ssh': 'T1021', 'scp': 'T1021',
            'nc': 'T1095', 'netcat': 'T1095',
            'base64': 'T1027', 'eval': 'T1059',
            'python': 'T1059', 'bash': 'T1059',
            'nmap': 'T1046', 'masscan': 'T1046',
        }

        for cmd in commands:
            cat = category_map.get(cmd, 'OTHER')
            categories.append(cat)

        return categories

    def _parse_time_window(self, window: str) -> int:
        """Parse time window string to hours."""
        unit = window[-1]
        value = int(window[:-1])

        if unit == 'h':
            return value
        elif unit == 'd':
            return value * 24
        elif unit == 'w':
            return value * 24 * 7
        else:
            return 24  # Default

    def _classify_campaign(self, commands: List[str]) -> str:
        """Classify campaign type from command patterns."""
        cmd_str = " ".join(commands).lower()

        if any(c in cmd_str for c in ['xmrig', 'minerd', 'stratum', 'pool']):
            return "CRYPTOMINER"
        elif any(c in cmd_str for c in ['mirai', 'botnet', 'bricker', 'iot']):
            return "BOTNET"
        elif any(c in cmd_str for c in ['ransom', 'encrypt', 'bitcoin', 'wallet']):
            return "RANSOMWARE"
        elif 'wget' in cmd_str and 'chmod' in cmd_str:
            return "PAYLOAD_DEPLOYMENT"
        elif 'nmap' in cmd_str or 'masscan' in cmd_str:
            return "RECONNAISSANCE"
        elif 'crontab' in cmd_str or 'systemctl' in cmd_str:
            return "PERSISTENCE"
        else:
            return "UNKNOWN"
