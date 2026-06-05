"""
Log Cleanser Module
Noise reduction, normalization, and data quality enforcement.
"""

import re
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class LogCleanser:
    """
    Cleans and normalizes honeypot log events.

    Features:
    - Noise pattern filtering (scanner probes, empty commands)
    - Command normalization (path canonicalization, argument stripping)
    - Encoding standardization (UTF-8 enforcement)
    - Suspicious pattern flagging
    """

    # Patterns considered noise (low-value scanner behavior)
    NOISE_PATTERNS = [
        r'^\s*$',                           # Empty commands
        r'^\s*ls\s*$',                      # Bare ls
        r'^\s*pwd\s*$',                     # Bare pwd  
        r'^\s*whoami\s*$',                   # Bare whoami
        r'^\s*id\s*$',                       # Bare id
        r'^\s*exit\s*$',                     # Bare exit
        r'^\s*uname\s*$',                   # Bare uname
        r'^\s*cat\s+/proc/version\s*$',    # Version check only
        r'^\s*echo\s+[^>]*$',               # Echo without redirection
    ]

    # Suspicious patterns to flag
    SUSPICIOUS_PATTERNS = {
        'download': r'(wget|curl|fetch|tftp|ftpget)\s+',
        'privilege_escalation': r'(sudo|su\s+-|chmod\s+\+x|chmod\s+777)',
        'persistence': r'(crontab|systemctl\s+enable|echo\s+.*>>\s*/etc/|chmod\s+777)',
        'network_tool': r'(nc\s|netcat|nmap\s|masscan)',
        'obfuscation': r'(base64|eval\s*\(|\$\(|`.*`)',
        'crypto_miner': r'(xmrig|minerd|stratum\+tcp)',
    }

    def __init__(self, 
                 noise_filter: bool = True,
                 normalize_commands: bool = True,
                 flag_suspicious: bool = True):
        """
        Initialize cleanser.

        Args:
            noise_filter: Remove noise patterns
            normalize_commands: Canonicalize command strings
            flag_suspicious: Add suspicious pattern flags
        """
        self.noise_filter = noise_filter
        self.normalize_commands = normalize_commands
        self.flag_suspicious = flag_suspicious
        self.noise_count = 0
        self.cleaned_count = 0

        self._noise_regex = [re.compile(p, re.IGNORECASE) for p in self.NOISE_PATTERNS]
        self._suspicious_regex = {k: re.compile(v, re.IGNORECASE) 
                                    for k, v in self.SUSPICIOUS_PATTERNS.items()}

    def cleanse_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Clean a single event.

        Args:
            event: Raw event dict

        Returns:
            Cleaned event or None if filtered as noise
        """
        if not event or "input" not in event:
            return None

        command = event.get("input", "")

        # Noise filtering
        if self.noise_filter and self._is_noise(command):
            self.noise_count += 1
            return None

        # Command normalization
        if self.normalize_commands:
            event["input"] = self._normalize_command(command)
            event["input_original"] = command  # Keep original

        # Suspicious pattern flagging
        if self.flag_suspicious:
            event["suspicious_flags"] = self._detect_suspicious(command)

        self.cleaned_count += 1
        return event

    def cleanse_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Clean multiple events.

        Args:
            events: List of raw event dicts

        Returns:
            List of cleaned events
        """
        cleaned = []
        for event in events:
            result = self.cleanse_event(event)
            if result:
                cleaned.append(result)
        return cleaned

    def _is_noise(self, command: str) -> bool:
        """Check if command matches noise patterns."""
        for pattern in self._noise_regex:
            if pattern.match(command):
                return True
        return False

    def _normalize_command(self, command: str) -> str:
        """
        Normalize command string.

        Steps:
        1. Strip whitespace
        2. Collapse multiple spaces
        3. Canonicalize common paths
        4. Lowercase for consistency
        """
        # Strip and collapse spaces
        cmd = command.strip()
        cmd = re.sub(r'\s+', ' ', cmd)

        # Canonicalize paths
        cmd = cmd.replace('/tmp//', '/tmp/')
        cmd = cmd.replace('/var/tmp//', '/var/tmp/')

        # Lowercase (preserving URLs which are case-sensitive)
        # Only lowercase the command part, not URLs
        parts = cmd.split(' ', 1)
        if parts:
            parts[0] = parts[0].lower()
            cmd = ' '.join(parts)

        return cmd

    def _detect_suspicious(self, command: str) -> List[str]:
        """Detect suspicious patterns in command."""
        flags = []
        for name, pattern in self._suspicious_regex.items():
            if pattern.search(command):
                flags.append(name)
        return flags

    def get_stats(self) -> Dict[str, int]:
        """Return cleansing statistics."""
        return {
            "cleaned": self.cleaned_count,
            "noise_filtered": self.noise_count,
            "total_processed": self.cleaned_count + self.noise_count
        }
