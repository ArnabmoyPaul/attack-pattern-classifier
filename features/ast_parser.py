"""
Command AST Parser with MITRE ATT&CK Technique Mapping
Maps Linux shell commands to ATT&CK techniques for threat intelligence enrichment.
Based on research: Mapping Linux Shell Commands to MITRE ATT&CK using NLP-Based Approach
"""

import re
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter


class CommandASTParser:
    """Parse shell commands into structured AST-like representations with ATT&CK mapping."""

    # MITRE ATT&CK Technique Mappings (from research and framework)
    # Tactics: TA0001 Initial Access, TA0002 Execution, TA0003 Persistence,
    #         TA0004 Privilege Escalation, TA0005 Defense Evasion,
    #         TA0006 Credential Access, TA0007 Discovery, TA0008 Lateral Movement,
    #         TA0009 Collection, TA0010 Exfiltration, TA0011 Command and Control

    COMMAND_CATEGORIES = {
        # Reconnaissance / Discovery (TA0007, TA0043)
        'recon': ['ls', 'pwd', 'whoami', 'id', 'uname', 'cat', 'ps', 'netstat', 
                  'ifconfig', 'ip', 'ss', 'lsof', 'df', 'du', 'find', 'locate',
                  'nmap', 'masscan', 'zmap', 'nikto', 'dirb', 'gobuster'],

        # Ingress Tool Transfer / Download (T1105)
        'download': ['wget', 'curl', 'fetch', 'tftp', 'ftpget', 'scp', 'sftp',
                     'rsync', 'nc', 'netcat', 'python', 'perl', 'ruby'],

        # Execution (TA0002)
        'execute': ['sh', 'bash', 'python', 'perl', 'ruby', 'php', 'nohup', 
                    './', 'exec', 'eval', 'source', '.'],

        # Privilege Escalation (TA0004)
        'privilege': ['sudo', 'su', 'chmod', 'chown', 'setuid', 'setgid',
                      'pkexec', 'doas', 'passwd', 'usermod'],

        # Persistence (TA0003)
        'persist': ['crontab', 'systemctl', 'service', 'chkconfig', 'echo', 
                    'cat', 'sed', 'awk', 'chmod', 'chown', 'useradd', 'usermod'],

        # Credential Access (TA0006)
        'credential': ['cat', 'grep', 'find', 'unshadow', 'john', 'hashcat',
                       'mimikatz', 'mimipenguin', 'laZagne'],

        # Lateral Movement (TA0008)
        'lateral': ['ssh', 'scp', 'sftp', 'rsync', 'rdesktop', 'xfreerdp',
                    'nc', 'netcat', 'socat', 'proxychains'],

        # Defense Evasion (TA0005)
        'evasion': ['base64', 'xxd', 'hexdump', 'openssl', 'steganography',
                    'timestomp', 'chattr', 'iptables', 'ufw'],

        # Collection (TA0009)
        'collection': ['tar', 'zip', 'gzip', 'bzip2', '7z', 'rar',
                       'dd', 'cat', 'grep', 'awk', 'sed'],

        # Exfiltration (TA0010)
        'exfil': ['curl', 'wget', 'nc', 'netcat', 'scp', 'sftp', 'ftp',
                  'tftp', 'rsync', 'python', 'perl'],

        # Command and Control (TA0011)
        'c2': ['nc', 'netcat', 'socat', 'python', 'perl', 'ruby', 'php',
               'openssl', 'ssh', 'dns', 'icmp'],
    }

    # MITRE ATT&CK Technique IDs for specific commands
    TECHNIQUE_MAPPING = {
        'wget': ('T1105', 'Ingress Tool Transfer'),
        'curl': ('T1105', 'Ingress Tool Transfer'),
        'chmod': ('T1222', 'File and Directory Permissions Modification'),
        'chown': ('T1222', 'File and Directory Permissions Modification'),
        'crontab': ('T1053', 'Scheduled Task/Job'),
        'systemctl': ('T1543', 'Create or Modify System Process'),
        'ssh': ('T1021', 'Remote Services'),
        'scp': ('T1021', 'Remote Services'),
        'nc': ('T1095', 'Non-Application Layer Protocol'),
        'netcat': ('T1095', 'Non-Application Layer Protocol'),
        'nmap': ('T1046', 'Network Service Scanning'),
        'masscan': ('T1046', 'Network Service Scanning'),
        'base64': ('T1027', 'Obfuscated Files or Information'),
        'eval': ('T1059', 'Command and Scripting Interpreter'),
        'python': ('T1059', 'Command and Scripting Interpreter'),
        'bash': ('T1059', 'Command and Scripting Interpreter'),
        'sh': ('T1059', 'Command and Scripting Interpreter'),
        'sudo': ('T1548', 'Abuse Elevation Control Mechanism'),
        'su': ('T1548', 'Abuse Elevation Control Mechanism'),
        'cat': ('T1005', 'Data from Local System'),
        'grep': ('T1005', 'Data from Local System'),
        'tar': ('T1560', 'Archive Collected Data'),
        'zip': ('T1560', 'Archive Collected Data'),
        'useradd': ('T1136', 'Create Account'),
        'usermod': ('T1136', 'Create Account'),
        'passwd': ('T1098', 'Account Manipulation'),
        'iptables': ('T1562', 'Impair Defenses'),
        'ufw': ('T1562', 'Impair Defenses'),
        'find': ('T1083', 'File and Directory Discovery'),
        'locate': ('T1083', 'File and Directory Discovery'),
        'ps': ('T1057', 'Process Discovery'),
        'netstat': ('T1049', 'System Network Connections Discovery'),
        'ifconfig': ('T1049', 'System Network Connections Discovery'),
        'ip': ('T1049', 'System Network Connections Discovery'),
        'whoami': ('T1033', 'System Owner/User Discovery'),
        'id': ('T1033', 'System Owner/User Discovery'),
        'uname': ('T1082', 'System Information Discovery'),
        'ls': ('T1083', 'File and Directory Discovery'),
        'pwd': ('T1083', 'File and Directory Discovery'),
        'df': ('T1082', 'System Information Discovery'),
        'du': ('T1082', 'System Information Discovery'),
        'lsof': ('T1049', 'System Network Connections Discovery'),
        'ss': ('T1049', 'System Network Connections Discovery'),
    }

    # Suspicious pattern detection
    SUSPICIOUS_PATTERNS = {
        'download': r'(wget|curl|fetch|tftp|ftpget)\s+',
        'privilege_escalation': r'(sudo|su\s+-|chmod\s+\+x|chmod\s+777|pkexec)',
        'persistence': r'(crontab|systemctl\s+enable|echo\s+.*>>\s*/etc/|chkconfig)',
        'network_tool': r'(nc\s|netcat|nmap\s|masscan|zmap)',
        'obfuscation': r'(base64|eval\s*\(|\$\(|`.*`|\\x[0-9a-fA-F]{2})',
    }

    def __init__(self):
        self.command_stats = Counter()
        self.technique_stats = Counter()

    def parse(self, command: str) -> Dict[str, Any]:
        """Parse a single command into structured features with ATT&CK mapping."""
        if not command or not isinstance(command, str):
            return self._empty_parse()

        tokens = self._tokenize(command)
        base_cmd = tokens[0].lower() if tokens else ""
        if base_cmd.startswith("./"):
            base_cmd = "./"
        elif "/" in base_cmd:
            base_cmd = base_cmd.split("/")[-1]

        # Get ATT&CK technique mapping
        technique_id, technique_name = self.TECHNIQUE_MAPPING.get(
            base_cmd, ("TXXXX", "Unknown Technique")
        )

        parse_result = {
            "raw": command,
            "tokens": tokens,
            "base_command": base_cmd,
            "token_count": len(tokens),
            "unique_tokens": len(set(tokens)),
            "has_arguments": len(tokens) > 1,
            "category": self._categorize(base_cmd),
            "mitre_technique_id": technique_id,
            "mitre_technique_name": technique_name,
            "flags": self._extract_flags(tokens),
            "paths": self._extract_paths(command),
            "urls": self._extract_urls(command),
            "ips": self._extract_ips(command),
            "has_obfuscation": self._detect_obfuscation(command),
            "has_pipe": "|" in command,
            "has_redirect": any(c in command for c in [">", "<", ">>", "<<"]),
            "has_background": "&" in command,
            "has_substitution": "$" in command or "`" in command,
            "suspicious_flags": self._detect_suspicious(command),
        }

        self.command_stats[base_cmd] += 1
        if technique_id != "TXXXX":
            self.technique_stats[technique_id] += 1

        return parse_result

    def parse_session(self, commands: List[str]) -> Dict[str, Any]:
        """Parse all commands in a session with ATT&CK technique aggregation."""
        parsed_commands = [self.parse(cmd) for cmd in commands if cmd]

        categories = [p["category"] for p in parsed_commands]
        category_sequence = "|".join(categories)

        # Aggregate MITRE techniques
        techniques = {}
        for p in parsed_commands:
            tid = p["mitre_technique_id"]
            if tid != "TXXXX":
                techniques[tid] = p["mitre_technique_name"]

        # Detect attack chain patterns
        attack_chain = self._detect_attack_chain(parsed_commands)

        return {
            "commands": parsed_commands,
            "category_sequence": category_sequence,
            "category_counts": dict(Counter(categories)),
            "mitre_techniques": techniques,
            "attack_chain": attack_chain,
            "total_commands": len(parsed_commands),
            "unique_commands": len(set(c["base_command"] for c in parsed_commands)),
            "has_download": any(c["category"] == "download" for c in parsed_commands),
            "has_persistence": any(c["category"] == "persist" for c in parsed_commands),
            "has_privilege": any(c["category"] == "privilege" for c in parsed_commands),
            "has_network": any(c["category"] == "network" for c in parsed_commands),
            "has_credential_access": any(c["category"] == "credential" for c in parsed_commands),
            "has_lateral_movement": any(c["category"] == "lateral" for c in parsed_commands),
            "has_defense_evasion": any(c["category"] == "evasion" for c in parsed_commands),
            "has_collection": any(c["category"] == "collection" for c in parsed_commands),
            "has_exfiltration": any(c["category"] == "exfil" for c in parsed_commands),
            "has_c2": any(c["category"] == "c2" for c in parsed_commands),
            "obfuscation_count": sum(1 for c in parsed_commands if c["has_obfuscation"]),
            "suspicious_command_count": sum(1 for c in parsed_commands if c["suspicious_flags"]),
        }

    def _detect_attack_chain(self, parsed_commands: List[Dict]) -> List[str]:
        """Detect multi-stage attack chains from command sequences."""
        chain = []
        categories = [c["category"] for c in parsed_commands]

        # Common attack chains
        if "download" in categories and "execute" in categories:
            chain.append("DOWNLOAD_EXECUTE")
        if "download" in categories and "privilege" in categories:
            chain.append("DOWNLOAD_ESCALATE")
        if "recon" in categories and "download" in categories:
            chain.append("RECON_DOWNLOAD")
        if "execute" in categories and "persist" in categories:
            chain.append("EXECUTE_PERSIST")
        if "credential" in categories and "exfil" in categories:
            chain.append("CREDENTIAL_EXFIL")
        if "lateral" in categories and "execute" in categories:
            chain.append("LATERAL_EXECUTE")
        if "evasion" in categories and "execute" in categories:
            chain.append("EVADE_EXECUTE")
        if "collection" in categories and "exfil" in categories:
            chain.append("COLLECT_EXFIL")

        return chain

    def _tokenize(self, command: str) -> List[str]:
        """Split command into tokens preserving quoted strings."""
        tokens = []
        current = ""
        in_quotes = False
        quote_char = None

        special_chars = set('()$|><&;')
        for char in command:
            if char in ('"', "'") and not in_quotes:
                in_quotes = True
                quote_char = char
                if current:
                    tokens.append(current)
                    current = ""
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
                if current:
                    tokens.append(current)
                    current = ""
            elif char.isspace() and not in_quotes:
                if current:
                    tokens.append(current)
                    current = ""
            elif char in special_chars and not in_quotes:
                if current:
                    tokens.append(current)
                    current = ""
                tokens.append(char)
            else:
                current += char

        if current:
            tokens.append(current)

        return tokens

    def _categorize(self, base_cmd: str) -> str:
        """Categorize command by MITRE ATT&CK tactic."""
        for category, commands in self.COMMAND_CATEGORIES.items():
            if base_cmd in commands:
                return category
        return "other"

    def _extract_flags(self, tokens: List[str]) -> List[str]:
        """Extract flag arguments."""
        return [t for t in tokens if t.startswith("-")]

    def _extract_paths(self, command: str) -> List[str]:
        """Extract file paths from command."""
        path_pattern = r'/[a-zA-Z0-9_./-]+'
        return re.findall(path_pattern, command)

    def _extract_urls(self, command: str) -> List[str]:
        """Extract URLs from command."""
        url_pattern = r'https?://[^\s"\']+'
        return re.findall(url_pattern, command)

    def _extract_ips(self, command: str) -> List[str]:
        """Extract IP addresses from command."""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return re.findall(ip_pattern, command)

    def _detect_obfuscation(self, command: str) -> bool:
        """Detect command obfuscation techniques."""
        obfuscation_patterns = [
            r'base64',
            r'\$\(',
            r'eval\s*\(',
            r'\`.*\`',
            r'\\x[0-9a-fA-F]{2}',
            r'chr\(\d+\)',
            r'\{\d+,\d+\}',
        ]
        return any(re.search(p, command, re.IGNORECASE) for p in obfuscation_patterns)

    def _detect_suspicious(self, command: str) -> List[str]:
        """Detect suspicious patterns in command."""
        flags = []
        for name, pattern in self.SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, command, re.IGNORECASE):
                flags.append(name)
        return flags

    def _empty_parse(self) -> Dict[str, Any]:
        """Return empty parse result."""
        return {
            "raw": "",
            "tokens": [],
            "base_command": "",
            "token_count": 0,
            "unique_tokens": 0,
            "has_arguments": False,
            "category": "other",
            "mitre_technique_id": "TXXXX",
            "mitre_technique_name": "Unknown Technique",
            "flags": [],
            "paths": [],
            "urls": [],
            "ips": [],
            "has_obfuscation": False,
            "has_pipe": False,
            "has_redirect": False,
            "has_background": False,
            "has_substitution": False,
            "suspicious_flags": [],
        }

    def get_technique_summary(self) -> Dict[str, int]:
        """Return summary of detected MITRE ATT&CK techniques."""
        return dict(self.technique_stats)
