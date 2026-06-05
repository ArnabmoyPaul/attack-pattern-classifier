
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class IPGeolocationEnricher:
    """Enrich session data with IP geolocation information."""

    # Known datacenter/VPN ASNs
    DATACENTER_ASNS = {
        15169,  # Google Cloud
        16509,  # Amazon AWS
        8075,   # Microsoft Azure
        36351,  # DigitalOcean
        14061,  # DigitalOcean
        20473,  # Vultr
        63949,  # Linode
        9009,   # M247
        60068,  # CDN77
    }

    # Known Tor exit node ASNs (subset)
    TOR_ASNS = {
        9009,   # M247
        20473,  # Vultr
    }

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize enricher.

        Args:
            db_path: Path to MaxMind GeoLite2 database (optional)
        """
        self.db_path = db_path
        self._reader = None

        if db_path:
            try:
                import maxminddb
                self._reader = maxminddb.open_database(db_path)
                logger.info(f"Loaded GeoLite2 database: {db_path}")
            except Exception as e:
                logger.warning(f"Could not load GeoLite2 database: {e}")

    def enrich(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich session with geolocation data.

        Args:
            session: Session dict with 'src_ip' key

        Returns:
            Dict of geolocation features
        """
        ip = session.get("src_ip", "0.0.0.0")

        features = {
            "country_code": "UNKNOWN",
            "country_name": "Unknown",
            "city": "Unknown",
            "asn": 0,
            "asn_org": "Unknown",
            "is_datacenter": 0,
            "is_tor": 0,
            "is_vpn": 0,
            "latitude": 0.0,
            "longitude": 0.0,
        }

        if not ip or ip == "0.0.0.0":
            return features

        if self._reader:
            try:
                record = self._reader.get(ip)
                if record:
                    # Country info
                    country = record.get("country", {})
                    features["country_code"] = country.get("iso_code", "UNKNOWN")
                    features["country_name"] = country.get("names", {}).get("en", "Unknown")

                    # City info
                    city = record.get("city", {})
                    features["city"] = city.get("names", {}).get("en", "Unknown")

                    # Location
                    location = record.get("location", {})
                    features["latitude"] = location.get("latitude", 0.0)
                    features["longitude"] = location.get("longitude", 0.0)

                    # ASN
                    asn_info = record.get("autonomous_system_number", 0)
                    features["asn"] = asn_info
                    features["asn_org"] = record.get("autonomous_system_organization", "Unknown")

                    # Flags
                    features["is_datacenter"] = 1 if asn_info in self.DATACENTER_ASNS else 0
                    features["is_tor"] = 1 if asn_info in self.TOR_ASNS else 0
                    features["is_vpn"] = features["is_datacenter"]  # Simplified heuristic

            except Exception as e:
                logger.warning(f"Geolocation lookup failed for {ip}: {e}")

        return features

    def enrich_batch(self, sessions: list) -> list:
        """Enrich multiple sessions."""
        return [self.enrich(session) for session in sessions]

    def close(self):
        """Close database reader."""
        if self._reader:
            self._reader.close()
