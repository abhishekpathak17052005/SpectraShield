import os
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from app.utils.ip_utils import is_bogon_or_private, is_valid_ip, defang_ip

logger = logging.getLogger("spectrashield.geo_trace")

# Common Cloud and Datacenter ASNs frequently abused for disposable spam/phishing
_CLOUD_AND_HOSTING_ASNS = {
    "AS16509": "Amazon AWS",
    "AS14618": "Amazon AWS",
    "AS15169": "Google Cloud",
    "AS8075": "Microsoft Azure",
    "AS14061": "DigitalOcean",
    "AS16276": "OVH SAS",
    "AS63949": "Linode / Akamai",
    "AS20473": "Choopa / Vultr",
    "AS49505": "Serverius Bulletproof",
    "AS200000": "Offshore VPN Network"
}


class GeoTraceAgent:
    """
    Resolves the Earliest Reliable Public Node (ERPN) into physical coordinates,
    Autonomous System Numbers (ASN), ISP names, and flags Tor/VPN/Cloud exit nodes.
    Supports offline datasets (sample_geo_ips.json, tor_exit_nodes.txt, MaxMind GeoLite2).
    """

    def __init__(self, data_dir: Optional[str] = None):
        if data_dir is None:
            # geo_trace_agent is in backend/app/agents/
            # Need to go up two levels to reach backend/data/
            current_dir = os.path.dirname(os.path.abspath(__file__))
            backend_dir = os.path.dirname(os.path.dirname(current_dir))
            data_dir = os.path.join(backend_dir, "data")

        self.data_dir = data_dir
        self.tor_exit_nodes: set[str] = set()
        self.offline_geo_db: Dict[str, Dict[str, Any]] = {}
        self.maxmind_city_reader = None
        self.maxmind_asn_reader = None

        self._load_tor_nodes()
        self._load_offline_geo_db()
        self._init_maxmind()

    def _load_tor_nodes(self):
        tor_path = os.path.join(self.data_dir, "tor_exit_nodes.txt")
        if os.path.exists(tor_path):
            try:
                with open(tor_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.tor_exit_nodes.add(line)
                logger.info(f"Loaded {len(self.tor_exit_nodes)} Tor exit nodes from offline feed.")
            except Exception as e:
                logger.warning(f"Failed loading tor_exit_nodes.txt: {e}")

    def _load_offline_geo_db(self):
        sample_path = os.path.join(self.data_dir, "sample_geo_ips.json")
        if os.path.exists(sample_path):
            try:
                with open(sample_path, "r", encoding="utf-8") as f:
                    self.offline_geo_db = json.load(f)
                logger.info(f"Loaded {len(self.offline_geo_db)} offline GeoIP records.")
            except Exception as e:
                logger.warning(f"Failed loading sample_geo_ips.json: {e}")

    def _init_maxmind(self):
        """Initializes MaxMind readers if geoip2 and mmdb files are present."""
        try:
            import geoip2.database
            city_path = os.path.join(self.data_dir, "GeoLite2-City.mmdb")
            asn_path = os.path.join(self.data_dir, "GeoLite2-ASN.mmdb")

            if os.path.exists(city_path):
                self.maxmind_city_reader = geoip2.database.Reader(city_path)
            if os.path.exists(asn_path):
                self.maxmind_asn_reader = geoip2.database.Reader(asn_path)
        except Exception as e:
            logger.debug(f"MaxMind mmdb reader not initialized (using JSON fallback): {e}")

    def resolve_ip(self, ip_str: Optional[str]) -> Dict[str, Any]:
        """Resolves a single IPv4/IPv6 address to its geographical and ASN profile."""
        if not ip_str or not is_valid_ip(ip_str):
            return self._empty_geo_record(ip_str)

        ip_clean = ip_str.strip()
        is_private = is_bogon_or_private(ip_clean)

        if is_private:
            return {
                "ip": ip_clean,
                "defanged_ip": defang_ip(ip_clean),
                "is_private": True,
                "is_bogon": True,
                "country": "Private / Bogon Space",
                "country_code": "LOCAL",
                "city": "Internal Network (RFC 1918)",
                "postal": None,
                "latitude": None,
                "longitude": None,
                "asn": None,
                "isp": "Private Enterprise Routing",
                "is_anonymized": False,
                "anonymization_type": None,
                "risk_rating": 0.0
            }

        # Check Tor exit nodes list
        is_tor = ip_clean in self.tor_exit_nodes

        # Check offline sample database first
        if ip_clean in self.offline_geo_db:
            record = dict(self.offline_geo_db[ip_clean])
            record["is_private"] = False
            record["is_bogon"] = False
            record["defanged_ip"] = defang_ip(ip_clean)
            if is_tor:
                record["is_anonymized"] = True
                record["anonymization_type"] = "TOR"
            record["risk_rating"] = self._compute_origin_risk(record)
            return record

        # Check MaxMind mmdb if available
        if self.maxmind_city_reader:
            try:
                city_resp = self.maxmind_city_reader.city(ip_clean)
                asn_str = None
                isp_str = None
                if self.maxmind_asn_reader:
                    try:
                        asn_resp = self.maxmind_asn_reader.asn(ip_clean)
                        asn_str = f"AS{asn_resp.autonomous_system_number}"
                        isp_str = asn_resp.autonomous_system_organization
                    except Exception:
                        pass

                record = {
                    "ip": ip_clean,
                    "defanged_ip": defang_ip(ip_clean),
                    "is_private": False,
                    "is_bogon": False,
                    "country": city_resp.country.name or "Unknown",
                    "country_code": city_resp.country.iso_code or "XX",
                    "city": city_resp.city.name or "Unknown",
                    "postal": city_resp.postal.code or None,
                    "latitude": float(city_resp.location.latitude) if city_resp.location.latitude else None,
                    "longitude": float(city_resp.location.longitude) if city_resp.location.longitude else None,
                    "asn": asn_str,
                    "isp": isp_str or "Internet Service Provider",
                    "is_anonymized": is_tor,
                    "anonymization_type": "TOR" if is_tor else None
                }
                record["risk_rating"] = self._compute_origin_risk(record)
                return record
            except Exception:
                pass

        # Algorithmic synthetic fallback based on subnet
        synth_record = self._synthetic_geo_fallback(ip_clean, is_tor)
        synth_record["risk_rating"] = self._compute_origin_risk(synth_record)
        return synth_record

    def enrich_relay_path(self, hops: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any], float]:
        """
        Takes parsed relay hops from HeaderForensicAgent, enriches each with
        geographic coordinates, and computes the flight trajectory and origin score.
        """
        enriched_hops: List[Dict[str, Any]] = []
        origin_node: Optional[Dict[str, Any]] = None
        highest_origin_risk = 0.0

        for hop in hops:
            ip = hop.get("ip")
            geo_profile = self.resolve_ip(ip) if ip else None

            hop_copy = dict(hop)
            hop_copy["geo"] = geo_profile

            if hop.get("is_origin", False) and origin_node is None and geo_profile:
                origin_node = geo_profile
                highest_origin_risk = max(highest_origin_risk, geo_profile.get("risk_rating", 0.0))

            enriched_hops.append(hop_copy)

        if origin_node is None and enriched_hops:
            # First public or first hop with geo
            for h in enriched_hops:
                if h.get("geo") and not h["geo"].get("is_private"):
                    origin_node = h["geo"]
                    h["is_origin"] = True
                    highest_origin_risk = max(highest_origin_risk, origin_node.get("risk_rating", 0.0))
                    break

        if origin_node is None:
            origin_node = self._empty_geo_record(None)

        return enriched_hops, origin_node, highest_origin_risk

    def _compute_origin_risk(self, geo_record: Dict[str, Any]) -> float:
        """Calculates origin threat risk score (0 - 100)."""
        score = 0.0
        if geo_record.get("is_anonymized"):
            score += 55.0

        anon_type = str(geo_record.get("anonymization_type") or "").upper()
        if "TOR" in anon_type:
            score += 35.0
        elif "BULLETPROOF" in anon_type:
            score += 30.0
        elif "VPN" in anon_type:
            score += 15.0

        asn = geo_record.get("asn")
        if asn and asn in _CLOUD_AND_HOSTING_ASNS:
            score += 15.0  # Server sending mail directly without proper MX reputation

        return min(100.0, max(0.0, score))

    def _synthetic_geo_fallback(self, ip_clean: str, is_tor: bool) -> Dict[str, Any]:
        """Provides deterministic fallback coordinates when completely offline."""
        octets = ip_clean.split(".")
        lat = 37.0902  # Default to US geographic center
        lon = -95.7129
        country = "United States"
        country_code = "US"
        city = "Washington D.C."
        asn = "AS15169"
        isp = "Public Cloud / Autonomous System"

        if len(octets) == 4:
            first_octet = int(octets[0]) if octets[0].isdigit() else 0
            if 185 <= first_octet <= 195:
                lat = 50.1109
                lon = 8.6821
                country = "Germany"
                country_code = "DE"
                city = "Frankfurt"
                asn = "AS60729"
                isp = "European Hosting Provider"
            elif 45 <= first_octet <= 55:
                lat = 52.3676
                lon = 4.9041
                country = "Netherlands"
                country_code = "NL"
                city = "Amsterdam"
                asn = "AS200000"
                isp = "Equinix Data Center"
            elif 13 <= first_octet <= 27:
                lat = 19.0760
                lon = 72.8777
                country = "India"
                country_code = "IN"
                city = "Mumbai"
                asn = "AS16509"
                isp = "Asia Pacific Relay Network"

        return {
            "ip": ip_clean,
            "defanged_ip": defang_ip(ip_clean),
            "is_private": False,
            "is_bogon": False,
            "country": country,
            "country_code": country_code,
            "city": city,
            "postal": "00000",
            "latitude": lat,
            "longitude": lon,
            "asn": asn,
            "isp": isp,
            "is_anonymized": is_tor,
            "anonymization_type": "TOR" if is_tor else None
        }

    def _empty_geo_record(self, ip_str: Optional[str]) -> Dict[str, Any]:
        return {
            "ip": ip_str or "0.0.0.0",
            "defanged_ip": defang_ip(ip_str or "0.0.0.0"),
            "is_private": True,
            "is_bogon": True,
            "country": "Unknown",
            "country_code": "UN",
            "city": "Unknown Location",
            "postal": None,
            "latitude": 0.0,
            "longitude": 0.0,
            "asn": None,
            "isp": "Unknown ISP",
            "is_anonymized": False,
            "anonymization_type": None,
            "risk_rating": 0.0
        }
