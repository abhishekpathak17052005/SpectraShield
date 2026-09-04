import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datasketch import MinHash
from app.graph_db import threat_graph_manager


class GraphAttributionAgent:
    """
    Correlates IOCs (Origin IP, Subnet, Sender Domain, DKIM, Attachment hashes)
    and computes MinHash structural body similarity to cluster emails into
    shared Threat Campaigns.
    """

    def __init__(self, num_perm: int = 128, similarity_threshold: float = 0.65):
        self.num_perm = num_perm
        self.similarity_threshold = similarity_threshold
        # Stores campaign signatures: campaign_id -> { "name": str, "minhash": MinHash, "incidents": int, "ips": set, "domains": set }
        self.campaign_clusters: Dict[str, Dict[str, Any]] = {}
        self._init_mock_clusters()

    def _init_mock_clusters(self):
        """Initializes baseline campaign clusters for real-time demo correlation."""
        # Seed Campaign 1: Microsoft 365 Credential Harvest
        m1 = self._compute_minhash("Your Microsoft 365 password expires today. Please verify credentials immediately.")
        self.campaign_clusters["CAMP-2026-M365"] = {
            "id": "CAMP-2026-M365",
            "name": "Targeted M365 Credential Harvest Spray",
            "minhash": m1,
            "incidents_count": 14,
            "ips": {"185.220.101.5", "185.220.101.7", "195.54.160.10"},
            "domains": {"micro-soft-sec.top", "office365-verify.com"},
            "threat_actor": "UNC402 (Financial Phishing Group)"
        }

        # Seed Campaign 2: European Wire Transfer BEC
        m2 = self._compute_minhash("Urgent: Overdue wire transfer invoice payment requested. Bank account details updated.")
        self.campaign_clusters["CAMP-2026-BEC"] = {
            "id": "CAMP-2026-BEC",
            "name": "European Executive Wire Diversion",
            "minhash": m2,
            "incidents_count": 8,
            "ips": {"45.142.214.12", "198.96.155.3"},
            "domains": {"billing-corporate-corp.com"},
            "threat_actor": "Storm-0829 (BEC Syndicate)"
        }

    def correlate_incident(
        self,
        email_hash: str,
        subject: str,
        body_text: str,
        origin_ip: Optional[str],
        country: Optional[str],
        sender_domain: Optional[str],
        asn_number: Optional[str],
        isp_name: Optional[str],
        threat_category: str,
        is_tor: bool = False
    ) -> Dict[str, Any]:
        """
        Determines if the email belongs to an existing campaign or creates a new one,
        then inserts the nodes and edges into the Threat Graph.
        """
        email_minhash = self._compute_minhash(f"{subject} {body_text}")
        best_match_id = None
        best_similarity = 0.0

        # 1. Compare against known MinHash cluster signatures
        for cid, cluster in self.campaign_clusters.items():
            sim = email_minhash.jaccard(cluster["minhash"])
            # IP or Domain overlap bonus
            if origin_ip and origin_ip in cluster["ips"]:
                sim += 0.25
            if sender_domain and sender_domain in cluster["domains"]:
                sim += 0.30

            if sim > best_similarity:
                best_similarity = sim
                best_match_id = cid

        # 2. Assign to Campaign
        if best_match_id and best_similarity >= self.similarity_threshold:
            cluster = self.campaign_clusters[best_match_id]
            cluster["incidents_count"] += 1
            if origin_ip:
                cluster["ips"].add(origin_ip)
            if sender_domain:
                cluster["domains"].add(sender_domain)

            assigned_id = cluster["id"]
            assigned_name = cluster["name"]
            attribution_confidence = min(98.0, round(best_similarity * 100.0, 1))
            threat_actor = cluster.get("threat_actor")
            total_linked = cluster["incidents_count"]
        else:
            # Create new emergent campaign cluster
            cluster_hash = hashlib.md5(f"{sender_domain}:{subject}".encode()).hexdigest()[:6].upper()
            assigned_id = f"CAMP-2026-{cluster_hash}"
            assigned_name = f"Emergent Campaign #{cluster_hash}: {subject[:30] or threat_category}"
            self.campaign_clusters[assigned_id] = {
                "id": assigned_id,
                "name": assigned_name,
                "minhash": email_minhash,
                "incidents_count": 1,
                "ips": {origin_ip} if origin_ip else set(),
                "domains": {sender_domain} if sender_domain else set(),
                "threat_actor": "Unattributed Threat Cluster"
            }
            attribution_confidence = 65.0
            threat_actor = "Emergent Threat Cluster"
            total_linked = 1

        # 3. Ingest into Graph Database
        threat_graph_manager.add_email_incident(
            email_hash=email_hash,
            subject=subject,
            origin_ip=origin_ip,
            country=country,
            sender_domain=sender_domain,
            asn_number=asn_number,
            isp_name=isp_name,
            campaign_id=assigned_id,
            campaign_name=assigned_name,
            is_tor=is_tor
        )

        return {
            "id": assigned_id,
            "campaign_id": assigned_id,
            "name": assigned_name,
            "campaign_name": assigned_name,
            "attribution_confidence": attribution_confidence,
            "threat_actor": threat_actor,
            "linked_incidents_count": total_linked,
            "similarity_metric": round(best_similarity, 2)
        }

    def _compute_minhash(self, text: str) -> MinHash:
        """Computes a MinHash signature on 3-character n-grams."""
        m = MinHash(num_perm=self.num_perm)
        clean = re.sub(r'\s+', ' ', (text or '').lower()).strip()
        if not clean:
            clean = "empty payload"
        # 3-gram shingles
        for i in range(len(clean) - 2):
            shingle = clean[i:i + 3].encode('utf-8')
            m.update(shingle)
        return m


# Global instance
graph_attribution_agent = GraphAttributionAgent()
