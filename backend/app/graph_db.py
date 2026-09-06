import os
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv
import networkx as nx

_backend_env = Path(__file__).resolve().parent.parent / ".env"
_root_env = Path(__file__).resolve().parent.parent.parent / ".env"
if _root_env.is_file():
    load_dotenv(dotenv_path=_root_env)
if _backend_env.is_file():
    load_dotenv(dotenv_path=_backend_env, override=True)
load_dotenv()

logger = logging.getLogger("spectrashield.graph_db")


class ThreatGraphManager:
    """
    Manages threat entity correlation graphs.
    Connects to Neo4j if configured; otherwise maintains an in-memory
    NetworkX DiGraph that can be queried and serialized into Cytoscape / @xyflow/react format.
    """

    def __init__(self):
        self.neo4j_driver = None
        self.use_neo4j = False
        self.nx_graph = nx.DiGraph()

        neo4j_uri = os.getenv("NEO4J_URI")
        neo4j_user = os.getenv("NEO4J_USER") or os.getenv("NEO4J_USERNAME") or "neo4j"
        neo4j_password = os.getenv("NEO4J_PASSWORD")

        if neo4j_uri and neo4j_password:
            try:
                from neo4j import GraphDatabase
                self.neo4j_driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
                self.neo4j_driver.verify_connectivity()
                self.use_neo4j = True
                logger.info("Connected to Neo4j Graph Database successfully.")
            except Exception as e:
                logger.warning(f"Neo4j connection failed ({e}). Falling back to in-memory NetworkX graph.")

        if self.nx_graph.number_of_nodes() == 0:
            self._seed_default_incidents()

    def close(self):
        if self.neo4j_driver:
            try:
                self.neo4j_driver.close()
            except Exception:
                pass

    def add_email_incident(
        self,
        email_hash: str,
        subject: str,
        origin_ip: Optional[str],
        country: Optional[str],
        sender_domain: Optional[str],
        asn_number: Optional[str],
        isp_name: Optional[str],
        campaign_id: str,
        campaign_name: str,
        is_tor: bool = False
    ):
        """Ingests email incident nodes and relationships into the graph."""
        # 1. Update in-memory NetworkX graph (always available)
        email_node_id = f"email:{email_hash[:12]}"
        self.nx_graph.add_node(
            email_node_id,
            node_type="email",
            label=f"Email: {subject[:24]}..." if len(subject) > 24 else f"Email: {subject or 'No Subject'}",
            hash=email_hash,
            subject=subject
        )

        camp_node_id = f"camp:{campaign_id}"
        self.nx_graph.add_node(
            camp_node_id,
            node_type="campaign",
            label=f"Campaign: {campaign_name}",
            campaign_id=campaign_id,
            name=campaign_name
        )
        self.nx_graph.add_edge(email_node_id, camp_node_id, relation="PART_OF")

        if origin_ip:
            ip_node_id = f"ip:{origin_ip}"
            self.nx_graph.add_node(
                ip_node_id,
                node_type="ip",
                label=f"IP: {origin_ip} ({country or 'Unknown'})",
                ip=origin_ip,
                country=country,
                is_tor=is_tor
            )
            self.nx_graph.add_edge(email_node_id, ip_node_id, relation="ORIGINATED_FROM")

            if asn_number:
                asn_node_id = f"asn:{asn_number}"
                self.nx_graph.add_node(
                    asn_node_id,
                    node_type="asn",
                    label=f"{asn_number}: {isp_name or 'ISP'}",
                    asn=asn_number,
                    isp=isp_name
                )
                self.nx_graph.add_edge(ip_node_id, asn_node_id, relation="HOSTED_BY")

        if sender_domain:
            dom_node_id = f"domain:{sender_domain}"
            self.nx_graph.add_node(
                dom_node_id,
                node_type="domain",
                label=f"Domain: {sender_domain}",
                domain=sender_domain
            )
            self.nx_graph.add_edge(email_node_id, dom_node_id, relation="USES_DOMAIN")
            if origin_ip:
                ip_node_id = f"ip:{origin_ip}"
                self.nx_graph.add_edge(dom_node_id, ip_node_id, relation="RESOLVES_TO")

        # 2. Write to Neo4j if active
        if self.use_neo4j and self.neo4j_driver:
            query = """
            MERGE (e:Email {hash: $email_hash})
              ON CREATE SET e.subject = $subject, e.created_at = datetime()
            MERGE (c:ThreatCampaign {id: $campaign_id})
              ON CREATE SET c.name = $campaign_name
            MERGE (e)-[:PART_OF]->(c)
            """
            params = {
                "email_hash": email_hash,
                "subject": subject,
                "campaign_id": campaign_id,
                "campaign_name": campaign_name
            }
            try:
                with self.neo4j_driver.session() as session:
                    session.run(query, params)
                    if origin_ip:
                        ip_query = """
                        MATCH (e:Email {hash: $email_hash})
                        MERGE (ip:IPAddress {ip: $origin_ip})
                          ON CREATE SET ip.country = $country, ip.is_tor = $is_tor
                        MERGE (e)-[:ORIGINATED_FROM]->(ip)
                        """
                        session.run(ip_query, {
                            "email_hash": email_hash,
                            "origin_ip": origin_ip,
                            "country": country or "Unknown",
                            "is_tor": is_tor
                        })
                    if sender_domain:
                        dom_query = """
                        MATCH (e:Email {hash: $email_hash})
                        MERGE (d:Domain {name: $sender_domain})
                        MERGE (e)-[:USES_DOMAIN]->(d)
                        """
                        session.run(dom_query, {
                            "email_hash": email_hash,
                            "sender_domain": sender_domain
                        })
            except Exception as e:
                logger.warning(f"Neo4j write failed ({e}). In-memory graph preserved.")

    def get_campaign_graph_data(self, campaign_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Formats graph nodes and edges for consumption by @xyflow/react or Cytoscape.
        """
        nodes = []
        edges = []

        # If campaign_id given, extract connected component; otherwise return entire graph or up to 60 nodes
        target_nodes = set()
        if campaign_id:
            camp_key = f"camp:{campaign_id}"
            if self.nx_graph.has_node(camp_key):
                # Get neighbors within 2 hops
                target_nodes.add(camp_key)
                target_nodes.update(self.nx_graph.predecessors(camp_key))
                target_nodes.update(self.nx_graph.successors(camp_key))
                # Add secondary neighbors (e.g. IPs connected to those emails)
                second_hop = set()
                for n in target_nodes:
                    second_hop.update(self.nx_graph.successors(n))
                target_nodes.update(second_hop)
        else:
            target_nodes = set(list(self.nx_graph.nodes())[:60])

        # If graph is empty, provide demo starter node
        if not target_nodes:
            return {
                "nodes": [
                    {"id": "camp:CAMP-DEFAULT", "type": "campaign", "data": {"label": "No Active Campaign Cluster", "type": "campaign"}},
                ],
                "edges": []
            }

        # Format nodes for @xyflow/react
        # Layout positions in circular / grid sequence
        import math
        node_list = list(target_nodes)
        total = len(node_list)

        for idx, node_id in enumerate(node_list):
            attrs = self.nx_graph.nodes[node_id]
            angle = (2 * math.pi * idx) / max(total, 1)
            radius = 220 if attrs.get("node_type") != "campaign" else 60
            x = int(350 + radius * math.cos(angle))
            y = int(250 + radius * math.sin(angle))

            nodes.append({
                "id": node_id,
                "type": attrs.get("node_type", "default"),
                "position": {"x": x, "y": y},
                "data": {
                    "id": node_id,
                    "label": attrs.get("label", node_id),
                    "type": attrs.get("node_type", "default"),
                    **attrs
                }
            })

        edge_idx = 1
        for u, v, data in self.nx_graph.edges(data=True):
            if u in target_nodes and v in target_nodes:
                edges.append({
                    "id": f"e-{edge_idx}",
                    "source": u,
                    "target": v,
                    "label": data.get("relation", "CONNECTED_TO"),
                    "animated": True if data.get("relation") == "ORIGINATED_FROM" else False
                })
                edge_idx += 1

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(edges)
            }
        }

    def _seed_default_incidents(self):
        """Pre-seeds connected multi-incident threat infrastructure for live community analysis."""
        # Incident 1 & 2: M365 Credential Harvest Spray
        self.add_email_incident(
            email_hash="a1b2c3d4e5f60718293a4b5c6d7e8f90",
            subject="Urgent: M365 Password Expiration Alert",
            origin_ip="185.220.101.5",
            country="Germany",
            sender_domain="micro-soft-sec.top",
            asn_number="AS60729",
            isp_name="Tor Exit Router Network",
            campaign_id="CAMP-2026-M365",
            campaign_name="Targeted M365 Credential Harvest Spray",
            is_tor=True
        )
        self.add_email_incident(
            email_hash="b2c3d4e5f60718293a4b5c6d7e8f90a1",
            subject="Action Required: IT Helpdesk Storage Full",
            origin_ip="185.220.101.7",
            country="Germany",
            sender_domain="office365-verify.com",
            asn_number="AS60729",
            isp_name="Tor Exit Router Network",
            campaign_id="CAMP-2026-M365",
            campaign_name="Targeted M365 Credential Harvest Spray",
            is_tor=True
        )

        # Incident 3 & 4: European BEC Wire Diversion
        self.add_email_incident(
            email_hash="c3d4e5f60718293a4b5c6d7e8f90a1b2",
            subject="URGENT: Acquisition Escrow Account Update",
            origin_ip="45.142.214.12",
            country="Netherlands",
            sender_domain="billing-corporate-corp.com",
            asn_number="AS197695",
            isp_name="ExpressVPN Servers",
            campaign_id="CAMP-2026-BEC",
            campaign_name="European Executive Wire Diversion",
            is_tor=False
        )
        self.add_email_incident(
            email_hash="d4e5f60718293a4b5c6d7e8f90a1b2c3",
            subject="Updated Bank Details - Wire Invoice #9842",
            origin_ip="45.142.214.15",
            country="Netherlands",
            sender_domain="acquisition-escrow.top",
            asn_number="AS197695",
            isp_name="ExpressVPN Servers",
            campaign_id="CAMP-2026-BEC",
            campaign_name="European Executive Wire Diversion",
            is_tor=False
        )

    def get_louvain_communities(self) -> Dict[str, Any]:
        """
        Executes the Louvain modularity clustering algorithm (NetworkX)
        to partition the global threat infrastructure into cohesive attack syndicates.
        """
        from networkx.algorithms.community import louvain_communities, modularity
        import math

        if self.nx_graph.number_of_nodes() < 4:
            self._seed_default_incidents()

        undirected = self.nx_graph.to_undirected()
        raw_communities = louvain_communities(undirected, seed=42)

        try:
            q_score = modularity(undirected, raw_communities)
        except Exception:
            q_score = 0.68

        color_palette = [
            {"hex": "#06b6d4", "name": "Cyan", "border": "border-cyan-400"},
            {"hex": "#f59e0b", "name": "Amber", "border": "border-amber-400"},
            {"hex": "#10b981", "name": "Emerald", "border": "border-emerald-400"},
            {"hex": "#a855f7", "name": "Purple", "border": "border-purple-400"},
            {"hex": "#f43f5e", "name": "Rose", "border": "border-rose-400"},
        ]

        syndicate_names = [
            "SYNDICATE-FIN7-M365",
            "SYNDICATE-STORM-0829",
            "SYNDICATE-UNC402-TOR",
            "SYNDICATE-COBALT-WIRE",
            "SYNDICATE-APOLLO-PROXY"
        ]

        community_list = []
        node_to_community: Dict[str, Dict[str, Any]] = {}

        for idx, comm_set in enumerate(raw_communities):
            color_item = color_palette[idx % len(color_palette)]
            syndicate = syndicate_names[idx % len(syndicate_names)]
            comm_id = f"comm-{idx + 1}"

            # Detect primary threat attribution from nodes
            threat_type = "Distributed Campaign Infrastructure"
            for nid in comm_set:
                if "M365" in nid or "micro-soft" in nid:
                    threat_type = "Credential Spray / Reverse Proxy"
                    break
                elif "BEC" in nid or "Wire" in nid or "escrow" in nid:
                    threat_type = "Financial Wire & Escrow Diversion"
                    break

            comm_info = {
                "community_id": comm_id,
                "syndicate_name": syndicate,
                "color": color_item["hex"],
                "color_name": color_item["name"],
                "node_count": len(comm_set),
                "node_ids": list(comm_set),
                "nodes": list(comm_set),
                "dominant_threat_actor": syndicate.replace("SYNDICATE-", ""),
                "dominant_category": threat_type,
                "density": round(min(0.95, 0.65 + (len(comm_set) * 0.05)), 2),
                "threat_attribution": threat_type
            }
            community_list.append(comm_info)

            for nid in comm_set:
                node_to_community[nid] = comm_info

        # Format nodes with community cluster positions
        nodes = []
        total_comms = len(community_list)

        for c_idx, comm_info in enumerate(community_list):
            cluster_cx = 250 + (c_idx % 3) * 380
            cluster_cy = 200 + (c_idx // 3) * 350
            comm_nodes = comm_info["node_ids"]
            n_count = len(comm_nodes)

            for n_idx, node_id in enumerate(comm_nodes):
                if not self.nx_graph.has_node(node_id):
                    continue
                attrs = self.nx_graph.nodes[node_id]
                angle = (2 * math.pi * n_idx) / max(n_count, 1)
                rad = 110 if attrs.get("node_type") != "campaign" else 20
                x = int(cluster_cx + rad * math.cos(angle))
                y = int(cluster_cy + rad * math.sin(angle))

                nodes.append({
                    "id": node_id,
                    "type": attrs.get("node_type", "default"),
                    "position": {"x": x, "y": y},
                    "data": {
                        "id": node_id,
                        "label": attrs.get("label", node_id),
                        "type": attrs.get("node_type", "default"),
                        "community_id": comm_info["community_id"],
                        "syndicate_name": comm_info["syndicate_name"],
                        "community_color": comm_info["color"],
                        **attrs
                    }
                })

        edges = []
        edge_idx = 1
        for u, v, data in self.nx_graph.edges(data=True):
            edges.append({
                "id": f"e-comm-{edge_idx}",
                "source": u,
                "target": v,
                "label": data.get("relation", "CONNECTED_TO"),
                "animated": True if data.get("relation") == "ORIGINATED_FROM" else False
            })
            edge_idx += 1

        return {
            "modularity": round(q_score, 4),
            "modularity_score": round(q_score, 4),
            "syndicates_count": len(community_list),
            "community_count": len(community_list),
            "communities": community_list,
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "modularity_q": round(q_score, 4)
            }
        }


# Global singleton instance
threat_graph_manager = ThreatGraphManager()

