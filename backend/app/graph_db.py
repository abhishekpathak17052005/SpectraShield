import os
import logging
from typing import Dict, List, Any, Optional
import networkx as nx

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
        neo4j_user = os.getenv("NEO4J_USER", "neo4j")
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


# Global singleton instance
threat_graph_manager = ThreatGraphManager()
