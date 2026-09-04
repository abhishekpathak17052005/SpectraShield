import re
import email
from email import policy
from email.parser import Parser, HeaderParser
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
import ipaddress
import dns.resolver
from app.utils.ip_utils import extract_first_ip, is_bogon_or_private, is_valid_ip, defang_ip


class HeaderForensicAgent:
    """
    Deconstructs raw RFC 5322 email headers, reverses MTA Received hops,
    measures hop transmission latency, evaluates cryptographic SPF/DKIM/DMARC
    DNS records, and detects header forgery anomalies.
    """

    def __init__(self, dns_timeout: float = 3.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = dns_timeout
        self.resolver.lifetime = dns_timeout

    def analyze_raw_headers(self, raw_header_text: str) -> Dict[str, Any]:
        """
        Parses raw RFC 5322 header text or complete email message string.
        """
        if not raw_header_text or not raw_header_text.strip():
            return self._empty_response()

        # Parse message using standard email library
        try:
            msg = Parser(policy=policy.default).parsestr(raw_header_text)
        except Exception:
            try:
                msg = HeaderParser().parsestr(raw_header_text)
            except Exception:
                msg = {}

        # 1. Extract Fundamental RFC 5322 Fields
        subject = str(msg.get("Subject", "") or "")
        header_from = str(msg.get("From", "") or "")
        return_path = str(msg.get("Return-Path", "") or "")
        reply_to = str(msg.get("Reply-To", "") or "")
        to_field = str(msg.get("To", "") or "")
        message_id = str(msg.get("Message-ID", "") or msg.get("Message-Id", "") or "")
        date_header = str(msg.get("Date", "") or "")

        from_domain = self._extract_domain(header_from)
        return_path_domain = self._extract_domain(return_path) if return_path else from_domain
        reply_to_domain = self._extract_domain(reply_to) if reply_to else None

        # 2. Extract and Reverse Received: Hops
        raw_received_headers = msg.get_all("Received", []) or []
        if not raw_received_headers and "received:" in raw_header_text.lower():
            # Fallback regex extraction if email parser missed multi-line received headers
            raw_received_headers = re.findall(r'(?i)received:\s*(.*?)(?=\n[A-Za-z0-9\-]+:|\Z)', raw_header_text, flags=re.DOTALL)

        hops, anomalies, erpn_hop = self._parse_and_order_hops(raw_received_headers)

        # 3. Cryptographic Protocol Validation
        origin_ip = erpn_hop.get("ip") if erpn_hop else None
        spf_result = self._validate_spf(return_path_domain, origin_ip)
        dkim_result = self._validate_dkim(msg, raw_header_text, from_domain)
        dmarc_result = self._validate_dmarc(from_domain, spf_result, dkim_result)

        # 4. Header Alignment & Discrepancy Checks
        alignment_anomalies = self._detect_header_anomalies(
            header_from=header_from,
            return_path=return_path,
            reply_to=reply_to,
            from_domain=from_domain,
            return_path_domain=return_path_domain,
            reply_to_domain=reply_to_domain,
            message_id=message_id,
            raw_received_count=len(raw_received_headers)
        )
        anomalies.extend(alignment_anomalies)

        # 5. Compute Header Threat Score (0 - 100)
        header_score, score_breakdown = self._compute_header_score(
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            anomalies=anomalies
        )

        return {
            "subject": subject,
            "header_from": header_from,
            "envelope_from": return_path or header_from,
            "reply_to": reply_to or None,
            "message_id": message_id,
            "date_header": date_header,
            "header_score": round(header_score, 2),
            "score_breakdown": score_breakdown,
            "authentication": {
                "spf": spf_result,
                "dkim": dkim_result,
                "dmarc": dmarc_result
            },
            "relay_hops": hops,
            "originating_node": erpn_hop,
            "anomalies": anomalies,
            "hop_count": len(hops)
        }

    def _parse_and_order_hops(self, raw_received_headers: List[str]) -> Tuple[List[Dict[str, Any]], List[str], Optional[Dict[str, Any]]]:
        """
        Processes Received headers. In RFC 5322, MTAs prepend Received headers to the top.
        Reversing the list orders hops chronologically (Hop 1 = origin client submission).
        """
        anomalies: List[str] = []
        if not raw_received_headers:
            return [], ["No Received: headers present in message"], None

        # Reverse so index 0 is chronologically first (bottom-most header)
        chronological_raw = list(reversed(raw_received_headers))
        hops: List[Dict[str, Any]] = []
        previous_dt: Optional[datetime] = None
        erpn_hop: Optional[Dict[str, Any]] = None

        for idx, hop_text in enumerate(chronological_raw, start=1):
            hop_clean = " ".join(hop_text.split())
            extracted_ip = extract_first_ip(hop_clean)
            is_private = is_bogon_or_private(extracted_ip) if extracted_ip else True

            # Parse "from", "by", "with", "id"
            from_match = re.search(r'(?i)\bfrom\s+([^\s;]+)', hop_clean)
            by_match = re.search(r'(?i)\bby\s+([^\s;]+)', hop_clean)
            protocol_match = re.search(r'(?i)\bwith\s+([^\s;]+)', hop_clean)
            id_match = re.search(r'(?i)\bid\s+([^\s;]+)', hop_clean)

            # Extract timestamp following the semicolon
            hop_dt: Optional[datetime] = None
            delay_seconds: int = 0
            if ";" in hop_clean:
                date_part = hop_clean.split(";")[-1].strip()
                try:
                    hop_dt = parsedate_to_datetime(date_part)
                    if hop_dt.tzinfo is None:
                        hop_dt = hop_dt.replace(tzinfo=timezone.utc)
                except Exception:
                    pass

            if hop_dt and previous_dt:
                delta = (hop_dt - previous_dt).total_seconds()
                delay_seconds = int(max(0, delta))
                if delta < -60:  # Backwards time travel > 1 minute
                    anomalies.append(
                        f"Hop {idx} timestamp anomaly: Hop claims time {int(abs(delta))}s earlier than prior hop."
                    )
            if hop_dt:
                previous_dt = hop_dt

            hop_obj = {
                "hop": idx,
                "received_from": from_match.group(1) if from_match else "Unknown",
                "by": by_match.group(1) if by_match else "Unknown",
                "protocol": protocol_match.group(1) if protocol_match else "SMTP",
                "message_id": id_match.group(1) if id_match else None,
                "ip": extracted_ip,
                "defanged_ip": defang_ip(extracted_ip) if extracted_ip else None,
                "is_private": is_private,
                "is_origin": False,
                "timestamp": hop_dt.isoformat() if hop_dt else None,
                "delay_seconds": delay_seconds,
                "raw_snippet": hop_clean[:180]
            }

            # Identify Earliest Reliable Public Node (ERPN)
            if erpn_hop is None and extracted_ip and not is_private:
                hop_obj["is_origin"] = True
                erpn_hop = hop_obj

            hops.append(hop_obj)

        # If no public IP found, fall back to first hop with an IP
        if erpn_hop is None:
            for h in hops:
                if h.get("ip"):
                    h["is_origin"] = True
                    erpn_hop = h
                    break

        return hops, anomalies, erpn_hop

    def _validate_spf(self, domain: Optional[str], origin_ip: Optional[str]) -> Dict[str, Any]:
        """Queries DNS TXT records for SPF policies and validates the client IP."""
        if not domain:
            return {"status": "None", "domain": None, "reason": "No sender domain identified", "record": None}

        try:
            answers = self.resolver.resolve(domain, "TXT")
            spf_records = [
                str(r).strip('"') for rdata in answers for r in rdata.strings if str(r).startswith(('b"v=spf1', '"v=spf1', 'v=spf1'))
            ]
            if not spf_records:
                return {"status": "None", "domain": domain, "reason": "No v=spf1 DNS record found", "record": None}

            record = spf_records[0]
            if not origin_ip or not is_valid_ip(origin_ip):
                return {"status": "Neutral", "domain": domain, "reason": "No originating public IP to evaluate", "record": record}

            # Check if origin_ip matches ip4/ip6 directives in SPF
            ip_obj = ipaddress.ip_address(origin_ip)
            is_matched = False
            for token in record.split():
                if token.startswith("ip4:") or token.startswith("+ip4:"):
                    cidr = token.split("ip4:")[-1]
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if ip_obj in net:
                            is_matched = True
                            break
                    except ValueError:
                        pass
                elif token.startswith("ip6:") or token.startswith("+ip6:"):
                    cidr = token.split("ip6:")[-1]
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if ip_obj in net:
                            is_matched = True
                            break
                    except ValueError:
                        pass

            if is_matched:
                return {"status": "Pass", "domain": domain, "sender_ip": origin_ip, "reason": "Origin IP authorized in SPF record", "record": record}

            if "-all" in record:
                return {"status": "Fail", "domain": domain, "sender_ip": origin_ip, "reason": "Origin IP not in SPF, record specifies -all (HardFail)", "record": record}
            elif "~all" in record:
                return {"status": "SoftFail", "domain": domain, "sender_ip": origin_ip, "reason": "Origin IP not in SPF, record specifies ~all (SoftFail)", "record": record}
            elif "?all" in record:
                return {"status": "Neutral", "domain": domain, "sender_ip": origin_ip, "reason": "SPF specifies ?all (Neutral)", "record": record}
            elif "+all" in record:
                return {"status": "Pass", "domain": domain, "sender_ip": origin_ip, "reason": "Permissive +all rule (Insecure SPF)", "record": record}

            return {"status": "Neutral", "domain": domain, "sender_ip": origin_ip, "reason": "No explicit directive matched", "record": record}

        except Exception as e:
            return {"status": "TempError", "domain": domain, "sender_ip": origin_ip, "reason": f"DNS query failed: {str(e)}", "record": None}

    def _validate_dkim(self, msg: Any, raw_text: str, from_domain: Optional[str]) -> Dict[str, Any]:
        """Extracts DKIM signature parameters and verifies public key availability."""
        dkim_sig = msg.get("DKIM-Signature", "") if hasattr(msg, "get") else ""
        if not dkim_sig and "dkim-signature:" in raw_text.lower():
            match = re.search(r'(?i)dkim-signature:\s*(.*?)(?=\n[A-Za-z0-9\-]+:|\Z)', raw_text, flags=re.DOTALL)
            if match:
                dkim_sig = match.group(1)

        if not dkim_sig:
            return {"status": "None", "selector": None, "domain": from_domain, "valid": False, "reason": "No DKIM-Signature header present"}

        # Parse tags d=, s=, a=, bh=
        d_match = re.search(r'\bd=([^;\s]+)', dkim_sig)
        s_match = re.search(r'\bs=([^;\s]+)', dkim_sig)
        a_match = re.search(r'\ba=([^;\s]+)', dkim_sig)

        selector = s_match.group(1).strip() if s_match else None
        signing_domain = d_match.group(1).strip() if d_match else from_domain
        algo = a_match.group(1).strip() if a_match else "rsa-sha256"

        if not selector or not signing_domain:
            return {"status": "Fail", "selector": selector, "domain": signing_domain, "valid": False, "reason": "Malformed DKIM header missing selector or domain"}

        # Query DNS for public key: <selector>._domainkey.<domain>
        dns_query = f"{selector}._domainkey.{signing_domain}"
        try:
            answers = self.resolver.resolve(dns_query, "TXT")
            records = [str(r).strip('"') for rdata in answers for r in rdata.strings]
            if records and any("v=DKIM1" in r or "p=" in r for r in records):
                return {
                    "status": "Pass",
                    "selector": selector,
                    "domain": signing_domain,
                    "algorithm": algo,
                    "valid": True,
                    "reason": f"Valid DKIM public key located at {dns_query}",
                    "dns_record": records[0]
                }
            return {
                "status": "Fail",
                "selector": selector,
                "domain": signing_domain,
                "valid": False,
                "reason": f"No valid DKIM1 public key record found at {dns_query}"
            }
        except Exception:
            # If live DNS fails, return fallback based on signature presence
            return {
                "status": "Neutral",
                "selector": selector,
                "domain": signing_domain,
                "valid": False,
                "reason": f"Could not verify public key at {dns_query} (offline or unresolvable)"
            }

    def _validate_dmarc(self, from_domain: Optional[str], spf_result: Dict[str, Any], dkim_result: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates DMARC DNS policies and alignment with SPF and DKIM domains."""
        if not from_domain:
            return {"status": "None", "domain": None, "policy": "none", "aligned": False, "reason": "No From: domain available"}

        dmarc_dns = f"_dmarc.{from_domain}"
        policy_str = "none"
        record_str = None

        try:
            answers = self.resolver.resolve(dmarc_dns, "TXT")
            records = [str(r).strip('"') for rdata in answers for r in rdata.strings if "v=DMARC1" in str(r)]
            if records:
                record_str = records[0]
                p_match = re.search(r'\bp=([a-zA-Z]+)', record_str)
                if p_match:
                    policy_str = p_match.group(1).lower()
        except Exception:
            pass

        # Check alignment:
        spf_pass = spf_result.get("status") == "Pass"
        dkim_pass = dkim_result.get("status") == "Pass"
        spf_domain = spf_result.get("domain") or ""
        dkim_domain = dkim_result.get("domain") or ""

        # Relaxed alignment: organizational domains match
        spf_aligned = spf_pass and (from_domain.endswith(spf_domain) or spf_domain.endswith(from_domain))
        dkim_aligned = dkim_pass and (from_domain.endswith(dkim_domain) or dkim_domain.endswith(from_domain))

        dmarc_pass = spf_aligned or dkim_aligned

        if dmarc_pass:
            status = "Pass"
            reason = "DMARC aligned: Pass verified via " + ("SPF & DKIM" if (spf_aligned and dkim_aligned) else ("SPF" if spf_aligned else "DKIM"))
        else:
            status = "Fail"
            reason = f"DMARC alignment failed under policy '{policy_str}'. Neither SPF nor DKIM aligned with From: domain."

        return {
            "status": status,
            "domain": from_domain,
            "policy": policy_str,
            "aligned": dmarc_pass,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "reason": reason,
            "record": record_str
        }

    def _detect_header_anomalies(self, header_from: str, return_path: str, reply_to: str, from_domain: str, return_path_domain: str, reply_to_domain: Optional[str], message_id: str, raw_received_count: int) -> List[str]:
        anomalies: List[str] = []

        if not header_from:
            anomalies.append("Missing mandatory RFC 5322 From: header.")

        if return_path and from_domain and return_path_domain:
            if from_domain.lower() != return_path_domain.lower():
                anomalies.append(
                    f"Return-Path mismatch: Envelope sender '{return_path_domain}' differs from visible From '{from_domain}'."
                )

        if reply_to_domain and from_domain and reply_to_domain.lower() != from_domain.lower():
            anomalies.append(
                f"Reply-To diversion: Reply-To domain '{reply_to_domain}' directs responses away from From '{from_domain}'."
            )

        if not message_id:
            anomalies.append("Missing standard Message-ID header (common in automated spam tools).")
        elif not message_id.startswith("<") or not message_id.endswith(">"):
            anomalies.append("Syntactically malformed Message-ID (RFC 5322 Section 3.6.4 violation).")

        if raw_received_count == 0:
            anomalies.append("Zero Received: hops present. Direct client injection suspected.")

        return anomalies

    def _compute_header_score(self, spf_result: Dict[str, Any], dkim_result: Dict[str, Any], dmarc_result: Dict[str, Any], anomalies: List[str]) -> Tuple[float, Dict[str, float]]:
        """Computes a 0 - 100 header threat risk score."""
        spf_status = spf_result.get("status", "None")
        dkim_status = dkim_result.get("status", "None")
        dmarc_status = dmarc_result.get("status", "Fail")

        # SPF component
        spf_score = 0.0
        if spf_status == "Fail":
            spf_score = 100.0
        elif spf_status == "SoftFail":
            spf_score = 65.0
        elif spf_status == "Neutral":
            spf_score = 30.0
        elif spf_status == "None":
            spf_score = 40.0

        # DKIM component
        dkim_score = 0.0
        if dkim_status == "Fail":
            dkim_score = 100.0
        elif dkim_status == "None":
            dkim_score = 50.0

        # DMARC component
        dmarc_score = 0.0
        if dmarc_status == "Fail":
            policy = dmarc_result.get("policy", "none")
            dmarc_score = 90.0 if policy == "reject" else (70.0 if policy == "quarantine" else 50.0)

        # Anomaly penalties
        anomaly_penalty = min(len(anomalies) * 12.0, 40.0)

        composite = (0.35 * spf_score) + (0.30 * dkim_score) + (0.35 * dmarc_score) + anomaly_penalty
        final_score = min(100.0, max(0.0, composite))

        return final_score, {
            "spf_penalty": round(spf_score * 0.35, 2),
            "dkim_penalty": round(dkim_score * 0.30, 2),
            "dmarc_penalty": round(dmarc_score * 0.35, 2),
            "anomaly_penalty": round(anomaly_penalty, 2)
        }

    def _extract_domain(self, address_field: str) -> str:
        """Extracts domain from an email address like 'John Doe <john@example.com>'."""
        if not address_field:
            return ""
        match = re.search(r'@([a-zA-Z0-9\.\-_]+)', address_field)
        if match:
            return match.group(1).rstrip(">.,'\"").lower()
        return ""

    def _empty_response(self) -> Dict[str, Any]:
        return {
            "subject": "",
            "header_from": "",
            "envelope_from": "",
            "reply_to": None,
            "message_id": "",
            "date_header": "",
            "header_score": 0.0,
            "score_breakdown": {},
            "authentication": {
                "spf": {"status": "None", "reason": "Empty input"},
                "dkim": {"status": "None", "reason": "Empty input"},
                "dmarc": {"status": "None", "reason": "Empty input"}
            },
            "relay_hops": [],
            "originating_node": None,
            "anomalies": ["Empty or unparseable email headers."],
            "hop_count": 0
        }
