"""
schema.py (Session-Centric Version)
Suricata Flows + Alerts + Zeek 로그를 Session 중심 Graph 구조로 변환
"""

import json
import hashlib
import re
import uuid
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ── MISP 매핑 테이블 ─────────────────────────────────────

MISP_CATEGORY_MAP = {
    "Misc Attack": "network-activity",
    "Generic Protocol Command Decode": "protocol-anomaly",
    "Misc activity": "network-activity",
    "Attempted Information Leak": "reconnaissance",
    "Attempted Administrator Privilege Gain": "intrusion-attempts",
    "Attempted Denial of Service": "availability",
    "Potentially Bad Traffic": "network-activity",
    "access to a potentially vulnerable web application": "exploit-kit",
    "Web Application Attack": "exploit-kit",
    "Unknown Traffic": "network-activity",
    "Detection of a Network Scan": "reconnaissance",
    "Successful Administrator Privilege Gain": "intrusion-attempts",
    "A Network Trojan was detected": "malware",
    "Potential Corporate Privacy Violation": "information-leak",
    "Not Suspicious Traffic": "benign",
    "Attempted User Privilege Gain": "intrusion-attempts",
    "Large Scale Information Leak": "information-leak",
    "Decode of an RPC Query": "protocol-anomaly",
    "A suspicious filename was detected": "malware",
    "Detection of a non-standard protocol or event": "protocol-anomaly",
    "Information Leak": "information-leak",
    "Executable code was detected": "payload-delivery"
}

SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}

ATTACK_KEYWORDS = {
    "NMAP":    ("network_service_scanning", "discovery", "nmap"),
    "SSH":     ("brute_force", "credential_access", None),
    "EXPLOIT": ("exploit_public_facing_application", "initial_access", None),
    "DROP":    ("command_and_control", "command_and_control", None),
    "Block":   ("command_and_control", "command_and_control", None),
    "SCAN":    ("network_scan", "discovery", None),
}


# ── Session-Centric 통합 스키마 ──────────────────────────

@dataclass
class UnifiedEvent:
    """
    Session-Centric Graph 스키마
    
    노드: Session(중심), Host, Service, Signature, Domain, URL
    엣지: SRC, DST, TARGETS, TRIGGERED, RUNS, QUERIES, ACCESSES
    """

    # ── Session 식별 ──
    session_id:       str = ""          # community_id 또는 UUID
    session_type:     str = ""          # suricata_flow/alert, zeek_conn/dns/http
    event_uuid:       str = ""
    source:           str = ""
    timestamp:        str = ""
    date:             str = ""

    # ── 네트워크 공통 (Host 노드) ──
    src_ip:           str = ""
    dest_ip:          str = ""
    src_port:         int = 0
    dest_port:        int = 0
    proto:            str = ""
    direction:        str = ""

    # ── Suricata Flow ──
    flow_state:       str = ""
    pkts_toserver:    int = 0
    pkts_toclient:    int = 0
    bytes_toserver:   int = 0
    bytes_toclient:   int = 0
    total_bytes:      int = 0
    anomaly_score:    int = 0

    # ── Suricata Alert (TRIGGERED 관계) ──
    has_alert:        bool = False
    alert_count:      int = 0
    signature:        str = ""
    signature_id:     str = ""
    category:         str = ""
    severity_numeric: int = 4
    severity:         str = "low"
    misp_category:    str = ""

    # ── Zeek conn ──
    uid:              str = ""
    service:          str = ""
    duration:         float = 0.0
    orig_bytes:       int = 0
    resp_bytes:       int = 0
    conn_state:       str = ""
    orig_pkts:        int = 0
    resp_pkts:        int = 0

    # ── Zeek DNS (QUERIES 관계) ──
    dns_query:        str = ""
    dns_qtype:        str = ""
    dns_answers:      str = ""
    suspicion_score:  int = 0

    # ── Zeek HTTP (ACCESSES 관계) ──
    http_method:      str = ""
    http_host:        str = ""
    http_uri:         str = ""
    http_user_agent:  str = ""
    http_status:      int = 0
    risk_score:       int = 0

    # ── 위협 인텔 ──
    tactic:           str = ""
    technique:        str = ""
    tool:             str = ""
    cve:              str = ""
    is_malicious:     bool = False
    confidence:       int = 25

    # ── Graph 구조 (Neo4j용) ──
    nodes:            Dict[str, Dict] = field(default_factory=dict)
    edges:            List[Dict] = field(default_factory=list)

    # ── RAG ──
    summary:          str = ""
    mitigation:       str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_jsonl_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


# ── 공통 유틸 ────────────────────────────────────────────

def _gen_uuid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))

def _gen_node_id(node_type: str, key: str) -> str:
    return hashlib.md5(f"{node_type}:{key}".encode()).hexdigest()[:16]

def _extract_date(ts: str) -> str:
    return ts[:10] if ts else ""

def _direction(src: str, dst: str) -> str:
    internal_prefixes = ['10.', '172.16.', '192.168.']
    src_internal = any(src.startswith(p) for p in internal_prefixes)
    dst_internal = any(dst.startswith(p) for p in internal_prefixes)
    
    if src_internal and not dst_internal:
        return "outbound"
    elif not src_internal and dst_internal:
        return "inbound"
    elif src_internal and dst_internal:
        return "internal"
    else:
        return "external"

def _extract_attack(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for kw, (tech, tact, tool) in ATTACK_KEYWORDS.items():
        if kw in text.upper():
            result["technique"] = tech
            result["tactic"] = tact
            if tool:
                result["tool"] = tool
            break
    
    cve_m = re.search(r"CVE-\d{4}-\d+", text)
    if cve_m:
        result["cve"] = cve_m.group(0)
    return result

def _confidence(severity: int) -> int:
    return {1: 95, 2: 75, 3: 50}.get(severity, 25)


# ── Suricata Flow 변환 (Alerts 병합 지원) ────────────────

def from_suricata_flow(row: Dict, alert_map: Dict[str, List] = None) -> UnifiedEvent:
    """
    Suricata flow → Session-centric Graph
    alert_map: {community_id: [alert_dicts]}로 미리 로드된 alert 정보
    """
    ts = row.get("ts", "")
    src_ip = row.get("src_ip", "")
    dest_ip = row.get("dest_ip", "")
    proto = row.get("proto", "TCP").lower()
    community_id = row.get("community_id", "").strip()
    
    # Session ID
    session_id = community_id or _gen_uuid(f"flow{ts}{src_ip}{dest_ip}{proto}")
    
    # 노드 ID
    src_host_id = _gen_node_id('host', src_ip)
    dst_host_id = _gen_node_id('host', dest_ip)
    
    dest_port = row.get("dest_port", "unknown")
    service_key = f"{dest_ip}:{dest_port}/{proto}"
    service_id = _gen_node_id('service', service_key)
    
    # Flow 통계
    try:
        pkts_toserver = int(row.get("pkts_toserver", 0) or 0)
        pkts_toclient = int(row.get("pkts_toclient", 0) or 0)
        bytes_toserver = int(row.get("bytes_toserver", 0) or 0)
        bytes_toclient = int(row.get("bytes_toclient", 0) or 0)
    except:
        pkts_toserver = pkts_toclient = bytes_toserver = bytes_toclient = 0
    
    total_bytes = bytes_toserver + bytes_toclient
    
    # 이상 점수 계산
    anomaly_score = 0
    flow_state = row.get("flow_state", "").lower()
    if "closed" not in flow_state:
        anomaly_score += 20
    if pkts_toserver > 0 and pkts_toclient == 0:
        anomaly_score += 25
    
    # 기본 노드
    nodes = {
        "src_host": {
            "id": src_host_id,
            "type": "host",
            "ip": src_ip,
            "label": src_ip
        },
        "dst_host": {
            "id": dst_host_id,
            "type": "host",
            "ip": dest_ip,
            "label": dest_ip
        },
        "service": {
            "id": service_id,
            "type": "service",
            "address": service_key,
            "ip": dest_ip,
            "port": dest_port,
            "protocol": proto,
            "label": service_key
        }
    }
    
    # 기본 엣지
    edges = [
        {"from": session_id, "to": src_host_id, "type": "SRC"},
        {"from": session_id, "to": dst_host_id, "type": "DST"},
        {"from": session_id, "to": service_id, "type": "TARGETS"},
        {"from": dst_host_id, "to": service_id, "type": "RUNS"}
    ]
    
    # Alert 병합
    has_alert = False
    alert_count = 0
    signature = ""
    category = ""
    severity_numeric = 4
    signature_id = ""
    
    if alert_map and community_id and community_id in alert_map:
        alerts = alert_map[community_id]
        has_alert = True
        alert_count = len(alerts)
        
        # 가장 심각한 alert 선택
        primary_alert = min(alerts, key=lambda x: x['severity'])
        signature = primary_alert['signature']
        category = primary_alert['category']
        severity_numeric = primary_alert['severity']
        signature_id = _gen_node_id('signature', f"{signature}:{category}")
        
        # Signature 노드 추가
        for alert in alerts:
            sig_key = f"{alert['signature']}:{alert['category']}"
            sig_id = _gen_node_id('signature', sig_key)
            
            nodes[f"signature_{sig_id}"] = {
                "id": sig_id,
                "type": "signature",
                "signature": alert['signature'],
                "category": alert['category'],
                "severity": alert['severity'],
                "label": alert['signature']
            }
            
            edges.append({
                "from": session_id,
                "to": sig_id,
                "type": "TRIGGERED"
            })
    
    attack = _extract_attack(signature) if signature else {}
    
    return UnifiedEvent(
        session_id=session_id,
        session_type="suricata_flow",
        event_uuid=_gen_uuid(f"{ts}{src_ip}{dest_ip}"),
        source="suricata_flow",
        timestamp=ts,
        date=_extract_date(ts),
        src_ip=src_ip,
        dest_ip=dest_ip,
        proto=proto,
        direction=_direction(src_ip, dest_ip),
        flow_state=row.get("flow_state", ""),
        pkts_toserver=pkts_toserver,
        pkts_toclient=pkts_toclient,
        bytes_toserver=bytes_toserver,
        bytes_toclient=bytes_toclient,
        total_bytes=total_bytes,
        anomaly_score=min(anomaly_score, 100),
        has_alert=has_alert,
        alert_count=alert_count,
        signature=signature,
        signature_id=signature_id,
        category=category,
        severity_numeric=severity_numeric,
        severity=SEVERITY_MAP.get(severity_numeric, "low"),
        misp_category=MISP_CATEGORY_MAP.get(category, "other"),
        tactic=attack.get("tactic", ""),
        technique=attack.get("technique", ""),
        cve=attack.get("cve", ""),
        is_malicious=severity_numeric <= 2,
        confidence=_confidence(severity_numeric) if has_alert else 20,
        nodes=nodes,
        edges=edges,
        summary=f"[Flow] {src_ip} → {dest_ip} | {total_bytes} bytes" + 
                (f" | Alert: {signature}" if has_alert else ""),
        mitigation="Monitor suspicious flow" if anomaly_score > 50 else "Normal flow"
    )


# ── Zeek Connection 변환 ─────────────────────────────────

def from_zeek_conn(row: Dict) -> UnifiedEvent:
    ts = row.get("ts", "")
    src_ip = row.get("orig_h", "")
    dest_ip = row.get("resp_h", "")
    proto = row.get("proto", "")
    community_id = row.get("community_id", "").strip()
    
    session_id = community_id or _gen_uuid(f"conn{ts}{src_ip}{dest_ip}")
    
    src_host_id = _gen_node_id('host', src_ip)
    dst_host_id = _gen_node_id('host', dest_ip)
    
    resp_port = row.get("resp_p", "unknown")
    service_key = f"{dest_ip}:{resp_port}/{proto}"
    service_id = _gen_node_id('service', service_key)
    
    try:
        orig_bytes = int(float(row.get("orig_bytes", 0) or 0))
        resp_bytes = int(float(row.get("resp_bytes", 0) or 0))
        duration = float(row.get("duration", 0) or 0)
    except:
        orig_bytes = resp_bytes = 0
        duration = 0.0
    
    conn_state = row.get("conn_state", "")
    suspicious = conn_state in ("REJ", "RSTO", "RSTOS0", "S0")
    severity = 3 if suspicious else 4
    
    anomaly_score = 30 if suspicious else 0
    if orig_bytes > 0 and resp_bytes == 0:
        anomaly_score += 20
    
    return UnifiedEvent(
        session_id=session_id,
        session_type="zeek_connection",
        event_uuid=_gen_uuid(f"{ts}{src_ip}{dest_ip}"),
        source="zeek_conn",
        timestamp=ts,
        date=_extract_date(ts),
        src_ip=src_ip,
        dest_ip=dest_ip,
        proto=proto,
        direction=_direction(src_ip, dest_ip),
        uid=row.get("uid", ""),
        service=row.get("service", ""),
        duration=duration,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        conn_state=conn_state,
        severity_numeric=severity,
        severity=SEVERITY_MAP.get(severity, "low"),
        anomaly_score=min(anomaly_score, 100),
        is_malicious=suspicious,
        confidence=40 if suspicious else 20,
        nodes={
            "src_host": {"id": src_host_id, "type": "host", "ip": src_ip},
            "dst_host": {"id": dst_host_id, "type": "host", "ip": dest_ip},
            "service": {"id": service_id, "type": "service", "address": service_key}
        },
        edges=[
            {"from": session_id, "to": src_host_id, "type": "SRC"},
            {"from": session_id, "to": dst_host_id, "type": "DST"},
            {"from": session_id, "to": service_id, "type": "TARGETS"},
            {"from": dst_host_id, "to": service_id, "type": "RUNS"}
        ],
        summary=f"[Conn] {src_ip} → {dest_ip} | {proto} | {conn_state}",
        mitigation="Review connection state" if suspicious else "Normal connection"
    )


# ── Zeek DNS 변환 ────────────────────────────────────────

def from_zeek_dns(row: Dict) -> UnifiedEvent:
    ts = row.get("ts", "")
    src_ip = row.get("orig_h", "")
    dest_ip = row.get("resp_h", "")
    query = row.get("query", "")
    community_id = row.get("community_id", "").strip()
    
    session_id = community_id or _gen_uuid(f"dns{ts}{src_ip}{query}")
    
    src_host_id = _gen_node_id('host', src_ip)
    dst_host_id = _gen_node_id('host', dest_ip)
    domain_id = _gen_node_id('domain', query)
    
    # DNS 의심도
    is_suspicious = len(query) > 30 or query.endswith((".tk", ".ml", ".ga"))
    suspicion_score = 60 if is_suspicious else 20
    severity = 3 if is_suspicious else 4
    
    nodes = {
        "src_host": {"id": src_host_id, "type": "host", "ip": src_ip},
        "dst_host": {"id": dst_host_id, "type": "host", "ip": dest_ip},
        "domain": {"id": domain_id, "type": "domain", "domain": query}
    }
    
    edges = [
        {"from": session_id, "to": src_host_id, "type": "SRC"},
        {"from": session_id, "to": dst_host_id, "type": "DST"},
        {"from": session_id, "to": domain_id, "type": "QUERIES"}
    ]
    
    # DNS answers
    answers = row.get("answers", "")
    if answers:
        for answer in answers.split(','):
            answer = answer.strip()
            if answer and '.' in answer:
                answer_host_id = _gen_node_id('host', answer)
                nodes[f"answer_{answer_host_id}"] = {
                    "id": answer_host_id,
                    "type": "host",
                    "ip": answer
                }
                edges.append({
                    "from": domain_id,
                    "to": answer_host_id,
                    "type": "RESOLVED_TO"
                })
    
    return UnifiedEvent(
        session_id=session_id,
        session_type="zeek_dns",
        event_uuid=_gen_uuid(f"{ts}{src_ip}{query}"),
        source="zeek_dns",
        timestamp=ts,
        date=_extract_date(ts),
        src_ip=src_ip,
        dest_ip=dest_ip,
        direction=_direction(src_ip, dest_ip),
        dns_query=query,
        dns_qtype=row.get("qtype_name", ""),
        dns_answers=answers,
        suspicion_score=suspicion_score,
        severity_numeric=severity,
        severity=SEVERITY_MAP.get(severity, "low"),
        is_malicious=is_suspicious,
        confidence=60 if is_suspicious else 20,
        nodes=nodes,
        edges=edges,
        summary=f"[DNS] {src_ip} → {query}",
        mitigation="Check domain reputation" if is_suspicious else "Normal DNS query"
    )


# ── Zeek HTTP 변환 ───────────────────────────────────────

def from_zeek_http(row: Dict) -> UnifiedEvent:
    ts = row.get("ts", "")
    src_ip = row.get("orig_h", "")
    dest_ip = row.get("resp_h", "")
    method = row.get("method", "")
    host = row.get("host", "")
    uri = row.get("uri", "")
    ua = row.get("user_agent", "")
    community_id = row.get("community_id", "").strip()
    
    session_id = community_id or _gen_uuid(f"http{ts}{src_ip}{uri}")
    
    src_host_id = _gen_node_id('host', src_ip)
    dst_host_id = _gen_node_id('host', dest_ip)
    
    resp_port = row.get("resp_p", "80")
    service_key = f"{dest_ip}:{resp_port}/http"
    service_id = _gen_node_id('service', service_key)
    
    full_url = f"http://{host}{uri}" if host else uri
    url_id = _gen_node_id('url', full_url)
    
    # 위험도 계산
    suspicious_ua = any(t in ua.lower() for t in ["curl", "python", "scanner"])
    risk_score = 60 if suspicious_ua else 20
    severity = 2 if suspicious_ua else 4
    
    return UnifiedEvent(
        session_id=session_id,
        session_type="zeek_http",
        event_uuid=_gen_uuid(f"{ts}{src_ip}{uri}"),
        source="zeek_http",
        timestamp=ts,
        date=_extract_date(ts),
        src_ip=src_ip,
        dest_ip=dest_ip,
        direction=_direction(src_ip, dest_ip),
        http_method=method,
        http_host=host,
        http_uri=uri,
        http_user_agent=ua,
        http_status=int(row.get("status_code", 0) or 0),
        risk_score=risk_score,
        severity_numeric=severity,
        severity=SEVERITY_MAP.get(severity, "low"),
        is_malicious=suspicious_ua,
        confidence=60 if suspicious_ua else 20,
        nodes={
            "src_host": {"id": src_host_id, "type": "host", "ip": src_ip},
            "dst_host": {"id": dst_host_id, "type": "host", "ip": dest_ip},
            "service": {"id": service_id, "type": "service", "address": service_key},
            "url": {"id": url_id, "type": "url", "url": full_url}
        },
        edges=[
            {"from": session_id, "to": src_host_id, "type": "SRC"},
            {"from": session_id, "to": dst_host_id, "type": "DST"},
            {"from": session_id, "to": service_id, "type": "TARGETS"},
            {"from": session_id, "to": url_id, "type": "ACCESSES"}
        ],
        summary=f"[HTTP] {src_ip} → {full_url}",
        mitigation="Block suspicious UA" if suspicious_ua else "Normal HTTP request"
    )


# ── 파서 엔트리포인트 ─────────────────────────────────────

SOURCE_PARSER = {
    "suricata_flow": from_suricata_flow,
    "zeek_conn": from_zeek_conn,
    "zeek_dns": from_zeek_dns,
    "zeek_http": from_zeek_http,
}

def parse_row(source: str, row: Dict, alert_map: Dict = None) -> Optional[UnifiedEvent]:
    """
    소스별 파싱
    alert_map: suricata_flow에만 사용
    """
    parser = SOURCE_PARSER.get(source)
    if not parser:
        logger.error(f"Unknown source: {source}")
        return None
    
    try:
        ts = row.get("ts", "") or row.get("timestamp", "")
        if not ts or ts.startswith("1970"):
            return None
        
        src = row.get("src_ip") or row.get("orig_h", "")
        if not src:
            return None
        
        if source == "suricata_flow":
            return parser(row, alert_map)
        else:
            return parser(row)
    except Exception as e:
        logger.debug(f"Parse error [{source}]: {e}")
        return None

