"""
avro_schema.py

입력 파일:
  - eve.json          : Suricata JSON 로그 (event_type: flow | alert | tls | ssh)
  - conn_*.log        : Zeek TSV (community_id 포함)
  - dns_*.log         : Zeek TSV
  - http_*.log        : Zeek TSV

세션 연결 전략:
  - Suricata flow/alert → flow_id 기반 session_id
  - Zeek conn          → community_id 기반 session_id (Suricata와 매핑 가능)
  - Zeek dns/http      → uid 기반 session_id
"""

# ─────────────────────────────────────────────────────────────
# 1. Suricata Flow  (event_type = "flow")
#    원본 필드: timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
#               proto, app_proto, flow.{pkts_toserver, pkts_toclient,
#               bytes_toserver, bytes_toclient, start, end, age, state, reason, alerted}
# ─────────────────────────────────────────────────────────────
SURICATA_AVRO_SCHEMA = {
    "type": "record",
    "name": "SuricataEvent",
    "namespace": "com.ctilab.honeypot",
    "fields": [
        # ── 원본 공통 ──
        {"name": "timestamp",       "type": ["null", "string"], "default": None},
        {"name": "flow_id",         "type": ["null", "float"], "default": None},  # int64 → string (정밀도 손실 방지)
        {"name": "event_type",      "type": ["null", "string"], "default": None},  # "flow"
        {"name": "src_ip",          "type": ["null", "string"], "default": None},
        {"name": "src_port",        "type": ["null", "float"],    "default": None},
        {"name": "dest_ip",         "type": ["null", "string"], "default": None},
        {"name": "dest_port",       "type": ["null", "float"],    "default": None},
        {"name": "proto",           "type": ["null", "string"], "default": None},
        {"name": "app_proto",       "type": ["null", "string"], "default": None},  # dns/tls/http/failed 등
        {"name": "direction",       "type": ["null", "string"], "default": None},  # to_server/to_client (원본)        

        # ── flow 서브객체 펼치기 ──
        {"name": "pkts_toserver",   "type": ["null", "long"],   "default": None},
        {"name": "pkts_toclient",   "type": ["null", "long"],   "default": None},
        {"name": "bytes_toserver",  "type": ["null", "long"],   "default": None},
        {"name": "bytes_toclient",  "type": ["null", "long"],   "default": None},
        {"name": "flow_start",      "type": ["null", "string"], "default": None},
        {"name": "flow_end",        "type": ["null", "string"], "default": None},
        {"name": "flow_age",        "type": ["null", "int"],    "default": None},
        {"name": "flow_state",      "type": ["null", "string"], "default": None},  # new/established/closed
        {"name": "flow_reason",     "type": ["null", "string"], "default": None},  # timeout/shutdown/forced
        {"name": "flow_alerted",    "type": ["null", "boolean"],"default": None},

        # ── alert 서브객체 펼치기 ──
        {"name": "alert_action",       "type": ["null", "string"], "default": None},  # allowed/blocked
        {"name": "alert_signature_id", "type": ["null", "int"],    "default": None},
        {"name": "alert_signature",    "type": ["null", "string"], "default": None},
        {"name": "alert_category",     "type": ["null", "string"], "default": None},
        {"name": "alert_severity",     "type": ["null", "int"],    "default": None},  # 1~4

        # ── 전처리 파생 ──
        {"name": "session_id",      "type": ["null", "string"], "default": None},  # flow_id 기반
        {"name": "date",            "type": ["null", "string"], "default": None},  # YYYY-MM-DD (파티션)
        {"name": "direction",       "type": ["null", "string"], "default": None},  # inbound/outbound/internal
        {"name": "net_direction",   "type": ["null", "string"], "default": None},  # inbound/outbound/internal (IP 기반)
        {"name": "total_bytes",     "type": ["null", "long"],   "default": None},
        {"name": "anomaly_score",   "type": ["null", "int"],    "default": None},
        {"name": "severity",        "type": ["null", "float"], "default": None},  # low/medium/high/critical
        {"name": "severity_label",  "type": ["null", "string"], "default": None},  # low~critical
        {"name": "is_malicious",    "type": ["null", "boolean"],"default": None},
        {"name": "misp_category",   "type": ["null", "string"], "default": None},
        {"name": "tactic",          "type": ["null", "string"], "default": None},
        {"name": "technique",       "type": ["null", "string"], "default": None},
        {"name": "cve",             "type": ["null", "string"], "default": None},


        # ── Graph (JSON string) ──
        {"name": "nodes_json",      "type": ["null", "string"], "default": None},
        {"name": "edges_json",      "type": ["null", "string"], "default": None},
        {"name": "summary",         "type": ["null", "string"], "default": None},
    ]
}


# ─────────────────────────────────────────────────────────────
# 2. Zeek Connection  (conn_*.log)
#    #fields: ts uid id.orig_h id.orig_p id.resp_h id.resp_p
#             proto service duration orig_bytes resp_bytes conn_state
#             local_orig local_resp missed_bytes history
#             orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes
#             tunnel_parents ip_proto community_id   ← community_id 있음!
# ─────────────────────────────────────────────────────────────
ZEEK_CONN_AVRO_SCHEMA = {
    "type": "record",
    "name": "ZeekConn",
    "namespace": "com.ctilab.honeypot",
    "fields": [
        # ── 원본 ──
        {"name": "ts",              "type": ["null", "float"], "default": None},  # Unix timestamp string
        {"name": "uid",             "type": ["null", "string"], "default": None},
        {"name": "orig_h",          "type": ["null", "float"], "default": None},
        {"name": "orig_p",          "type": ["null", "float"],    "default": None},
        {"name": "resp_h",          "type": ["null", "float"], "default": None},
        {"name": "resp_p",          "type": ["null", "float"],    "default": None},
        {"name": "proto",           "type": ["null", "string"], "default": None},
        {"name": "service",         "type": ["null", "string"], "default": None},
        {"name": "duration",        "type": ["null", "double"], "default": None},
        {"name": "orig_bytes",      "type": ["null", "float"],   "default": None},
        {"name": "resp_bytes",      "type": ["null", "float"],   "default": None},
        {"name": "conn_state",      "type": ["null", "string"], "default": None},
        {"name": "local_orig",      "type": ["null", "boolean"],"default": None},
        {"name": "local_resp",      "type": ["null", "boolean"],"default": None},
        {"name": "missed_bytes",    "type": ["null", "float"],   "default": None},
        {"name": "history",         "type": ["null", "string"], "default": None},
        {"name": "orig_pkts",       "type": ["null", "float"],   "default": None},
        {"name": "orig_ip_bytes",   "type": ["null", "float"],   "default": None},
        {"name": "resp_pkts",       "type": ["null", "float"],   "default": None},
        {"name": "resp_ip_bytes",   "type": ["null", "float"],   "default": None},
        {"name": "tunnel_parents",  "type": ["null", "string"], "default": None},  # set → string
        {"name": "ip_proto",        "type": ["null", "int"],    "default": None},
        {"name": "community_id",    "type": ["null", "string"], "default": None},  # ← Suricata flow_id와 매핑 가능

        # ── 전처리 파생 ──
        {"name": "session_id",      "type": ["null", "string"], "default": None},  # community_id 우선, 없으면 uid
        {"name": "date",            "type": ["null", "string"], "default": None},
        {"name": "direction",       "type": ["null", "string"], "default": None},
        {"name": "anomaly_score",   "type": ["null", "float"],    "default": None},
        {"name": "severity",        "type": ["null", "float"], "default": None},
        {"name": "is_malicious",    "type": ["null", "boolean"],"default": None},

        # ── Graph ──
        {"name": "nodes_json",      "type": ["null", "string"], "default": None},
        {"name": "edges_json",      "type": ["null", "string"], "default": None},
        {"name": "summary",         "type": ["null", "string"], "default": None},
    ]
}


# ─────────────────────────────────────────────────────────────
# 3. Zeek DNS  (dns_*.log)
#    #fields: ts uid id.orig_h id.orig_p id.resp_h id.resp_p
#             proto trans_id rtt query qclass qclass_name
#             qtype qtype_name rcode rcode_name AA TC RD RA Z
#             answers TTLs rejected
#    ※ community_id 없음 → uid 기반 session_id
# ─────────────────────────────────────────────────────────────
ZEEK_DNS_AVRO_SCHEMA = {
    "type": "record",
    "name": "ZeekDns",
    "namespace": "com.ctilab.honeypot",
    "fields": [
        # ── 원본 ──
        {"name": "ts",          "type": ["null", "float"], "default": None},
        {"name": "uid",         "type": ["null", "string"], "default": None},
        {"name": "orig_h",      "type": ["null", "float"], "default": None},
        {"name": "orig_p",      "type": ["null", "float"],    "default": None},
        {"name": "resp_h",      "type": ["null", "float"], "default": None},
        {"name": "resp_p",      "type": ["null", "float"],    "default": None},
        {"name": "proto",       "type": ["null", "string"], "default": None},
        {"name": "trans_id",    "type": ["null", "int"],    "default": None},
        {"name": "rtt",         "type": ["null", "double"], "default": None},  # "-" → None
        {"name": "query",       "type": ["null", "string"], "default": None},
        {"name": "qclass",      "type": ["null", "int"],    "default": None},
        {"name": "qclass_name", "type": ["null", "string"], "default": None},
        {"name": "qtype",       "type": ["null", "int"],    "default": None},
        {"name": "qtype_name",  "type": ["null", "string"], "default": None},
        {"name": "rcode",       "type": ["null", "int"],    "default": None},
        {"name": "rcode_name",  "type": ["null", "string"], "default": None},  # NOERROR/NXDOMAIN
        {"name": "AA",          "type": ["null", "boolean"],"default": None},
        {"name": "TC",          "type": ["null", "boolean"],"default": None},
        {"name": "RD",          "type": ["null", "boolean"],"default": None},
        {"name": "RA",          "type": ["null", "boolean"],"default": None},
        {"name": "Z",           "type": ["null", "int"],    "default": None},
        {"name": "answers",     "type": ["null", "string"], "default": None},  # vector → comma-joined string
        {"name": "TTLs",        "type": ["null", "string"], "default": None},  # vector → comma-joined string
        {"name": "rejected",    "type": ["null", "boolean"],"default": None},

        # ── 전처리 파생 ──
        {"name": "session_id",      "type": ["null", "string"], "default": None},  # uid 기반
        {"name": "date",            "type": ["null", "string"], "default": None},
        {"name": "direction",       "type": ["null", "string"], "default": None},
        {"name": "suspicion_score", "type": ["null", "int"],    "default": None},
        {"name": "is_malicious",    "type": ["null", "boolean"],"default": None},
        {"name": "severity",        "type": ["null", "float"], "default": None},

        # ── Graph ──
        {"name": "nodes_json",  "type": ["null", "string"], "default": None},
        {"name": "edges_json",  "type": ["null", "string"], "default": None},
        {"name": "summary",     "type": ["null", "string"], "default": None},
    ]
}


# ─────────────────────────────────────────────────────────────
# 4. Zeek HTTP  (http_*.log)
#    #fields: ts uid id.orig_h id.orig_p id.resp_h id.resp_p
#             trans_depth method host uri referrer version user_agent origin
#             request_body_len response_body_len status_code status_msg
#             info_code info_msg tags username password proxied
#             orig_fuids orig_filenames orig_mime_types
#             resp_fuids resp_filenames resp_mime_types
#    ※ community_id 없음 → uid 기반 session_id
# ─────────────────────────────────────────────────────────────
ZEEK_HTTP_AVRO_SCHEMA = {
    "type": "record",
    "name": "ZeekHttp",
    "namespace": "com.ctilab.honeypot",
    "fields": [
        # ── 원본 ──
        {"name": "ts",                  "type": ["null", "float"], "default": None},
        {"name": "uid",                 "type": ["null", "string"], "default": None},
        {"name": "orig_h",              "type": ["null", "float"], "default": None},
        {"name": "orig_p",              "type": ["null", "float"],    "default": None},
        {"name": "resp_h",              "type": ["null", "float"], "default": None},
        {"name": "resp_p",              "type": ["null", "float"],    "default": None},
        {"name": "trans_depth",         "type": ["null", "int"],    "default": None},
        {"name": "method",              "type": ["null", "string"], "default": None},
        {"name": "host",                "type": ["null", "string"], "default": None},
        {"name": "uri",                 "type": ["null", "string"], "default": None},
        {"name": "referrer",            "type": ["null", "string"], "default": None},  # "-" → None
        {"name": "version",             "type": ["null", "string"], "default": None},
        {"name": "user_agent",          "type": ["null", "string"], "default": None},
        {"name": "origin",              "type": ["null", "string"], "default": None},
        {"name": "request_body_len",    "type": ["null", "long"],   "default": None},
        {"name": "response_body_len",   "type": ["null", "long"],   "default": None},
        {"name": "status_code",         "type": ["null", "int"],    "default": None},  # "-" → None
        {"name": "status_msg",          "type": ["null", "string"], "default": None},
        {"name": "info_code",           "type": ["null", "int"],    "default": None},
        {"name": "info_msg",            "type": ["null", "string"], "default": None},
        {"name": "tags",                "type": ["null", "string"], "default": None},  # set[enum] → string
        {"name": "username",            "type": ["null", "string"], "default": None},
        {"name": "password",            "type": ["null", "string"], "default": None},
        {"name": "resp_fuids",          "type": ["null", "string"], "default": None},  # vector → string
        {"name": "resp_mime_types",     "type": ["null", "string"], "default": None},  # e.g. "text/html"

        # ── 전처리 파생 ──
        {"name": "session_id",   "type": ["null", "string"],  "default": None},  # uid 기반
        {"name": "date",         "type": ["null", "string"],  "default": None},
        {"name": "direction",    "type": ["null", "string"],  "default": None},
        {"name": "full_url",     "type": ["null", "string"],  "default": None},  # host + uri 조합
        {"name": "risk_score",   "type": ["null", "float"],     "default": None},
        {"name": "severity",     "type": ["null", "float"],  "default": None},
        {"name": "is_malicious", "type": ["null", "boolean"], "default": None},
        {"name": "tactic",       "type": ["null", "string"],  "default": None},  # exploit URI 패턴 탐지
        {"name": "technique",    "type": ["null", "string"],  "default": None},

        # ── Graph ──
        {"name": "nodes_json",   "type": ["null", "string"], "default": None},
        {"name": "edges_json",   "type": ["null", "string"], "default": None},
        {"name": "summary",      "type": ["null", "string"], "default": None},
    ]
}


# ─────────────────────────────────────────────────────────────
# 스키마 레지스트리 (소스명으로 조회)
# ─────────────────────────────────────────────────────────────
SCHEMA_REGISTRY = {
    "suricata":       SURICATA_AVRO_SCHEMA,
    "zeek_conn":      ZEEK_CONN_AVRO_SCHEMA,
    "zeek_dns":       ZEEK_DNS_AVRO_SCHEMA,
    "zeek_http":      ZEEK_HTTP_AVRO_SCHEMA,
}