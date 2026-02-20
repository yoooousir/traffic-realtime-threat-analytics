"""
preprocess.py (Session-Centric Version)
Suricata Flows + Alerts 병합 → JSONL → Delta Lake
"""

import csv
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

try:
    import pyarrow as pa
    from deltalake import write_deltalake
    DELTA_AVAILABLE = True
except ImportError:
    DELTA_AVAILABLE = False
    logger.warning("Delta Lake not available. Install pyarrow and deltalake for Delta support.")

from preprocessor.schema import parse_row, UnifiedEvent


# ── 소스 파일 정의 ────────────────────────────────────────

SOURCE_FILES = {
    "suricata_flows": "suricata_flows.csv",
    "suricata_alerts": "suricata_alerts.csv",
    "zeek_conn": "zeek_conn.csv",
    "zeek_dns":  "zeek_dns.csv",
    "zeek_http": "zeek_http.csv",
}


# ============================================================
# 1. JSONL 변환 (Alert 병합 지원)
# ============================================================

class MultiSourceConverter:
    """
    Suricata Flows + Alerts 병합 + Zeek → 공통 스키마 JSONL
    """

    def __init__(self, base_dir: str = ".", output_dir: str = "./output"):
        self.base_dir   = Path(base_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.alert_map: Dict[str, List[Dict]] = {}

    def load_alerts(self, alerts_csv: Path):
        """
        Suricata alerts를 community_id 기반으로 메모리에 로드
        """
        if not alerts_csv.exists():
            logger.warning(f"Alert 파일 없음: {alerts_csv}")
            return
        
        logger.info("📊 Loading Suricata alerts into memory...")
        with open(alerts_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cleaned = {k.strip('"'): v.strip('"') for k, v in row.items()}
                community_id = cleaned.get('community_id', '').strip()
                
                if community_id:
                    if community_id not in self.alert_map:
                        self.alert_map[community_id] = []
                    
                    self.alert_map[community_id].append({
                        'signature': cleaned.get('signature', ''),
                        'category': cleaned.get('category', ''),
                        'severity': int(cleaned.get('severity', 4))
                    })
        
        logger.info(f"✅ Loaded alerts for {len(self.alert_map)} community_ids")

    def convert_all(self) -> Tuple[Path, Dict[str, int]]:
        """
        모든 소스 변환 후 단일 JSONL로 병합
        """
        output_file = self.output_dir / "unified_events.jsonl"
        stats: Dict[str, int] = {}
        total = 0

        # 1. Alert 먼저 로드
        alerts_path = self.base_dir / SOURCE_FILES["suricata_alerts"]
        self.load_alerts(alerts_path)

        with open(output_file, "w", encoding="utf-8") as f_out:
            # 2. Suricata Flows (Alert 병합)
            flows_path = self.base_dir / SOURCE_FILES["suricata_flows"]
            if flows_path.exists():
                logger.info("📊 Processing Suricata flows...")
                count = 0
                with open(flows_path, "r", encoding="utf-8") as f_in:
                    for row in csv.DictReader(f_in):
                        cleaned = {k.strip('"'): v.strip('"') for k, v in row.items()}
                        event = parse_row("suricata_flow", cleaned, self.alert_map)
                        if event is None:
                            continue
                        f_out.write(event.to_jsonl_line() + "\n")
                        count += 1
                stats["suricata_flows"] = count
                total += count
                logger.info(f"  [suricata_flows] {count}건 변환 완료")
            
            # 3. Zeek 로그들
            for source in ["zeek_conn", "zeek_dns", "zeek_http"]:
                csv_path = self.base_dir / SOURCE_FILES[source]
                if not csv_path.exists():
                    logger.warning(f"파일 없음: {csv_path}")
                    stats[source] = 0
                    continue

                count = 0
                with open(csv_path, "r", encoding="utf-8") as f_in:
                    for row in csv.DictReader(f_in):
                        cleaned = {k.strip('"'): v.strip('"') for k, v in row.items()}
                        event = parse_row(source, cleaned)
                        if event is None:
                            continue
                        f_out.write(event.to_jsonl_line() + "\n")
                        count += 1

                stats[source] = count
                total += count
                logger.info(f"  [{source}] {count}건 변환 완료")

        logger.info(f"JSONL 저장 완료 → {output_file} (총 {total}건)")
        return output_file, stats


# ============================================================
# 2. Delta Lake 저장
# ============================================================

if DELTA_AVAILABLE:
    DELTA_SCHEMA = pa.schema([
        # Session (Core)
        pa.field("session_id",       pa.string()),
        pa.field("session_type",     pa.string()),
        pa.field("event_uuid",       pa.string()),
        pa.field("source",           pa.string()),
        pa.field("timestamp",        pa.string()),
        pa.field("date",             pa.string()),
        
        # Network
        pa.field("src_ip",           pa.string()),
        pa.field("dest_ip",          pa.string()),
        pa.field("src_port",         pa.int32()),
        pa.field("dest_port",        pa.int32()),
        pa.field("proto",            pa.string()),
        pa.field("direction",        pa.string()),
        
        # Suricata Flow
        pa.field("flow_state",       pa.string()),
        pa.field("pkts_toserver",    pa.int64()),
        pa.field("pkts_toclient",    pa.int64()),
        pa.field("bytes_toserver",   pa.int64()),
        pa.field("bytes_toclient",   pa.int64()),
        pa.field("total_bytes",      pa.int64()),
        pa.field("anomaly_score",    pa.int32()),
        
        # Suricata Alert
        pa.field("has_alert",        pa.bool_()),
        pa.field("alert_count",      pa.int32()),
        pa.field("signature",        pa.string()),
        pa.field("signature_id",     pa.string()),
        pa.field("category",         pa.string()),
        pa.field("severity",         pa.string()),
        pa.field("severity_numeric", pa.int32()),
        pa.field("misp_category",    pa.string()),
        
        # Zeek conn
        pa.field("uid",              pa.string()),
        pa.field("service",          pa.string()),
        pa.field("conn_state",       pa.string()),
        pa.field("orig_bytes",       pa.int64()),
        pa.field("resp_bytes",       pa.int64()),
        pa.field("duration",         pa.float64()),
        pa.field("orig_pkts",        pa.int64()),
        pa.field("resp_pkts",        pa.int64()),
        
        # Zeek DNS
        pa.field("dns_query",        pa.string()),
        pa.field("dns_qtype",        pa.string()),
        pa.field("dns_answers",      pa.string()),
        pa.field("suspicion_score",  pa.int32()),
        
        # Zeek HTTP
        pa.field("http_method",      pa.string()),
        pa.field("http_host",        pa.string()),
        pa.field("http_uri",         pa.string()),
        pa.field("http_user_agent",  pa.string()),
        pa.field("http_status",      pa.int32()),
        pa.field("risk_score",       pa.int32()),
        
        # 위협 인텔
        pa.field("tactic",           pa.string()),
        pa.field("technique",        pa.string()),
        pa.field("tool",             pa.string()),
        pa.field("cve",              pa.string()),
        pa.field("is_malicious",     pa.bool_()),
        pa.field("confidence",       pa.int32()),
        
        # RAG
        pa.field("summary",          pa.string()),
        pa.field("mitigation",       pa.string()),
        
        # Graph (stored as JSON strings)
        pa.field("nodes_json",       pa.string()),
        pa.field("edges_json",       pa.string()),
    ])
else:
    DELTA_SCHEMA = None


class DeltaLakeWriter:
    """JSONL → Delta Lake (date/severity 파티션)"""

    def __init__(self, delta_path: str = "./delta_lake/unified_events"):
        self.delta_path = delta_path

    def write(self, jsonl_path: Path, mode: str = "append") -> int:
        if not DELTA_AVAILABLE:
            logger.warning("Delta Lake not available. Skipping Delta write.")
            return 0
        
        rows: List[Dict] = []
        
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                
                # nodes와 edges를 JSON 문자열로 변환
                nodes_json = json.dumps(r.get("nodes", {}), ensure_ascii=False)
                edges_json = json.dumps(r.get("edges", []), ensure_ascii=False)
                
                rows.append({
                    "session_id":       r.get("session_id", ""),
                    "session_type":     r.get("session_type", ""),
                    "event_uuid":       r.get("event_uuid", ""),
                    "source":           r.get("source", ""),
                    "timestamp":        r.get("timestamp", ""),
                    "date":             r.get("date", ""),
                    "src_ip":           r.get("src_ip", ""),
                    "dest_ip":          r.get("dest_ip", ""),
                    "src_port":         int(r.get("src_port") or 0),
                    "dest_port":        int(r.get("dest_port") or 0),
                    "proto":            r.get("proto", ""),
                    "direction":        r.get("direction", ""),
                    "flow_state":       r.get("flow_state", ""),
                    "pkts_toserver":    int(r.get("pkts_toserver") or 0),
                    "pkts_toclient":    int(r.get("pkts_toclient") or 0),
                    "bytes_toserver":   int(r.get("bytes_toserver") or 0),
                    "bytes_toclient":   int(r.get("bytes_toclient") or 0),
                    "total_bytes":      int(r.get("total_bytes") or 0),
                    "anomaly_score":    int(r.get("anomaly_score") or 0),
                    "has_alert":        bool(r.get("has_alert", False)),
                    "alert_count":      int(r.get("alert_count") or 0),
                    "signature":        r.get("signature", ""),
                    "signature_id":     r.get("signature_id", ""),
                    "category":         r.get("category", ""),
                    "severity":         r.get("severity", "low"),
                    "severity_numeric": int(r.get("severity_numeric") or 4),
                    "misp_category":    r.get("misp_category", ""),
                    "uid":              r.get("uid", ""),
                    "service":          r.get("service", ""),
                    "conn_state":       r.get("conn_state", ""),
                    "orig_bytes":       int(r.get("orig_bytes") or 0),
                    "resp_bytes":       int(r.get("resp_bytes") or 0),
                    "duration":         float(r.get("duration") or 0),
                    "orig_pkts":        int(r.get("orig_pkts") or 0),
                    "resp_pkts":        int(r.get("resp_pkts") or 0),
                    "dns_query":        r.get("dns_query", ""),
                    "dns_qtype":        r.get("dns_qtype", ""),
                    "dns_answers":      r.get("dns_answers", ""),
                    "suspicion_score":  int(r.get("suspicion_score") or 0),
                    "http_method":      r.get("http_method", ""),
                    "http_host":        r.get("http_host", ""),
                    "http_uri":         r.get("http_uri", ""),
                    "http_user_agent":  r.get("http_user_agent", ""),
                    "http_status":      int(r.get("http_status") or 0),
                    "risk_score":       int(r.get("risk_score") or 0),
                    "tactic":           r.get("tactic", ""),
                    "technique":        r.get("technique", ""),
                    "tool":             r.get("tool", ""),
                    "cve":              r.get("cve", ""),
                    "is_malicious":     bool(r.get("is_malicious", False)),
                    "confidence":       int(r.get("confidence") or 0),
                    "summary":          r.get("summary", ""),
                    "mitigation":       r.get("mitigation", ""),
                    "nodes_json":       nodes_json,
                    "edges_json":       edges_json,
                })

        if not rows:
            logger.warning("Delta Lake: 저장할 데이터 없음")
            return 0

        if not DELTA_AVAILABLE or DELTA_SCHEMA is None:
            logger.warning("Delta Lake not available")
            return 0

        table = pa.Table.from_pylist(rows, schema=DELTA_SCHEMA)
        write_deltalake(
            self.delta_path, table,
            mode=mode,
            partition_by=["date", "severity"],
        )
        logger.info(f"Delta Lake 저장 완료 → {self.delta_path} ({len(rows)}건)")
        return len(rows)


# ============================================================
# 3. 통합 파이프라인
# ============================================================

def run_preprocessing(
    base_dir:   str = ".",
    output_dir: str = "./output",
    delta_path: str = "./delta_lake/unified_events",
    delta_mode: str = "append",
) -> Dict[str, Any]:
    """
    CSV → JSONL → Delta Lake
    """
    logger.info("━" * 55)
    logger.info("Step 1/2  CSV → Session-Centric JSONL 변환")
    converter  = MultiSourceConverter(base_dir=base_dir, output_dir=output_dir)
    jsonl_path, source_stats = converter.convert_all()

    # logger.info("━" * 55)
    # logger.info("Step 2/2  Delta Lake 저장")
    # writer     = DeltaLakeWriter(delta_path=delta_path)
    # row_count  = writer.write(jsonl_path, mode=delta_mode)

    return {
        "jsonl_path":     str(jsonl_path),
        "source_stats":   source_stats,
        "total_records":  sum(source_stats.values()),
        "delta_path":     delta_path,
        # "delta_rows":     row_count,
    }

