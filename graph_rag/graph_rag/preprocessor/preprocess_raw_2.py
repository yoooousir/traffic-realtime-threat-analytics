"""
preprocess_raw.py (Session-Centric Version v3)
Suricata + Zeek 로그 → Session-Centric JSONL 변환

겉 틀 구조 (최소화):
  {
    "community_id": str,
    "flow_start":   str,   # timeline 내 최소 ts
    "flow_end":     str,   # timeline 내 최대 ts
    "is_threat":    bool,
    "alert_count":  int,
    "timeline": [
      {
        "source":  "suricata" | "zeek_conn" | "zeek_dns" | "zeek_http" | "zeek_ssl",
        "ts":      str,
        <source별 원본 필드명 그대로>
      }, ...
    ]
  }

필드명 통일 기준 (schema.py 파서 입력 기준):
  - IP:   orig_h / resp_h  (zeek 원본 필드명)
  - Port: orig_p / resp_p
  - 겉 틀에서 중복되는 src_ip/dst_ip/duration 등 제거

매핑 전략:
  1. uid 일치 (정확)
  2. (orig_h, resp_h, resp_p, proto) loose 매핑 (fallback)
  3. 매핑 실패한 dns/http/ssl → 독립 세션으로 출력
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


# ── 소스 파일 정의 ────────────────────────────────────────────────────────────
BASE_DIR = Path("./raw_data")
SOURCE_FILES = {
    "suricata":  BASE_DIR / "eve.json",
    "zeek_conn": BASE_DIR / "conn.log",
    "zeek_dns":  BASE_DIR / "dns.log",
    "zeek_http": BASE_DIR / "http.log",
    "zeek_ssl":  BASE_DIR / "ssl.log",
}


# ── Zeek TSV 파서 ─────────────────────────────────────────────────────────────
def parse_zeek_log(path: Path) -> List[Dict]:
    results, headers = [], []
    if not path.exists():
        logger.warning(f"파일 없음: {path}")
        return results

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                headers = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif headers:
                values = line.split("\t")
                row = dict(zip(headers, values))
                row = {k: (None if v in ("-", "(empty)") else v)
                       for k, v in row.items()}
                results.append(row)

    logger.info(f"  {path.name}: {len(results)}행 로드")
    return results


# ── ts 정규화 ─────────────────────────────────────────────────────────────────
def normalize_ts(ts: Optional[str]) -> str:
    if not ts:
        return ""
    try:
        if ts.replace(".", "").isdigit():
            return datetime.fromtimestamp(
                float(ts), tz=timezone.utc
            ).isoformat()
        return ts
    except Exception:
        return ts


# ── loose key ─────────────────────────────────────────────────────────────────
def make_loose_key(orig_h, resp_h, resp_p, proto) -> str:
    return f"{orig_h}|{resp_h}|{resp_p}|{proto}"


# ── 소스별 타임라인 이벤트 빌더 ───────────────────────────────────────────────
# 필드명은 schema.py 파서 입력 기준 (zeek 원본 필드명) 으로 통일

def build_suricata_event(row: Dict) -> Dict:
    """schema.py from_suricata_flow() 입력 기준"""
    alert = row.get("alert", {})
    return {
        "source":       "suricata",
        "ts":           normalize_ts(row.get("timestamp")),
        "event_type":   row.get("event_type"),
        # IP/Port: schema가 src_ip/dest_ip로 읽음 (suricata는 원본 유지)
        "src_ip":       row.get("src_ip"),
        "dest_ip":      row.get("dest_ip"),
        "src_port":     row.get("src_port"),
        "dest_port":    row.get("dest_port"),
        "proto":        row.get("proto"),
        "community_id": row.get("community_id"),
        # flow 통계
        "flow_state":     row.get("flow", {}).get("state"),
        "flow_reason":    row.get("flow", {}).get("reason"),
        "pkts_toserver":  row.get("flow", {}).get("pkts_toserver"),
        "pkts_toclient":  row.get("flow", {}).get("pkts_toclient"),
        "bytes_toserver": row.get("flow", {}).get("bytes_toserver"),
        "bytes_toclient": row.get("flow", {}).get("bytes_toclient"),
        # alert
        "signature":    alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "category":     alert.get("category"),
        "severity":     alert.get("severity"),
    }


def build_zeek_conn_event(row: Dict) -> Dict:
    """schema.py from_zeek_conn() 입력 기준 (zeek 원본 필드명 유지)"""
    return {
        "source":       "zeek_conn",
        "ts":           normalize_ts(row.get("ts")),
        "uid":          row.get("uid"),
        "community_id": row.get("community_id"),
        # IP/Port: zeek 원본 필드명
        "orig_h":   row.get("id.orig_h"),
        "orig_p":   row.get("id.orig_p"),
        "resp_h":   row.get("id.resp_h"),
        "resp_p":   row.get("id.resp_p"),
        "proto":    row.get("proto"),
        "service":  row.get("service"),
        # 플로우 통계
        "duration":   row.get("duration"),
        "orig_bytes": row.get("orig_bytes"),
        "resp_bytes": row.get("resp_bytes"),
        "orig_pkts":  row.get("orig_pkts"),
        "resp_pkts":  row.get("resp_pkts"),
        "conn_state": row.get("conn_state"),
    }


def build_zeek_dns_event(row: Dict) -> Dict:
    """schema.py from_zeek_dns() 입력 기준"""
    return {
        "source":  "zeek_dns",
        "ts":      normalize_ts(row.get("ts")),
        "uid":     row.get("uid"),
        "orig_h":  row.get("id.orig_h"),
        "orig_p":  row.get("id.orig_p"),
        "resp_h":  row.get("id.resp_h"),
        "resp_p":  row.get("id.resp_p"),
        "proto":   row.get("proto"),
        "query":   row.get("query"),
        "qtype_name":  row.get("qtype_name"),
        "rcode_name":  row.get("rcode_name"),
        "answers": row.get("answers"),
    }


def build_zeek_http_event(row: Dict) -> Dict:
    """schema.py from_zeek_http() 입력 기준"""
    return {
        "source":      "zeek_http",
        "ts":          normalize_ts(row.get("ts")),
        "uid":         row.get("uid"),
        "orig_h":      row.get("id.orig_h"),
        "orig_p":      row.get("id.orig_p"),
        "resp_h":      row.get("id.resp_h"),
        "resp_p":      row.get("id.resp_p"),
        "proto":       row.get("proto"),
        "method":      row.get("method"),
        "host":        row.get("host"),
        "uri":         row.get("uri"),
        "user_agent":  row.get("user_agent"),
        "status_code": row.get("status_code"),
        "resp_mime_types": row.get("resp_mime_types"),
    }


def build_zeek_ssl_event(row: Dict) -> Dict:
    """schema.py (zeek_ssl 파서 입력 기준)"""
    return {
        "source":      "zeek_ssl",
        "ts":          normalize_ts(row.get("ts")),
        "uid":         row.get("uid"),
        "orig_h":      row.get("id.orig_h"),
        "orig_p":      row.get("id.orig_p"),
        "resp_h":      row.get("id.resp_h"),
        "resp_p":      row.get("id.resp_p"),
        "proto":       row.get("proto"),
        "version":     row.get("version"),
        "cipher":      row.get("cipher"),
        "server_name": row.get("server_name"),
        "established": row.get("established"),
        "validation_status": row.get("validation_status"),
    }


# ── 메인 클래스 ───────────────────────────────────────────────────────────────
class MergeRaw:

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # community_id → [suricata events]
        self.alert_map: Dict[str, List[Dict]] = {}

        # uid → events  /  loose_key → events
        self.dns_map_uid:    Dict[str, List[Dict]] = {}
        self.dns_map_loose:  Dict[str, List[Dict]] = {}
        self.http_map_uid:   Dict[str, List[Dict]] = {}
        self.http_map_loose: Dict[str, List[Dict]] = {}
        self.ssl_map_uid:    Dict[str, List[Dict]] = {}
        self.ssl_map_loose:  Dict[str, List[Dict]] = {}

        # 독립 세션 출력용 원본 보관 + 매핑 추적
        self._all_dns_rows:  List[Dict] = []
        self._all_http_rows: List[Dict] = []
        self._all_ssl_rows:  List[Dict] = []
        self._matched_uids:  set = set()

    # ── 로드 ──────────────────────────────────────────────────────────────────
    def load_suricata(self, path: Path):
        if not path.exists():
            logger.warning(f"eve.json 없음: {path}")
            return
        logger.info("Loading suricata eve.json ...")
        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cid = row.get("community_id", "")
                if not cid:
                    continue
                self.alert_map.setdefault(cid, []).append(
                    build_suricata_event(row)
                )
                count += 1
        logger.info(f"  suricata: {count}개 / {len(self.alert_map)}개 community_id")

    def _load_layer7(self, path: Path, source: str,
                     uid_map: Dict, loose_map: Dict,
                     all_rows: List, builder):
        logger.info(f"Loading {source} ...")
        rows = parse_zeek_log(path)
        all_rows.extend(rows)
        for row in rows:
            uid  = row.get("uid")
            lkey = make_loose_key(
                row.get("id.orig_h"), row.get("id.resp_h"),
                row.get("id.resp_p"), row.get("proto")
            )
            event = builder(row)
            if uid:
                uid_map.setdefault(uid, []).append(event)
            loose_map.setdefault(lkey, []).append(event)
        logger.info(f"  {source}: uid={len(uid_map)} / loose={len(loose_map)}")

    def load_all(self):
        self.load_suricata(SOURCE_FILES["suricata"])
        self._load_layer7(SOURCE_FILES["zeek_dns"],  "zeek_dns",
                          self.dns_map_uid,  self.dns_map_loose,
                          self._all_dns_rows,  build_zeek_dns_event)
        self._load_layer7(SOURCE_FILES["zeek_http"], "zeek_http",
                          self.http_map_uid, self.http_map_loose,
                          self._all_http_rows, build_zeek_http_event)
        self._load_layer7(SOURCE_FILES["zeek_ssl"],  "zeek_ssl",
                          self.ssl_map_uid,  self.ssl_map_loose,
                          self._all_ssl_rows,  build_zeek_ssl_event)

    # ── uid → loose 매핑 ──────────────────────────────────────────────────────
    def _fetch_events(self, uid: str, loose_key: str,
                      uid_map: Dict, loose_map: Dict) -> List[Dict]:
        if uid and uid in uid_map:
            for ev in uid_map[uid]:
                if ev.get("uid"):
                    self._matched_uids.add(ev["uid"])
            return uid_map[uid]
        if loose_key in loose_map:
            for ev in loose_map[loose_key]:
                if ev.get("uid"):
                    self._matched_uids.add(ev["uid"])
            return loose_map[loose_key]
        return []

    # ── 세션 병합 ─────────────────────────────────────────────────────────────
    def merge_session(self, conn_row: Dict) -> Dict:
        cid  = conn_row.get("community_id") or ""
        uid  = conn_row.get("uid") or ""
        lkey = make_loose_key(
            conn_row.get("id.orig_h"), conn_row.get("id.resp_h"),
            conn_row.get("id.resp_p"), conn_row.get("proto")
        )

        timeline = []

        # suricata 이벤트
        timeline += self.alert_map.get(cid, [])

        # zeek_conn 이벤트
        timeline.append(build_zeek_conn_event(conn_row))

        # layer7 이벤트 (uid → loose fallback)
        for uid_map, loose_map in [
            (self.dns_map_uid,  self.dns_map_loose),
            (self.http_map_uid, self.http_map_loose),
            (self.ssl_map_uid,  self.ssl_map_loose),
        ]:
            timeline += self._fetch_events(uid, lkey, uid_map, loose_map)

        # ts 정렬
        timeline.sort(key=lambda x: x.get("ts") or "9999")

        ts_list    = [e["ts"] for e in timeline if e.get("ts")]
        flow_start = min(ts_list) if ts_list else ""
        flow_end   = max(ts_list) if ts_list else ""

        alerts      = [e for e in timeline if e["source"] == "suricata"]
        is_threat   = len(alerts) > 0
        threat_level = min(
            (a["severity"] for a in alerts if a.get("severity") is not None),
            default=None
        )

        return {
            "community_id": cid,
            "flow_start":   flow_start,
            "flow_end":     flow_end,
            "is_threat":    is_threat,
            "threat_level": threat_level,
            "alert_count":  len(alerts),
            "timeline":     timeline,
        }

    # ── 미매핑 독립 세션 ──────────────────────────────────────────────────────
    def _orphan_sessions(self, rows: List[Dict], builder) -> List[Dict]:
        sessions = []
        for row in rows:
            uid = row.get("uid") or ""
            if uid and uid in self._matched_uids:
                continue
            event = builder(row)
            ts = event.get("ts", "")
            sessions.append({
                "community_id": None,
                "flow_start":   ts,
                "flow_end":     ts,
                "is_threat":    False,
                "threat_level": None,
                "alert_count":  0,
                "timeline":     [event],
            })
        return sessions

    # ── 전체 파이프라인 ───────────────────────────────────────────────────────
    def run(self, print_sample: bool = True) -> Path:
        self.load_all()

        logger.info("Loading zeek conn.log ...")
        conn_rows = parse_zeek_log(SOURCE_FILES["zeek_conn"])
        logger.info(f"  zeek_conn: {len(conn_rows)}행")

        output_path = self.output_dir / "unified_events.jsonl"
        count, orphan_count = 0, 0
        sample_printed = False

        with open(output_path, "w", encoding="utf-8") as out_f:
            for conn_row in conn_rows:
                session = self.merge_session(conn_row)
                out_f.write(json.dumps(session, ensure_ascii=False) + "\n")
                count += 1

                if print_sample and not sample_printed and len(session["timeline"]) > 1:
                    print("\n" + "=" * 65)
                    print("▶ unified_events.jsonl 샘플 (멀티소스 세션)")
                    print("=" * 65)
                    print(json.dumps(session, ensure_ascii=False, indent=2))
                    print("=" * 65 + "\n")
                    sample_printed = True

            # 미매핑 독립 세션
            for builder, rows in [
                (build_zeek_dns_event,  self._all_dns_rows),
                (build_zeek_http_event, self._all_http_rows),
                (build_zeek_ssl_event,  self._all_ssl_rows),
            ]:
                orphans = self._orphan_sessions(rows, builder)
                for s in orphans:
                    out_f.write(json.dumps(s, ensure_ascii=False) + "\n")
                    orphan_count += 1

        logger.info(f"완료: conn기반 {count}개 + orphan {orphan_count}개 "
                    f"= 총 {count + orphan_count}개 세션 → {output_path}")
        return output_path


if __name__ == "__main__":
    merger = MergeRaw(output_dir="./output")
    merger.run(print_sample=True)