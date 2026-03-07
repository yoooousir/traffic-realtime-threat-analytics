"""
preprocess_raw.py (Session-Centric Version)
Suricata + Zeek 로그를 통합하여 Session-Centric JSONL로 변환

구조:
  "community_id": ""
      ├── "flow_start": ""
      ├── "flow_end": ""
      └── "timeline" : [
          ├── ts, source(suricata, zeek_conn, zeek_dns, zeek_http 중 1), 해당 source의 각종 필드
          └── ts, source(suricata, zeek_conn, zeek_dns, zeek_http 중 1), 해당 source의 각종 필드
          ]

최종 출력: JSONL
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
}


# ── Zeek TSV 파서 ─────────────────────────────────────────────────────────────
def parse_zeek_log(path: Path) -> List[Dict]:
    """
    Zeek TSV 로그 파싱
    #fields 헤더 기준으로 컬럼명 추출 후 딕셔너리 리스트 반환
    Zeek 결측값 "-", "(empty)" → None 처리
    """
    results = []
    headers = []
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
    """
    다양한 ts 포맷을 ISO 형식으로 통일
    Suricata: "2026-03-02T08:20:48.962577+0000"
    Zeek:     "1740889248.962577" (Unix epoch)
    """
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


# ── 메인 클래스 ───────────────────────────────────────────────────────────────
class MergeRaw:
    """
    Suricata + Zeek(conn/dns/http) → Session-Centric JSONL 변환기

    메모리 선로드 구조:
      alert_map : community_id → [suricata 이벤트]
      dns_map   : uid          → [zeek dns 이벤트]
      http_map  : uid          → [zeek http 이벤트]
    """

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.alert_map: Dict[str, List[Dict]] = {}
        self.dns_map:   Dict[str, List[Dict]] = {}
        self.http_map:  Dict[str, List[Dict]] = {}

    # ── 1. Suricata 로드 ──────────────────────────────────────────────────────
    def load_suricata(self, path: Path):
        """NDJSON → community_id 기준 alert_map 구성"""
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

                community_id = row.get("community_id", "")
                if not community_id:
                    continue

                alert_info = row.get("alert", {})
                ts = normalize_ts(row.get("timestamp", ""))

                self.alert_map.setdefault(community_id, []).append({
                    "source":       "suricata",
                    "ts":           ts,
                    "event_type":   row.get("event_type", ""),
                    "src_ip":       row.get("src_ip"),
                    "src_port":     row.get("src_port"),
                    "dest_ip":      row.get("dest_ip"),
                    "dest_port":    row.get("dest_port"),
                    "proto":        row.get("proto"),
                    "signature":    alert_info.get("signature"),
                    "signature_id": alert_info.get("signature_id"),
                    "category":     alert_info.get("category"),
                    "severity":     alert_info.get("severity"),
                    "flow":         row.get("flow", {}),
                })
                count += 1

        logger.info(f"  suricata: {count}개 이벤트 / "
                    f"{len(self.alert_map)}개 community_id")

    # ── 2. Zeek DNS 로드 ──────────────────────────────────────────────────────
    def load_zeek_dns(self, path: Path):
        """Zeek dns.log → uid 기준 dns_map 구성"""
        logger.info("Loading zeek dns.log ...")
        rows = parse_zeek_log(path)
        for row in rows:
            uid = row.get("uid")
            if not uid:
                continue
            self.dns_map.setdefault(uid, []).append({
                "source":  "zeek_dns",
                "ts":      normalize_ts(row.get("ts")),
                "query":   row.get("query"),
                "answers": row.get("answers"),
                "qtype":   row.get("qtype_name"),
                "rcode":   row.get("rcode_name"),
            })
        logger.info(f"  dns_map: {len(self.dns_map)}개 uid")

    # ── 3. Zeek HTTP 로드 ─────────────────────────────────────────────────────
    def load_zeek_http(self, path: Path):
        """Zeek http.log → uid 기준 http_map 구성"""
        logger.info("Loading zeek http.log ...")
        rows = parse_zeek_log(path)
        for row in rows:
            uid = row.get("uid")
            if not uid:
                continue
            self.http_map.setdefault(uid, []).append({
                "source":      "zeek_http",
                "ts":          normalize_ts(row.get("ts")),
                "method":      row.get("method"),
                "host":        row.get("host"),
                "uri":         row.get("uri"),
                "status_code": row.get("status_code"),
                "resp_mime":   row.get("resp_mime_types"),
            })
        logger.info(f"  http_map: {len(self.http_map)}개 uid")

    # ── 4. 타임라인 생성 ──────────────────────────────────────────────────────
    def build_timeline(self, community_id: str, uid: str) -> List[Dict]:
        """
        community_id → suricata 이벤트
        uid          → dns, http 이벤트
        모두 합쳐서 ts 기준 정렬
        각 이벤트는 source 필드로 구분
        """
        events = []
        events += self.alert_map.get(community_id, [])
        events += self.dns_map.get(uid, [])
        events += self.http_map.get(uid, [])

        # ts 기준 정렬 (ts 없는 경우 맨 뒤로)
        events.sort(key=lambda x: x.get("ts") or "9999")
        return events

    # ── 5. 세션 병합 ──────────────────────────────────────────────────────────
    def merge_session(self, conn_row: Dict) -> Dict:
        """zeek_conn 1행 → community_id 기반 UnifiedSession 생성"""
        community_id = conn_row.get("community_id") or ""
        uid          = conn_row.get("uid") or ""

        zeek_conn_event = {
            "source": "zeek_conn",
            "ts":     normalize_ts(conn_row.get("ts")),
            "uid":    uid,
            "proto":  conn_row.get("proto"),
            "service": conn_row.get("service"),
            "duration": conn_row.get("duration"),
            "orig_bytes": conn_row.get("orig_bytes"),
            "resp_bytes": conn_row.get("resp_bytes"),
            "orig_pkts":  conn_row.get("orig_pkts"),
            "resp_pkts":  conn_row.get("resp_pkts"),
            "conn_state": conn_row.get("conn_state"),
        }

        timeline = self.build_timeline(community_id, uid)
        timeline.append(zeek_conn_event)
        timeline.sort(key=lambda x: x.get("ts") or "9999")

        # flow_start / flow_end: timeline의 ts 최솟값/최댓값
        ts_list    = [e["ts"] for e in timeline if e.get("ts")]
        flow_start = min(ts_list) if ts_list else normalize_ts(conn_row.get("ts"))
        flow_end   = max(ts_list) if ts_list else None

        # 위협 요약
        alerts       = [e for e in timeline if e["source"] == "suricata"]
        is_threat    = len(alerts) > 0
        threat_level = min(
            (a["severity"] for a in alerts if a.get("severity") is not None),
            default=None
        )

        return {
            # ── 세션 식별자 ──
            "community_id": community_id,
            "uid":          uid,
            "flow_start":   flow_start,
            "flow_end":     flow_end,

            # ── 네트워크 5-tuple ──
            "src_ip":   conn_row.get("id.orig_h"),
            "src_port": conn_row.get("id.orig_p"),
            "dst_ip":   conn_row.get("id.resp_h"),
            "dst_port": conn_row.get("id.resp_p"),
            "proto":    conn_row.get("proto"),
            "service":  conn_row.get("service"),

            # ── 플로우 통계 ──
            "duration":   conn_row.get("duration"),
            "orig_bytes": conn_row.get("orig_bytes"),
            "resp_bytes": conn_row.get("resp_bytes"),
            "orig_pkts":  conn_row.get("orig_pkts"),
            "resp_pkts":  conn_row.get("resp_pkts"),
            "conn_state": conn_row.get("conn_state"),

            # ── 위협 요약 ──
            "is_threat":    is_threat,
            "threat_level": threat_level,
            "alert_count":  len(alerts),

            # ── 타임라인 (ts 정렬, source 혼합) ──
            "timeline": timeline,

            # ── 메타 ──
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── 6. 전체 파이프라인 ────────────────────────────────────────────────────
    def run(self, print_sample: bool = True):
        # 선로드
        self.load_suricata(SOURCE_FILES["suricata"])
        self.load_zeek_dns(SOURCE_FILES["zeek_dns"])
        self.load_zeek_http(SOURCE_FILES["zeek_http"])

        # zeek_conn 파싱
        logger.info("Loading zeek conn.log ...")
        conn_rows = parse_zeek_log(SOURCE_FILES["zeek_conn"])
        logger.info(f"  zeek_conn: {len(conn_rows)}행")

        output_path = self.output_dir / "unified_events.jsonl"
        sample_printed = False
        count = 0

        with open(output_path, "w", encoding="utf-8") as out_f:
            for conn_row in conn_rows:
                session = self.merge_session(conn_row)

                # JSONL: 1줄 = 1 session (flow 깨지지 않게)
                out_f.write(json.dumps(session, ensure_ascii=False) + "\n")
                count += 1

                # ── 샘플 1개 출력 (timeline이 있는 첫 번째 세션) ──────────
                if print_sample and not sample_printed and session["timeline"]:
                    print("\n" + "=" * 65)
                    print("community_id 기반 타임라인 통합 결과 샘플")
                    print("=" * 65)
                    print(json.dumps(session, ensure_ascii=False, indent=2))
                    print("=" * 65 + "\n")
                    sample_printed = True

        logger.info(f"완료: {count}개 세션 → {output_path}")


# ── 실행 ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    merger = MergeRaw(output_dir="./output")
    merger.run(print_sample=True)