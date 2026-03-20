"""
preprocess.py (Session-Centric Version v5)
Suricata + Zeek 로그 → Session-Centric JSONL 변환

매핑 전략 (v5 수정):
  1. suricata ↔ conn : community_id 기준 (변경 없음)
  2. conn ↔ dns/http/ssl :
       ① uid 일치 + ts가 conn의 [flow_start, flow_end + MARGIN] 구간 내
       ② uid 없거나 실패 시 → loose key(orig_h|resp_h|resp_p|proto) +
          ts가 conn의 [flow_start, flow_end + MARGIN] 구간 내
       ③ 위 모두 실패 → orphan 독립 세션으로 출력

  [v4 대비 변경점]
  - loose 매핑에 시간 구간 필터 추가 → 동일 4-tuple 다른 세션 오염 방지
  - uid 매핑도 시간 구간 교차 검증 추가 (Zeek uid 재사용 방어)
  - uid가 시간 구간 불일치면 loose fallback 없이 바로 스킵
    (uid가 있다는 건 명확한 식별자이므로 loose 오염 허용 안 함)
  - FLOW_MARGIN_SEC: flow_end 이후 허용 여유 시간 (기본 5초)
    HTTP keep-alive / DNS retransmit 커버용

겉 틀 구조:
  {
    "community_id": str,
    "flow_start":   str,
    "flow_end":     str,
    "is_threat":    bool,
    "threat_level": int | None,
    "alert_count":  int,
    "timeline":     [ { "source": ..., "ts": ..., ... }, ... ]
  }
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# conn의 flow_end 이후 layer7 이벤트를 허용할 여유 시간 (초)
# HTTP keep-alive, DNS retransmit, SSL close_notify 등을 커버
FLOW_MARGIN_SEC = 5.0

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


# ── ts 파싱 / 정규화 ──────────────────────────────────────────────────────────
def normalize_ts(ts: Optional[str]) -> str:
    """Unix epoch 문자열 → ISO 8601. 이미 ISO면 그대로."""
    if not ts:
        return ""
    try:
        if ts.replace(".", "").isdigit():
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        return ts
    except Exception:
        return ts


def parse_ts(ts_str: Optional[str]) -> Optional[datetime]:
    """ISO 8601 문자열 → datetime (UTC 인식). 실패 시 None."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        try:
            return datetime.fromtimestamp(float(ts_str), tz=timezone.utc)
        except Exception:
            return None


# ── loose key ─────────────────────────────────────────────────────────────────
def make_loose_key(orig_h, resp_h, resp_p, proto) -> str:
    return f"{orig_h}|{resp_h}|{resp_p}|{proto}"


# ── 시간 구간 체크 ────────────────────────────────────────────────────────────
def _in_window(
    event_ts: Optional[str],
    flow_start: Optional[datetime],
    flow_end_margin: Optional[datetime],
) -> bool:
    """
    event_ts 가 [flow_start, flow_end + FLOW_MARGIN_SEC] 구간에 속하는지 확인.
    - flow_start / flow_end_margin 이 None 이면 True (정보 없으면 허용)
    - event_ts 파싱 실패 시 True (보수적으로 포함)
    """
    if flow_start is None or flow_end_margin is None:
        return True
    ev_dt = parse_ts(event_ts)
    if ev_dt is None:
        return True
    return flow_start <= ev_dt <= flow_end_margin


# ── conn flow 구간 계산 ───────────────────────────────────────────────────────
def _conn_window(conn_row: Dict) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    conn_row의 ts + duration → [flow_start, flow_end + FLOW_MARGIN_SEC].
    duration 이 없거나 0이면 flow_end = flow_start (순간 연결로 간주).
    """
    ts_str = normalize_ts(conn_row.get("ts"))
    flow_start = parse_ts(ts_str)
    if flow_start is None:
        return None, None

    try:
        dur = float(conn_row.get("duration") or 0)
    except (ValueError, TypeError):
        dur = 0.0

    flow_end = flow_start + timedelta(seconds=dur)
    flow_end_margin = flow_end + timedelta(seconds=FLOW_MARGIN_SEC)
    return flow_start, flow_end_margin


# ── 소스별 타임라인 이벤트 빌더 ───────────────────────────────────────────────

def build_suricata_event(row: Dict) -> Dict:
    alert = row.get("alert", {})
    flow  = row.get("flow", {})
    return {
        "source":         "suricata",
        "ts":             normalize_ts(row.get("timestamp")),
        "event_type":     row.get("event_type"),
        "src_ip":         row.get("src_ip"),
        "dest_ip":        row.get("dest_ip"),
        "src_port":       row.get("src_port"),
        "dest_port":      row.get("dest_port"),
        "proto":          row.get("proto"),
        "community_id":   row.get("community_id"),
        "flow_state":     flow.get("state"),
        "flow_reason":    flow.get("reason"),
        "pkts_toserver":  flow.get("pkts_toserver"),
        "pkts_toclient":  flow.get("pkts_toclient"),
        "bytes_toserver": flow.get("bytes_toserver"),
        "bytes_toclient": flow.get("bytes_toclient"),
        "signature":      alert.get("signature"),
        "signature_id":   alert.get("signature_id"),
        "category":       alert.get("category"),
        "severity":       alert.get("severity"),
    }


def build_zeek_conn_event(row: Dict) -> Dict:
    return {
        "source":       "zeek_conn",
        "ts":           normalize_ts(row.get("ts")),
        "uid":          row.get("uid"),
        "community_id": row.get("community_id"),
        "orig_h":       row.get("id.orig_h"),
        "orig_p":       row.get("id.orig_p"),
        "resp_h":       row.get("id.resp_h"),
        "resp_p":       row.get("id.resp_p"),
        "proto":        row.get("proto"),
        "service":      row.get("service"),
        "duration":     row.get("duration"),
        "orig_bytes":   row.get("orig_bytes"),
        "resp_bytes":   row.get("resp_bytes"),
        "conn_state":   row.get("conn_state"),
        "missed_bytes": row.get("missed_bytes"),
        "history":      row.get("history"),
        "orig_pkts":    row.get("orig_pkts"),
        "resp_pkts":    row.get("resp_pkts"),
    }


def build_zeek_dns_event(row: Dict) -> Dict:
    return {
        "source":     "zeek_dns",
        "ts":         normalize_ts(row.get("ts")),
        "uid":        row.get("uid"),
        "orig_h":     row.get("id.orig_h"),
        "orig_p":     row.get("id.orig_p"),
        "resp_h":     row.get("id.resp_h"),
        "resp_p":     row.get("id.resp_p"),
        "proto":      row.get("proto"),
        "query":      row.get("query"),
        "qtype_name": row.get("qtype_name"),
        "rcode_name": row.get("rcode_name"),
        "answers":    row.get("answers"),
        "rtt":        row.get("rtt"),
    }


def build_zeek_http_event(row: Dict) -> Dict:
    return {
        "source":            "zeek_http",
        "ts":                normalize_ts(row.get("ts")),
        "uid":               row.get("uid"),
        "orig_h":            row.get("id.orig_h"),
        "orig_p":            row.get("id.orig_p"),
        "resp_h":            row.get("id.resp_h"),
        "resp_p":            row.get("id.resp_p"),
        "proto":             row.get("proto"),
        "method":            row.get("method"),
        "host":              row.get("host"),
        "uri":               row.get("uri"),
        "user_agent":        row.get("user_agent"),
        "request_body_len":  row.get("request_body_len"),
        "response_body_len": row.get("response_body_len"),
        "status_code":       row.get("status_code"),
        "status_msg":        row.get("status_msg"),
    }


def build_zeek_ssl_event(row: Dict) -> Dict:
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
        "curve":       row.get("curve"),
        "server_name": row.get("server_name"),
        "ssl_history": row.get("ssl_history"),
        "established": row.get("established"),
        "resumed":     row.get("resumed"),
    }


# ══════════════════════════════════════════════════════════════════════════════
# 메인 클래스
# ══════════════════════════════════════════════════════════════════════════════
class MergeRaw:

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # community_id → [suricata events]
        self.alert_map: Dict[str, List[Dict]] = {}

        # uid → [events]  /  loose_key → [events]
        self.dns_map_uid:    Dict[str, List[Dict]] = {}
        self.dns_map_loose:  Dict[str, List[Dict]] = {}
        self.http_map_uid:   Dict[str, List[Dict]] = {}
        self.http_map_loose: Dict[str, List[Dict]] = {}
        self.ssl_map_uid:    Dict[str, List[Dict]] = {}
        self.ssl_map_loose:  Dict[str, List[Dict]] = {}

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
        logger.info(f"  {source}: uid_keys={len(uid_map)} / loose_keys={len(loose_map)}")

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

    # ── [v5 핵심] 시간 구간 필터 적용 layer7 이벤트 fetch ─────────────────────
    def _fetch_events(
        self,
        uid: str,
        loose_key: str,
        uid_map: Dict,
        loose_map: Dict,
        flow_start: Optional[datetime],
        flow_end_margin: Optional[datetime],
    ) -> List[Dict]:
        """
        매핑 우선순위 및 시간 필터 로직:

        1순위 — uid 매핑:
          - uid_map에 해당 uid가 존재하면 시간 구간 필터 적용
          - 필터 통과한 이벤트 반환
          - uid가 있었지만 시간이 안 맞으면 loose fallback 없이 종료
            → uid는 명확한 식별자이므로 틀렸으면 loose로 오염시키지 않음

        2순위 — loose key 매핑 (v5: 시간 필터 추가):
          - uid가 없거나 uid_map에 없는 경우에만 시도
          - loose_key 일치 + ts가 conn flow 구간 내인 것만 반환
          - 이전(v4): 시간 무관하게 같은 4-tuple 전부 병합 → 오염 발생
          - 이후(v5): flow_start ~ flow_end+margin 구간 필터로 오염 차단
        """
        # ── 1순위: uid 매핑 ──────────────────────────────────────────────────
        if uid and uid in uid_map:
            matched = [
                ev for ev in uid_map[uid]
                if _in_window(ev.get("ts"), flow_start, flow_end_margin)
            ]
            # uid hit 시 — 시간 일치 여부와 무관하게 loose 시도 안 함
            for ev in matched:
                if ev.get("uid"):
                    self._matched_uids.add(ev["uid"])
            if not matched:
                logger.debug(
                    "uid=%s 존재하나 flow 구간 불일치 → 스킵 (start=%s, end=%s)",
                    uid, flow_start, flow_end_margin,
                )
            return matched

        # ── 2순위: loose key 매핑 + 시간 구간 필터 ───────────────────────────
        if loose_key in loose_map:
            matched = [
                ev for ev in loose_map[loose_key]
                if _in_window(ev.get("ts"), flow_start, flow_end_margin)
            ]
            for ev in matched:
                if ev.get("uid"):
                    self._matched_uids.add(ev["uid"])
            return matched

        return []

    # ── 세션 병합 ─────────────────────────────────────────────────────────────
    def merge_session(self, conn_row: Dict) -> Dict:
        cid  = conn_row.get("community_id") or ""
        uid  = conn_row.get("uid") or ""
        lkey = make_loose_key(
            conn_row.get("id.orig_h"), conn_row.get("id.resp_h"),
            conn_row.get("id.resp_p"), conn_row.get("proto")
        )

        # conn의 ts + duration → layer7 시간 필터 기준
        flow_start_dt, flow_end_margin_dt = _conn_window(conn_row)

        timeline: List[Dict] = []

        # ── 1단계: community_id 기준 → suricata 이벤트 병합 ──────────────────
        timeline += self.alert_map.get(cid, [])

        # ── 2단계: zeek_conn 자체 추가 ───────────────────────────────────────
        timeline.append(build_zeek_conn_event(conn_row))

        # ── 3단계: uid + 시간 구간 → dns/http/ssl 병합 (v5) ──────────────────
        for uid_map, loose_map in [
            (self.dns_map_uid,  self.dns_map_loose),
            (self.http_map_uid, self.http_map_loose),
            (self.ssl_map_uid,  self.ssl_map_loose),
        ]:
            timeline += self._fetch_events(
                uid, lkey, uid_map, loose_map,
                flow_start_dt, flow_end_margin_dt,
            )

        # ts 정렬
        timeline.sort(key=lambda x: x.get("ts") or "9999")

        ts_list    = [e["ts"] for e in timeline if e.get("ts")]
        flow_start = min(ts_list) if ts_list else ""
        flow_end   = max(ts_list) if ts_list else ""

        alerts = [e for e in timeline if e["source"] == "suricata"]
        is_threat = len(alerts) > 0
        threat_level = min(
            (a["severity"] for a in alerts if a.get("severity") is not None),
            default=None,
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
        """
        _matched_uids에 등록되지 않은 이벤트 → 독립 orphan 세션으로 출력.
        uid가 없는 이벤트도 orphan으로 처리 (loose 매핑에서도 걸리지 않은 것들).
        """
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
    def run_parquet(self, print_sample: bool = True) -> Path:
        import pandas as pd
        from whitelist import should_include, SUSPICION_THRESHOLD

        self.load_all()

        logger.info("Loading zeek conn.log ...")
        conn_rows = parse_zeek_log(SOURCE_FILES["zeek_conn"])
        logger.info(f"  zeek_conn: {len(conn_rows)}행")

        sessions: List[Dict] = []
        orphan_count = 0
        filtered_count = 0
        sample_printed = False

        for conn_row in conn_rows:
            session = self.merge_session(conn_row)

            # ── 화이트리스트 / 스코어 필터 ───────────────────────────────────
            if not should_include(session):
                filtered_count += 1
                continue

            # timeline은 JSON 문자열로 직렬화하여 Parquet 컬럼에 저장
            session["timeline"] = json.dumps(session["timeline"], ensure_ascii=False)
            sessions.append(session)

            if print_sample and not sample_printed and \
                    len(json.loads(session["timeline"])) > 1:
                print("\n" + "=" * 65)
                print("▶ unified_events 샘플 (멀티소스 세션)")
                print("=" * 65)
                display = dict(session)
                display["timeline"] = json.loads(display["timeline"])
                print(json.dumps(display, ensure_ascii=False, indent=2))
                print("=" * 65 + "\n")
                sample_printed = True

        # 미매핑 독립 세션 — orphan은 alert 없으므로 스코어 필터만 적용
        # (화이트리스트 체크는 should_include 내부에서 동일하게 처리)
        for builder, rows in [
            (build_zeek_dns_event,  self._all_dns_rows),
            (build_zeek_http_event, self._all_http_rows),
            (build_zeek_ssl_event,  self._all_ssl_rows),
        ]:
            for orphan in self._orphan_sessions(rows, builder):
                if not should_include(orphan):
                    filtered_count += 1
                    continue
                orphan["timeline"] = json.dumps(orphan["timeline"], ensure_ascii=False)
                sessions.append(orphan)
                orphan_count += 1

        output_path = self.output_dir / "unified_events.parquet"
        pd.DataFrame(sessions).to_parquet(output_path, index=False)

        total = len(sessions)
        conn_count = total - orphan_count
        logger.info(
            f"완료: conn기반 {conn_count}개 + orphan {orphan_count}개 "
            f"= 총 {total}개 세션 저장 / {filtered_count}개 필터링 "
            f"(임계값 score<{SUSPICION_THRESHOLD} 또는 whitelist IP) "
            f"→ {output_path}"
        )
        return output_path


    def run_jsonl(self, print_sample: bool = True) -> Path:
        from whitelist import should_include, SUSPICION_THRESHOLD

        self.load_all()

        logger.info("Loading zeek conn.log ...")
        conn_rows = parse_zeek_log(SOURCE_FILES["zeek_conn"])
        logger.info(f"  zeek_conn: {len(conn_rows)}행")

        output_path = self.output_dir / "unified_events.jsonl"
        conn_count = 0
        orphan_count = 0
        filtered_count = 0
        sample_printed = False

        with open(output_path, "w", encoding="utf-8") as out_f:
            for conn_row in conn_rows:
                session = self.merge_session(conn_row)

                if not should_include(session):
                    filtered_count += 1
                    continue

                out_f.write(json.dumps(session, ensure_ascii=False) + "\n")
                conn_count += 1

                if print_sample and not sample_printed and len(session["timeline"]) > 1:
                    print("\n" + "=" * 65)
                    print("▶ unified_events.jsonl 샘플 (멀티소스 세션)")
                    print("=" * 65)
                    print(json.dumps(session, ensure_ascii=False, indent=2))
                    print("=" * 65 + "\n")
                    sample_printed = True

            for builder, rows in [
                (build_zeek_dns_event,  self._all_dns_rows),
                (build_zeek_http_event, self._all_http_rows),
                (build_zeek_ssl_event,  self._all_ssl_rows),
            ]:
                for orphan in self._orphan_sessions(rows, builder):
                    if not should_include(orphan):
                        filtered_count += 1
                        continue
                    out_f.write(json.dumps(orphan, ensure_ascii=False) + "\n")
                    orphan_count += 1

        total = conn_count + orphan_count
        logger.info(
            f"완료: conn기반 {conn_count}개 + orphan {orphan_count}개 "
            f"= 총 {total}개 세션 저장 / {filtered_count}개 필터링 "
            f"(임계값 score<{SUSPICION_THRESHOLD} 또는 whitelist IP) "
            f"→ {output_path}"
        )
        return output_path


if __name__ == "__main__":
    merger = MergeRaw(output_dir="./output")
    merger.run_parquet(print_sample=True)