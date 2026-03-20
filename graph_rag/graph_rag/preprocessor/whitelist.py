"""
whitelist.py
화이트리스트 IP 목록 + 세션 의심도 스코어링 규칙

사용처: preprocess.py 의 MergeRaw.run() 에서
  1. src_ip 가 화이트리스트에 있으면 세션 통과 (필터링)
  2. 화이트리스트에 없더라도 suspicion_score < SUSPICION_THRESHOLD 이면 통과
"""

from typing import Dict, List

# ── 화이트리스트 IP ───────────────────────────────────────────────────────────
# 와일드카드(*) 미지원 — 정확한 IP 또는 WHITELIST_CIDRS 사용
WHITELIST_IPS: set[str] = {
    # ── 내부 인프라 (단일 IP) ────────────────────────────
    "10.0.0.1",       # 게이트웨이
    "10.0.0.2",       # DNS 서버
    "192.168.0.1",    # 내부 라우터
    "192.168.0.10",   # 모니터링 서버
    # 추가 필요 시 여기에 IP 문자열로 등록
}

# CIDR 대역으로 관리 (ipaddress 모듈 사용)
WHITELIST_CIDRS: list[str] = [
    "10.0.2.0/24",
    # "172.16.0.0/12",
    # "192.168.0.0/16",
]

# suspicion_score 기준 — 이 값 미만이면 unified에서 제외
# classtype_score 최소 단위가 10점이므로
#   30  = priority_1 classtype 하나만 있어도 포함 (권장)
#   40  = priority_1 + severity 중간 이상이어야 포함 (보수적)
#   20  = priority_2 classtype도 포함 (느슨하게)
SUSPICION_THRESHOLD = 30


# ── CIDR 매칭 헬퍼 ────────────────────────────────────────────────────────────
def _in_whitelist(ip: str | None) -> bool:
    """
    IP가 WHITELIST_IPS 또는 WHITELIST_CIDRS 에 속하면 True.
    ip가 None이거나 파싱 불가면 False.
    """
    if not ip:
        return False
    if ip in WHITELIST_IPS:
        return True
    if WHITELIST_CIDRS:
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in ipaddress.ip_network(cidr, strict=False)
                       for cidr in WHITELIST_CIDRS)
        except ValueError:
            return False
    return False


def is_whitelisted_session(session: Dict) -> bool:
    """
    세션의 src_ip 가 화이트리스트에 있으면 True.
    timeline에서 zeek_conn → suricata 순으로 IP 추출.
    """
    for ev in session.get("timeline", []):
        if ev.get("source") == "zeek_conn":
            if _in_whitelist(ev.get("orig_h")):
                return True
        elif ev.get("source") == "suricata":
            if _in_whitelist(ev.get("src_ip")):
                return True
    return False


# ── 스코어링 함수 ─────────────────────────────────────────────────────────────

def classtype_score(classtype: str) -> int:
    priority_1 = {"web-application-attack", "trojan-activity", "command-and-control"}
    priority_2 = {"bad-unknown", "misc-attack"}
    priority_3 = {"not-suspicious", "unknown", "network-scan"}

    if classtype in priority_1:
        return 30
    elif classtype in priority_2:
        return 20
    elif classtype in priority_3:
        return 10
    return 0


def severity_score(severity: int) -> int:
    if severity == 1:
        return 30
    elif severity == 2:
        return 20
    elif severity == 3:
        return 10
    return 0


def repeat_score(repeat_count_short_window: int) -> int:
    if repeat_count_short_window >= 5:
        return 20
    elif repeat_count_short_window >= 3:
        return 10
    return 0


def calc_suspicion_score(highest_priority_classtype: str,
                         highest_risk_severity: int,
                         repeat_count_short_window: int) -> int:
    return (
        classtype_score(highest_priority_classtype)
        + severity_score(highest_risk_severity)
        + repeat_score(repeat_count_short_window)
    )


# ── 세션에서 스코어 입력값 집계 ───────────────────────────────────────────────

# Suricata alert.category → classtype 정규화 맵
_CATEGORY_TO_CLASSTYPE: Dict[str, str] = {
    "Web Application Attack":                 "web-application-attack",
    "A Network Trojan was detected":          "trojan-activity",
    "Misc Attack":                            "misc-attack",
    "Potentially Bad Traffic":                "bad-unknown",
    "Detection of a Network Scan":            "network-scan",
    "Not Suspicious Traffic":                 "not-suspicious",
    "Attempted Administrator Privilege Gain": "misc-attack",
    "Attempted User Privilege Gain":          "misc-attack",
    "Generic Protocol Command Decode":        "bad-unknown",
    "Unknown Traffic":                        "unknown",
}

def _category_to_classtype(category: str | None) -> str:
    if not category:
        return "unknown"
    return _CATEGORY_TO_CLASSTYPE.get(category, "unknown")


def extract_score_inputs(session: Dict) -> Dict:
    """
    session(merge_session 결과)의 timeline에서 스코어 계산에 필요한 3개 값 추출.

    반환:
      {
        "highest_priority_classtype": str,   # 가장 위험한 classtype
        "highest_risk_severity":      int,   # 가장 낮은 severity 숫자 (1=critical)
        "repeat_count_short_window":  int,   # suricata alert 발생 건수
      }
    """
    classtypes: List[str] = []
    severities: List[int] = []
    alert_count = 0

    for ev in session.get("timeline", []):
        if ev.get("source") != "suricata":
            continue
        if not ev.get("signature"):
            continue

        alert_count += 1

        ct = _category_to_classtype(ev.get("category"))
        classtypes.append(ct)

        sev = ev.get("severity")
        if sev is not None:
            try:
                severities.append(int(sev))
            except (ValueError, TypeError):
                pass

    _CLASSTYPE_RANK = {
        "web-application-attack": 3, "trojan-activity": 3, "command-and-control": 3,
        "bad-unknown": 2,            "misc-attack": 2,
        "not-suspicious": 1,         "unknown": 1,          "network-scan": 1,
    }
    highest_ct = max(
        classtypes,
        key=lambda c: _CLASSTYPE_RANK.get(c, 0),
        default="unknown",
    )
    highest_sev = min(severities) if severities else 4

    return {
        "highest_priority_classtype": highest_ct,
        "highest_risk_severity":      highest_sev,
        "repeat_count_short_window":  alert_count,
    }


def should_include(session: Dict) -> bool:
    """
    True  → unified_events.parquet 에 포함
    False → 필터링 (저장 안 함)

    판단 순서:
      1. 화이트리스트 IP 포함 → 제외
      2. suspicion_score < SUSPICION_THRESHOLD → 제외
      3. 그 외 → 포함
    """
    if is_whitelisted_session(session):
        return False

    inputs = extract_score_inputs(session)
    score = calc_suspicion_score(
        inputs["highest_priority_classtype"],
        inputs["highest_risk_severity"],
        inputs["repeat_count_short_window"],
    )
    return score >= SUSPICION_THRESHOLD