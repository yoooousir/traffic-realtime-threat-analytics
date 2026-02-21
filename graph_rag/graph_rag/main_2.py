"""
RAG 모듈 (Session-Centric Version)
- Session 정보 + Flow 통계 포함
- Groq LLM 호출 (llama-3.3-70b-versatile)
- JSON 파싱 및 구조화
- v2: 할루시네이션 방지 + 보안 도메인 기반 프롬프트 강화
"""

import json
import logging
from typing import Dict, Any

from groq import Groq

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

SEVERITY_LABEL = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}

# MITRE ATT&CK 단계 (LLM 참조용 - 근거 없이 추론 금지)
MITRE_STAGES = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

# ============================================================
# 1. 프롬프트 템플릿 (Session-Centric, 할루시네이션 방지)
# ============================================================

def build_prompt(
    packet: Dict[str, Any],
    graph_context: Dict[str, Any],
    ip_history: Dict[str, Any],
) -> str:
    severity_label = SEVERITY_LABEL.get(packet.get("severity_numeric", 4), "Unknown")
    source = packet.get("source", "unknown")
    session_type = packet.get("session_type", source)
    is_new_ip = not ip_history.get("known", False)

    # ── Session 정보 ──
    session_info = f"""[Session 정보]
  Session ID   : {packet.get('session_id', 'N/A')}
  Session Type : {session_type}
  Has Alert    : {'예' if packet.get('has_alert') else '아니오'}"""

    if packet.get('has_alert'):
        session_info += f"\n  Alert Count  : {packet.get('alert_count', 0)}개"

    # ── Flow 통계 ──
    flow_stats = ""
    if source == "suricata_flow":
        flow_stats = f"""
[Flow 통계]
  Flow State    : {packet.get('flow_state', 'N/A')}
  Total Bytes   : {packet.get('total_bytes', 0):,} bytes
  Packets       : ↑{packet.get('pkts_toserver', 0)} / ↓{packet.get('pkts_toclient', 0)}
  Anomaly Score : {packet.get('anomaly_score', 0)}/100"""

    # ── 소스별 추가 컨텍스트 ──
    extra = ""
    if source == "zeek_conn":
        extra = f"""
[Zeek Connection 정보]
  프로토콜      : {packet.get('proto', 'N/A')}
  연결 상태     : {packet.get('conn_state', 'N/A')}
  송신/수신     : {packet.get('orig_bytes', 0):,} / {packet.get('resp_bytes', 0):,} bytes
  Anomaly Score : {packet.get('anomaly_score', 0)}/100"""
    elif source == "zeek_dns":
        extra = f"""
[Zeek DNS 정보]
  질의 도메인   : {packet.get('dns_query', 'N/A')}
  질의 타입     : {packet.get('dns_qtype', 'N/A')}
  응답 값       : {packet.get('dns_answers', 'N/A')}
  Suspicion Score: {packet.get('suspicion_score', 0)}/100"""
    elif source == "zeek_http":
        extra = f"""
[Zeek HTTP 정보]
  메서드        : {packet.get('http_method', 'N/A')}
  호스트        : {packet.get('http_host', 'N/A')}
  URI           : {packet.get('http_uri', 'N/A')}
  User-Agent    : {str(packet.get('http_user_agent', 'N/A'))[:80]}
  응답 코드     : {packet.get('http_status', 'N/A')}
  Risk Score    : {packet.get('risk_score', 0)}/100"""

    # ── 그래프 탐색 결과 ──
    # Alert 목록 (없으면 명시적으로 "없음" 표기)
    if graph_context.get("alerts"):
        alerts_lines = []
        for a in graph_context["alerts"][:10]:
            alerts_lines.append(
                f"  - [{a.get('severity','?')}] {a.get('signature','N/A')} "
                f"| 카테고리: {a.get('category','N/A')} "
                f"| 시간: {a.get('timestamp', 'N/A')}"
            )
        alerts_text = "\n".join(alerts_lines)
        if len(graph_context["alerts"]) > 10:
            alerts_text += f"\n  ... 외 {len(graph_context['alerts']) - 10}건"
    else:
        alerts_text = "  [데이터 없음 - Alert 기반 추론 금지]"

    # 타겟 IP
    if graph_context.get("targeted_ips"):
        targets_text = "\n".join(
            f"  - {t['dest_ip']} (공격 횟수: {t['attack_count']}, "
            f"최고 위험도: {t['min_severity']})"
            for t in graph_context["targeted_ips"]
        )
    else:
        targets_text = "  [데이터 없음]"

    # 연관 공격자
    if graph_context.get("related_attackers"):
        related_text = "\n".join(
            f"  - {r['related_ip']} (공유 Alert 수: {r['shared_alerts']})"
            for r in graph_context["related_attackers"]
        )
    else:
        related_text = "  [데이터 없음 - 연관 공격자 추론 금지]"

    # DNS
    dns_text = ""
    if graph_context.get("dns_queries"):
        dns_list = "\n".join(f"  - {d}" for d in graph_context["dns_queries"][:10])
        if len(graph_context["dns_queries"]) > 10:
            dns_list += f"\n  ... 외 {len(graph_context['dns_queries']) - 10}개"
        dns_text = f"\n[DNS 질의 도메인]\n{dns_list}"

    # HTTP URL
    url_text = ""
    if graph_context.get("http_urls"):
        url_list = "\n".join(f"  - {u}" for u in graph_context["http_urls"][:10])
        if len(graph_context["http_urls"]) > 10:
            url_list += f"\n  ... 외 {len(graph_context['http_urls']) - 10}개"
        url_text = f"\n[HTTP 접근 URL]\n{url_list}"

    # IP 이력
    if ip_history.get("known"):
        history_text = (
            f"  - 누적 Alert 수: {ip_history['total_alerts']}\n"
            f"  - 최고 위험도: {ip_history['highest_severity']}\n"
            f"  - 위협 카테고리: {', '.join(ip_history.get('categories', [])) or '[분류 없음]'}"
        )
    else:
        history_text = "  - 신규 IP (그래프에 이력 없음) - 과거 행위 추론 금지"

    # MITRE 단계 목록 (참조용)
    mitre_ref = ", ".join(MITRE_STAGES)

    prompt = f"""당신은 네트워크 보안 관제 전문가입니다.
아래 제공된 데이터만을 근거로 분석하세요.

## 핵심 규칙 (반드시 준수)
1. 제공된 데이터에 없는 정보는 절대 추론하거나 생성하지 마세요.
2. "[데이터 없음]"으로 표시된 항목은 null 또는 빈 배열로 처리하세요.
3. MITRE ATT&CK 단계는 반드시 아래 목록에서만 선택하세요: {mitre_ref}
4. 시그니처, IP, 카테고리 등 고유값은 반드시 제공된 값 그대로 사용하세요.
5. 대응 방안은 탐지된 공격 유형에 맞는 실제 보안 조치만 작성하세요 (일반론 금지).
6. is_new_ip는 반드시 {str(is_new_ip).lower()} 로 고정하세요 (변경 금지).

=== 현재 이벤트 정보 ===
{session_info}
출발지 IP  : {packet.get('src_ip', 'N/A')}
목적지 IP  : {packet.get('dest_ip', 'N/A')}
위험도     : {severity_label} (level {packet.get('severity_numeric', 'N/A')})
카테고리   : {packet.get('category', 'N/A')}
시그니처   : {packet.get('signature', 'N/A')}
타임스탬프 : {packet.get('timestamp', 'N/A')}
{flow_stats}
{extra}

=== 그래프 분석 결과 (Neo4j Session Graph) ===
[탐지된 공격 Alert]
{alerts_text}

[공격 타겟 IP]
{targets_text}

[연관 공격자 IP]
{related_text}
{dns_text}{url_text}

[출발지 IP 과거 이력]
{history_text}

=== 응답 형식 ===
아래 JSON만 출력하세요. 마크다운, 코드블록, 설명 텍스트 절대 금지.

{{
  "attack_summary": "위 데이터에 있는 시그니처·카테고리·Flow 수치를 직접 인용하여 공격 행위를 1~2문장으로 기술",
  "severity_reason": "제공된 Alert 개수·Anomaly Score·카테고리를 근거로 위험도 판단 이유 기술 (수치 직접 인용)",
  "attack_stage": "MITRE ATT&CK 단계 1개 (위 목록에서만 선택, 근거 없으면 null)",
  "predicted_next": "현재 단계 이후 MITRE ATT&CK 상 다음 단계 (위 목록에서만 선택, 근거 없으면 null)",
  "related_threat": "연관 공격자 데이터가 있을 경우에만 기술, 없으면 null",
  "mitigation": ["탐지된 공격 유형({packet.get('category', 'N/A')})에 특화된 대응 방안 1", "대응 방안 2", "대응 방안 3"],
  "is_new_ip": {str(is_new_ip).lower()},
  "session_analysis": "Session Alert 연계 및 Flow 패턴을 제공된 수치 기반으로 기술 (데이터 없으면 '분석 가능한 Session 데이터 없음')"
}}""".strip()

    return prompt


# ============================================================
# 2. Groq LLM 호출
# ============================================================

class RAGExecutor:
    """
    Neo4j Session-Centric 컨텍스트 → Groq API → 구조화 결과
    """

    DEFAULT_MODEL = "llama-3.3-70b-versatile"

    def __init__(self, api_key: str, model: str = None):
        self.client = Groq(api_key=api_key)
        self.model  = model or self.DEFAULT_MODEL

    def run(
        self,
        packet: Dict[str, Any],
        graph_context: Dict[str, Any],
        ip_history: Dict[str, Any],
        max_tokens: int = 1536,
    ) -> Dict[str, Any]:
        prompt = build_prompt(packet, graph_context, ip_history)
        logger.debug(f"Prompt length: {len(prompt)} chars")

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=0.0,       # 재현성 최대화, 할루시네이션 억제
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity analyst specializing in "
                            "Session-based network threat analysis using real observed data. "
                            "STRICT RULES: "
                            "1) Output valid JSON only — no markdown, no explanation, no code blocks. "
                            "2) Never invent, infer, or hallucinate data not explicitly provided. "
                            "3) If data is missing, use null or empty array — never fabricate values. "
                            "4) MITRE ATT&CK stages must only come from the provided list in the prompt. "
                            "5) is_new_ip must match the value specified in the prompt exactly."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            raw_text = response.choices[0].message.content.strip()
            result   = self._parse_and_validate(raw_text, packet, ip_history)

        except Exception as e:
            logger.error(f"Groq API error: {e}")
            result = self._fallback_result(str(e))

        return {
            "packet":     packet,
            "xai_result": result,
            "model":      self.model,
        }

    def _parse_and_validate(
        self,
        raw: str,
        packet: Dict[str, Any],
        ip_history: Dict[str, Any],
    ) -> Dict[str, Any]:
        """JSON 파싱 후 핵심 필드 후처리 검증"""
        # 코드블록 제거
        if "```" in raw:
            for part in raw.split("```"):
                part = part.strip().lstrip("json").strip()
                if part.startswith("{"):
                    raw = part
                    break

        try:
            result = json.loads(raw.strip())
        except json.JSONDecodeError as e:
            logger.warning(f"JSON 파싱 실패: {e} | raw[:300]: {raw[:300]}")
            return {"raw_response": raw, "parse_error": str(e)}

        # ── 후처리 검증: 하드코딩 값 강제 교정 ──
        is_new_ip = not ip_history.get("known", False)
        if result.get("is_new_ip") != is_new_ip:
            logger.warning(
                f"is_new_ip 불일치 교정: LLM={result.get('is_new_ip')} → 실제={is_new_ip}"
            )
            result["is_new_ip"] = is_new_ip

        # MITRE 단계 유효성 검증
        for field in ("attack_stage", "predicted_next"):
            val = result.get(field)
            if val and val not in MITRE_STAGES:
                logger.warning(f"{field} 유효하지 않은 MITRE 단계: '{val}' → null 처리")
                result[field] = None

        # mitigation이 리스트인지 확인
        if not isinstance(result.get("mitigation"), list):
            result["mitigation"] = ["수동 검토 필요"]

        return result

    def _fallback_result(self, error: str) -> Dict[str, Any]:
        # return {
        #     "attack_summary":   f"분석 실패: {error}",
        #     "severity_reason":  "API 오류로 인한 분석 불가",
        #     "attack_stage":     None,
        #     "predicted_next":   None,
        #     "related_threat":   None,
        #     "mitigation":       ["수동 검토 필요"],
        #     "is_new_ip":        None,
        #     "session_analysis": "분석 불가",
        #     "parse_error":      error,
        # }
        return {
            "attack_summary":   f"분석 실패: {error}"
        }