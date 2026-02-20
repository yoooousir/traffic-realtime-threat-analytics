"""
RAG 모듈 (Session-Centric Version)
- Session 정보 + Flow 통계 포함
- Groq LLM 호출 (llama-3.3-70b-versatile)
- JSON 파싱 및 구조화
"""

import json
import logging
from typing import Dict, Any

from groq import Groq

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

SEVERITY_LABEL = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}


# ============================================================
# 1. 프롬프트 템플릿 (Session-Centric)
# ============================================================

def build_prompt(
    packet: Dict[str, Any],
    graph_context: Dict[str, Any],
    ip_history: Dict[str, Any],
) -> str:
    severity_label = SEVERITY_LABEL.get(packet.get("severity_numeric", 4), "Unknown")
    source = packet.get("source", "unknown")
    session_type = packet.get("session_type", source)

    # ── Session 정보 (추가) ──
    session_info = f"""
[Session 정보]
  Session ID   : {packet.get('session_id', 'N/A')}
  Session Type : {session_type}
  Has Alert    : {'예' if packet.get('has_alert') else '아니오'}"""
    
    if packet.get('has_alert'):
        session_info += f"""
  Alert Count  : {packet.get('alert_count', 0)}개"""

    # ── Flow 통계 (Suricata Flow인 경우) ──
    flow_stats = ""
    if source == "suricata_flow":
        flow_stats = f"""
[Flow 통계]
  Flow State    : {packet.get('flow_state', '-')}
  Total Bytes   : {packet.get('total_bytes', 0):,} bytes
  Packets       : ↑{packet.get('pkts_toserver', 0)} / ↓{packet.get('pkts_toclient', 0)}
  Anomaly Score : {packet.get('anomaly_score', 0)}/100"""

    # ── 그래프 탐색 결과 포맷 ──
    alerts_text = "탐지된 Alert 없음"
    if graph_context.get("alerts"):
        lines = []
        for a in graph_context["alerts"]:
            line = (
                f"  - [{a.get('severity','?')}] {a.get('signature','')} "
                f"| 카테고리: {a.get('category','')} "
                f"| 시간: {a.get('timestamp', '-')}"
            )
            lines.append(line)
        alerts_text = "\n".join(lines[:10])  # 최대 10개
        if len(graph_context["alerts"]) > 10:
            alerts_text += f"\n  ... 외 {len(graph_context['alerts']) - 10}건"

    targets_text = "타겟 IP 없음"
    if graph_context.get("targeted_ips"):
        lines = [
            f"  - {t['dest_ip']} (공격 횟수: {t['attack_count']}, "
            f"최고 위험도: {t['min_severity']})"
            for t in graph_context["targeted_ips"]
        ]
        targets_text = "\n".join(lines)

    related_text = "연관 공격자 없음"
    if graph_context.get("related_attackers"):
        lines = [
            f"  - {r['related_ip']} (공유 Alert 수: {r['shared_alerts']})"
            for r in graph_context["related_attackers"]
        ]
        related_text = "\n".join(lines)

    dns_text = ""
    if graph_context.get("dns_queries"):
        dns_text = "\n[DNS 질의 도메인]\n" + "\n".join(
            f"  - {d}" for d in graph_context["dns_queries"][:10]
        )
        if len(graph_context["dns_queries"]) > 10:
            dns_text += f"\n  ... 외 {len(graph_context['dns_queries']) - 10}개"

    url_text = ""
    if graph_context.get("http_urls"):
        url_text = "\n[HTTP 접근 URL]\n" + "\n".join(
            f"  - {u}" for u in graph_context["http_urls"][:10]
        )
        if len(graph_context["http_urls"]) > 10:
            url_text += f"\n  ... 외 {len(graph_context['http_urls']) - 10}개"

    # ── IP 이력 ──
    if ip_history.get("known"):
        history_text = (
            f"  - 누적 Alert 수: {ip_history['total_alerts']}\n"
            f"  - 최고 위험도: {ip_history['highest_severity']}\n"
            f"  - 위협 카테고리: {', '.join(ip_history.get('categories', [])) or '-'}"
        )
    else:
        history_text = "  - 신규 IP (그래프에 이력 없음)"

    # ── 소스별 추가 컨텍스트 ──
    extra = ""
    if source == "zeek_conn":
        extra = f"""
[Zeek Connection 정보]
  프로토콜      : {packet.get('proto','-')}
  연결 상태     : {packet.get('conn_state','-')}
  송신/수신     : {packet.get('orig_bytes',0):,} / {packet.get('resp_bytes',0):,} bytes
  Anomaly Score : {packet.get('anomaly_score', 0)}/100"""
    elif source == "zeek_dns":
        extra = f"""
[Zeek DNS 정보]
  질의 도메인   : {packet.get('dns_query','-')}
  질의 타입     : {packet.get('dns_qtype','-')}
  응답 값       : {packet.get('dns_answers','-')}
  Suspicion Score: {packet.get('suspicion_score', 0)}/100"""
    elif source == "zeek_http":
        extra = f"""
[Zeek HTTP 정보]
  메서드        : {packet.get('http_method','-')}
  호스트        : {packet.get('http_host','-')}
  URI           : {packet.get('http_uri','-')}
  User-Agent    : {packet.get('http_user_agent','-')[:80]}
  응답 코드     : {packet.get('http_status',0)}
  Risk Score    : {packet.get('risk_score', 0)}/100"""

    prompt = f"""당신은 네트워크 보안 관제 전문가입니다.
아래 Session 기반 패킷 정보와 그래프 분석 결과를 바탕으로 공격을 분석하고,
반드시 아래 JSON 형식으로만 응답하세요. JSON 외 다른 텍스트는 절대 포함하지 마세요.

=== 현재 이벤트 정보 ===
{session_info}
출발지 IP  : {packet.get('src_ip','N/A')}
목적지 IP  : {packet.get('dest_ip','N/A')}
위험도     : {severity_label} (level {packet.get('severity_numeric','N/A')})
카테고리   : {packet.get('category','-')}
시그니처   : {packet.get('signature','-')}
타임스탬프 : {packet.get('timestamp','N/A')}
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

=== 응답 형식 (JSON만 출력) ===
{{
  "attack_summary": "공격 행위를 1~2문장으로 요약 (Session 정보와 Flow 통계 고려)",
  "severity_reason": "위험도가 이 수준인 이유 (Alert + Anomaly Score 종합)",
  "attack_stage": "MITRE ATT&CK 기준 현재 공격 단계",
  "predicted_next": "다음 공격 단계 예측",
  "related_threat": "연관 공격자 또는 캠페인 정보 (없으면 null)",
  "mitigation": ["대응 방안 1", "대응 방안 2", "대응 방안 3"],
  "confidence": 0,
  "is_new_ip": {str(not ip_history.get("known", False)).lower()},
  "session_analysis": "Session 단위 분석 요약 (Flow 패턴, Alert 연계)"
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
        max_tokens: int = 1536,  # Session 정보 추가로 토큰 증가
    ) -> Dict[str, Any]:
        prompt = build_prompt(packet, graph_context, ip_history)
        logger.debug(f"Prompt length: {len(prompt)} chars")

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=0.1,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity analyst specializing in "
                            "Session-based network threat analysis. "
                            "Always respond with valid JSON only. "
                            "No markdown, no explanation, no code blocks."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            raw_text = response.choices[0].message.content.strip()
            result   = self._parse_response(raw_text)

        except Exception as e:
            logger.error(f"Groq API error: {e}")
            result = self._fallback_result(str(e))

        return {
            "packet":     packet,
            "xai_result": result,
            "model":      self.model,
        }

    def _parse_response(self, raw: str) -> Dict[str, Any]:
        # ```json ... ``` 블록 제거
        if "```" in raw:
            parts = raw.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:]
                part = part.strip()
                if part.startswith("{"):
                    raw = part
                    break
        try:
            return json.loads(raw.strip())
        except json.JSONDecodeError as e:
            logger.warning(f"JSON 파싱 실패: {e} | raw[:200]: {raw[:200]}")
            return {"raw_response": raw, "parse_error": str(e)}

    def _fallback_result(self, error: str) -> Dict[str, Any]:
        return {
            "attack_summary":  f"분석 실패: {error}",
            "severity_reason": "API 오류",
            "attack_stage":    "Unknown",
            "predicted_next":  None,
            "related_threat":  None,
            "mitigation":      ["수동 검토 필요"],
            #"confidence":      0,
            "is_new_ip":       True,
            "session_analysis": "분석 불가"
        }

