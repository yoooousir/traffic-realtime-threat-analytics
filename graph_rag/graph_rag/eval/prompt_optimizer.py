"""
eval/prompt_optimizer.py
최적 프롬프트 산출 모듈
- 프롬프트 변형 생성 → 동일 모델로 평가 → 최고 점수 프롬프트 선정
- main.py의 main_2 프롬프트 튜닝 기반으로 발전
"""

import json
import logging
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass, asdict

from eval.model_evaluator import ModelEvaluator, EvalResult, _build_reference_text

logger = logging.getLogger(__name__)


# ── 프롬프트 변형 전략 ────────────────────────────────────

SYSTEM_PROMPT_VARIANTS = {
    "base": (
        "You are a cybersecurity analyst specializing in "
        "Session-based network threat analysis using real observed data. "
        "Output valid JSON only — no markdown, no explanation, no code blocks."
    ),
    "strict": (
        "You are a cybersecurity analyst specializing in "
        "Session-based network threat analysis using real observed data. "
        "STRICT RULES: "
        "1) Output valid JSON only — no markdown, no explanation, no code blocks. "
        "2) Never invent, infer, or hallucinate data not explicitly provided. "
        "3) If data is missing, use null or empty array — never fabricate values. "
        "4) MITRE ATT&CK stages must only come from the provided list in the prompt. "
        "5) is_new_ip must match the value specified in the prompt exactly."
    ),
    "cot": (
        "You are a cybersecurity analyst specializing in "
        "Session-based network threat analysis. "
        "Before answering, think step by step: "
        "1) What attack pattern is shown? "
        "2) What MITRE stage fits? "
        "3) What mitigation is specific to this attack type? "
        "Then output valid JSON only."
    ),
    "korean": (
        "당신은 네트워크 보안 관제 전문가입니다. "
        "제공된 데이터만을 근거로 분석하며, 반드시 유효한 JSON만 출력하세요. "
        "마크다운, 코드블록, 설명 텍스트는 절대 포함하지 마세요. "
        "데이터에 없는 정보는 null로 처리하세요."
    ),
}

# user 프롬프트 suffix 변형 (구조 강조 방식)
USER_PROMPT_SUFFIXES = {
    "default": "",
    "emphasis": (
        "\n\n[중요] 반드시 위 JSON 형식 그대로만 출력하세요. "
        "추가 텍스트, 마크다운, 코드블록 절대 금지."
    ),
    "example": (
        "\n\n출력 예시:\n"
        '{"attack_summary": "...", "severity_reason": "...", '
        '"attack_stage": "Reconnaissance", "predicted_next": "Initial Access", '
        '"related_threat": null, "mitigation": ["...", "..."], '
        '"is_new_ip": true, "session_analysis": "..."}'
    ),
    "chain": (
        "\n\n분석 순서: "
        "① 시그니처·카테고리로 공격 행위 파악 → "
        "② Anomaly Score·Alert 수로 위험도 판단 → "
        "③ MITRE 단계 매핑 → "
        "④ 대응 방안 도출 → "
        "⑤ JSON 출력"
    ),
}


@dataclass
class PromptVariant:
    system_key:   str
    suffix_key:   str
    system_text:  str
    suffix_text:  str
    eval_result:  EvalResult = None

    @property
    def variant_id(self) -> str:
        return f"{self.system_key}+{self.suffix_key}"

    def to_dict(self) -> Dict:
        d = {
            "variant_id":  self.variant_id,
            "system_key":  self.system_key,
            "suffix_key":  self.suffix_key,
            "system_text": self.system_text,
            "suffix_text": self.suffix_text,
        }
        if self.eval_result:
            d["eval"] = self.eval_result.to_dict()
            d["overall_score"] = self.eval_result.overall_score
        return d


class PromptOptimizer:
    """
    프롬프트 변형 × 평가 → 최적 프롬프트 선정
    """

    def __init__(
        self,
        evaluator: ModelEvaluator,
        target_model: Tuple[str, str],   # (provider, model_name)
        base_user_prompt_fn,             # Callable: (packet, graph_ctx, ip_hist) → str
    ):
        self.evaluator = evaluator
        self.target_provider, self.target_model = target_model
        self.base_user_prompt_fn = base_user_prompt_fn

    def _build_variants(self) -> List[PromptVariant]:
        variants = []
        for sys_key, sys_text in SYSTEM_PROMPT_VARIANTS.items():
            for suf_key, suf_text in USER_PROMPT_SUFFIXES.items():
                variants.append(PromptVariant(
                    system_key=sys_key,
                    suffix_key=suf_key,
                    system_text=sys_text,
                    suffix_text=suf_text,
                ))
        return variants

    def optimize(
        self,
        packet: Dict[str, Any],
        graph_context: Dict[str, Any],
        ip_history: Dict[str, Any],
        n_trials: int = 1,
    ) -> Tuple[PromptVariant, List[PromptVariant]]:
        """
        모든 프롬프트 변형 평가 후 최적 변형 반환
        Returns: (best_variant, all_variants_sorted)
        """
        base_user = self.base_user_prompt_fn(packet, graph_context, ip_history)
        reference = _build_reference_text(packet)
        variants  = self._build_variants()

        logger.info(f"프롬프트 최적화 시작: {len(variants)}개 변형 × {n_trials}회 시험")

        # 원래 evaluator의 models를 임시 교체하여 단일 모델만 사용
        original_models = self.evaluator.models
        self.evaluator.models = [(self.target_provider, self.target_model)]

        for i, variant in enumerate(variants):
            user_prompt = base_user + variant.suffix_text
            logger.info(f"  [{i+1}/{len(variants)}] {variant.variant_id} 평가 중...")

            result = self.evaluator.evaluate_single(
                provider=self.target_provider,
                model=self.target_model,
                system_prompt=variant.system_text,
                user_prompt=user_prompt,
                reference_text=reference,
            )
            variant.eval_result = result

        self.evaluator.models = original_models

        # 종합 점수 기준 정렬
        variants_sorted = sorted(
            variants,
            key=lambda v: v.eval_result.overall_score if v.eval_result else 0,
            reverse=True
        )

        best = variants_sorted[0]
        logger.info(f"\n★ 최적 프롬프트: {best.variant_id}  (점수: {best.eval_result.overall_score})")
        return best, variants_sorted

    def print_report(self, variants: List[PromptVariant]):
        print("\n" + "=" * 95)
        print("  프롬프트 변형 최적화 리포트")
        print("=" * 95)
        header = (
            f"{'변형 ID':<25} {'BLEU':>6} {'R-1':>6} {'R-L':>6} "
            f"{'필드':>6} {'JSON':>5} {'MITRE':>6} {'지연(s)':>8} {'비용($)':>10} {'종합':>7}"
        )
        print(header)
        print("-" * 95)
        for v in variants:
            if not v.eval_result:
                continue
            r = v.eval_result
            row = (
                f"{v.variant_id:<25} "
                f"{r.bleu:>6.4f} "
                f"{r.rouge1_f:>6.4f} "
                f"{r.rougeL_f:>6.4f} "
                f"{r.field_coverage:>6.2f} "
                f"{'✓' if r.json_valid else '✗':>5} "
                f"{'✓' if r.mitre_valid else '✗':>6} "
                f"{r.latency_sec:>8.2f} "
                f"{r.cost_usd:>10.6f} "
                f"{r.overall_score:>7.4f}"
            )
            print(row)
        print("=" * 95)
        if variants:
            best = variants[0]
            print(f"\n★ 최적 프롬프트 변형: {best.variant_id}")
            if best.eval_result:
                print(f"   BLEU: {best.eval_result.bleu}  |  ROUGE-L: {best.eval_result.rougeL_f}"
                      f"  |  지연: {best.eval_result.latency_sec}s  |  비용: ${best.eval_result.cost_usd:.6f}")
        print()

    def save_report(self, best: PromptVariant, all_variants: List[PromptVariant], output_path: str):
        data = {
            "best_variant": best.to_dict(),
            "all_variants": [v.to_dict() for v in all_variants],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"프롬프트 최적화 결과 저장: {output_path}")
        return data