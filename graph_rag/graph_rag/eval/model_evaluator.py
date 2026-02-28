"""
eval/model_evaluator.py
LLM API (Gemini, Groq, OpenAI) 성능 비교 모듈
- BLEU, ROUGE-1/2/L, BERTScore (선택), 응답 속도, 비용 산출
"""

from logging import config
import time
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# ── 지표 라이브러리 (없으면 graceful skip) ─────────────────

try:
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    BLEU_AVAILABLE = True
except ImportError:
    BLEU_AVAILABLE = False
    logger.warning("nltk not available. pip install nltk")

try:
    from rouge_score import rouge_scorer
    ROUGE_AVAILABLE = True
except ImportError:
    ROUGE_AVAILABLE = False
    logger.warning("rouge_score not available. pip install rouge-score")


# ── 비용 테이블 (USD per 1M tokens, 2025년 기준) ───────────

COST_TABLE = {
    # model_name: (input_cost, output_cost) per 1M tokens
    "llama-3.3-70b-versatile":    (0.59,  0.79),   # Groq
    "llama-3.1-8b-instant":       (0.05,  0.08),   # Groq
    "gemini-2.0-flash":           (0.10,  0.40),   # Google
    "gemini-2.0-flash-lite":           (0.075, 0.30),   # Google
    "gemini-2.5-flash-lite":             (1.25,  5.00),   # Google
    "gpt-4o-mini":                (0.15,  0.60),   # OpenAI
    "gpt-4o":                     (2.50, 10.00),   # OpenAI
}

# ── 참조 답변 템플릿 (정성 평가용) ──────────────────────────

REFERENCE_ANSWERS = {
    "attack_summary_keywords": [
        "공격", "탐지", "시그니처", "카테고리", "세션", "Flow",
        "Anomaly", "Alert", "IP", "포트"
    ],
    "required_fields": [
        "attack_summary", "severity_reason", "attack_stage",
        "predicted_next", "mitigation", "is_new_ip", "session_analysis"
    ],
    "mitre_stages": [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ]
}


@dataclass
class EvalResult:
    model:          str
    provider:       str
    bleu:           float = 0.0
    rouge1_f:       float = 0.0
    rouge2_f:       float = 0.0
    rougeL_f:       float = 0.0
    field_coverage: float = 0.0   # 필수 필드 포함률
    json_valid:     bool  = False
    mitre_valid:    bool  = False
    latency_sec:    float = 0.0
    input_tokens:   int   = 0
    output_tokens:  int   = 0
    cost_usd:       float = 0.0
    raw_response:   str   = ""
    error:          str   = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    @property
    def overall_score(self) -> float:
        """종합 점수 (정확도 60% + 속도 20% + 비용 20%)"""
        accuracy = (
            self.bleu * 0.2 +
            self.rouge1_f * 0.2 +
            self.rougeL_f * 0.2 +
            self.field_coverage * 0.2 +
            (1.0 if self.json_valid else 0.0) * 0.1 +
            (1.0 if self.mitre_valid else 0.0) * 0.1
        ) * 0.6

        # 속도 점수: 5초 이하면 1.0, 30초 이상이면 0.0
        speed_score = max(0.0, min(1.0, (30 - self.latency_sec) / 25)) * 0.2

        # 비용 점수: 0.001$ 이하면 1.0, 0.01$ 이상이면 0.0
        cost_score = max(0.0, min(1.0, (0.01 - self.cost_usd) / 0.009)) * 0.2

        return round(accuracy + speed_score + cost_score, 4)


# ── 개별 LLM 호출 ────────────────────────────────────────

class _GroqCaller:
    def __init__(self, api_key: str, model: str):
        from groq import Groq
        self.client = Groq(api_key=api_key)
        self.model = model

    def call(self, system: str, user: str, max_tokens: int = 1536) -> Dict:
        t0 = time.time()
        resp = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=0.0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ]
        )
        latency = time.time() - t0
        return {
            "text":          resp.choices[0].message.content.strip(),
            "input_tokens":  resp.usage.prompt_tokens,
            "output_tokens": resp.usage.completion_tokens,
            "latency":       latency,
        }


class _GeminiCaller:
    def __init__(self, api_key: str, model: str):
        from google import genai
        self.client = genai.Client(api_key=api_key)
        self.model_name = model

    def call(self, system: str, user: str, max_tokens: int = 1536) -> Dict:
        import time
        from google import genai
        from google.genai import types
        for attempt in range(3):
            try: 
                t0 = time.time()
                resp = self.client.models.generate_content(
                    model=self.model_name,
                    contents=user,
                    config=types.GenerateContentConfig(
                        max_output_tokens=max_tokens,
                        temperature=0.0,
                    )
                )
                latency = time.time() - t0
                usage = resp.usage_metadata
                return {
                    "text":          resp.text.strip(),
                    "input_tokens":  usage.prompt_token_count,
                    "output_tokens": usage.candidates_token_count,
                    "latency":       latency,
                }
            except Exception as e:
                if "429" in str(e) and attempt < 2:
                    logger.warning(f"Rate limit hit for Gemini. Retrying... (attempt {attempt+1}/3)")
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise e

class _OpenAICaller:
    def __init__(self, api_key: str, model: str):
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def call(self, system: str, user: str, max_tokens: int = 1536) -> Dict:
        t0 = time.time()
        resp = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=0.0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ]
        )
        latency = time.time() - t0
        return {
            "text":          resp.choices[0].message.content.strip(),
            "input_tokens":  resp.usage.prompt_tokens,
            "output_tokens": resp.usage.completion_tokens,
            "latency":       latency,
        }


def _get_caller(provider: str, model: str, keys: Dict[str, str]):
    if provider == "groq":
        return _GroqCaller(keys["groq"], model)
    elif provider == "gemini":
        return _GeminiCaller(keys["google"], model)
    elif provider == "openai":
        return _OpenAICaller(keys["openai"], model)
    raise ValueError(f"Unknown provider: {provider}")


# ── 평가 지표 계산 ───────────────────────────────────────

def _calc_bleu(hypothesis: str, reference: str) -> float:
    if not BLEU_AVAILABLE or not hypothesis or not reference:
        return 0.0
    hyp_tokens = hypothesis.lower().split()
    ref_tokens = reference.lower().split()
    if not hyp_tokens or not ref_tokens:
        return 0.0
    smoother = SmoothingFunction().method1
    return sentence_bleu([ref_tokens], hyp_tokens, smoothing_function=smoother)


def _calc_rouge(hypothesis: str, reference: str) -> Dict[str, float]:
    if not ROUGE_AVAILABLE or not hypothesis or not reference:
        return {"rouge1": 0.0, "rouge2": 0.0, "rougeL": 0.0}
    scorer = rouge_scorer.RougeScorer(["rouge1", "rouge2", "rougeL"], use_stemmer=False)
    scores = scorer.score(reference, hypothesis)
    return {
        "rouge1": scores["rouge1"].fmeasure,
        "rouge2": scores["rouge2"].fmeasure,
        "rougeL": scores["rougeL"].fmeasure,
    }


def _calc_field_coverage(response_text: str) -> float:
    """필수 JSON 필드 포함률"""
    count = sum(1 for f in REFERENCE_ANSWERS["required_fields"] if f in response_text)
    return count / len(REFERENCE_ANSWERS["required_fields"])


def _check_json_valid(response_text: str) -> bool:
    text = response_text.strip()
    if "```" in text:
        for part in text.split("```"):
            part = part.strip().lstrip("json").strip()
            if part.startswith("{"):
                text = part
                break
    try:
        json.loads(text)
        return True
    except Exception:
        return False


def _check_mitre_valid(response_text: str) -> bool:
    """응답에 유효한 MITRE 단계가 포함되어 있는지"""
    return any(stage in response_text for stage in REFERENCE_ANSWERS["mitre_stages"])


def _calc_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    if model not in COST_TABLE:
        return 0.0
    in_cost, out_cost = COST_TABLE[model]
    return (input_tokens * in_cost + output_tokens * out_cost) / 1_000_000


# ── 참조 텍스트 생성 (골든 답변) ─────────────────────────

def _build_reference_text(packet: Dict) -> str:
    """평가용 참조 답변 (키워드 기반)"""
    sig = packet.get("signature", "알 수 없는 시그니처")
    cat = packet.get("category", "알 수 없는 카테고리")
    src = packet.get("src_ip", "N/A")
    dst = packet.get("dest_ip", "N/A")
    sev = packet.get("severity_numeric", 4)

    sev_label = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}.get(sev, "Low")
    stage = "Reconnaissance" if "SCAN" in sig.upper() else "Initial Access"

    return json.dumps({
        "attack_summary": f"{src}에서 {dst}으로 {sig} 공격이 탐지됨. 카테고리: {cat}.",
        "severity_reason": f"위험도 {sev_label}로 판단. Alert 기반 분석.",
        "attack_stage": stage,
        "predicted_next": "Execution",
        "related_threat": None,
        "mitigation": [f"{cat} 관련 방화벽 규칙 적용", "해당 IP 차단", "로그 모니터링 강화"],
        "is_new_ip": True,
        "session_analysis": f"Session에서 {sig} 시그니처 탐지됨."
    }, ensure_ascii=False)


# ── 메인 평가 클래스 ─────────────────────────────────────

class ModelEvaluator:
    """
    여러 LLM 모델을 동일한 프롬프트로 호출하여 성능 비교
    """

    # 비교할 모델 목록 (provider, model_name)
    DEFAULT_MODELS = [
        ("groq",   "llama-3.3-70b-versatile"),
        ("groq",   "llama-3.1-8b-instant"),
        ("gemini", "gemini-2.0-flash"),
        ("openai", "gpt-4o-mini"),
    ]

    def __init__(self, api_keys: Dict[str, str], models: List = None):
        """
        api_keys: {"groq": "...", "google": "...", "openai": "..."}
        models: [(provider, model_name), ...]
        """
        self.api_keys = api_keys
        self.models = models or self._filter_available_models()

    def _filter_available_models(self) -> List:
        """API 키가 있는 모델만 필터링"""
        available = []
        for provider, model in self.DEFAULT_MODELS:
            key_map = {"groq": "groq", "gemini": "google", "openai": "openai"}
            key_name = key_map.get(provider, provider)
            if self.api_keys.get(key_name):
                available.append((provider, model))
        return available

    def evaluate_single(
        self,
        provider: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        reference_text: str,
    ) -> EvalResult:
        result = EvalResult(model=model, provider=provider)
        try:
            caller = _get_caller(provider, model, self.api_keys)
            resp = caller.call(system_prompt, user_prompt)

            result.raw_response  = resp["text"]
            result.input_tokens  = resp["input_tokens"]
            result.output_tokens = resp["output_tokens"]
            result.latency_sec   = round(resp["latency"], 3)
            result.cost_usd      = _calc_cost(model, resp["input_tokens"], resp["output_tokens"])
            result.json_valid    = _check_json_valid(resp["text"])
            result.mitre_valid   = _check_mitre_valid(resp["text"])
            result.field_coverage = _calc_field_coverage(resp["text"])

            result.bleu = round(_calc_bleu(resp["text"], reference_text), 4)
            rouge = _calc_rouge(resp["text"], reference_text)
            result.rouge1_f = round(rouge["rouge1"], 4)
            result.rouge2_f = round(rouge["rouge2"], 4)
            result.rougeL_f = round(rouge["rougeL"], 4)

        except Exception as e:
            result.error = str(e)
            logger.error(f"[{provider}/{model}] 평가 실패: {e}")

        return result

    def evaluate_all(
        self,
        packet: Dict[str, Any],
        system_prompt: str,
        user_prompt: str,
        n_trials: int = 1,
    ) -> List[EvalResult]:
        """
        모든 모델 평가 후 결과 반환
        n_trials: 동일 모델 반복 호출 수 (평균 산출)
        """
        reference_text = _build_reference_text(packet)
        results = []

        for provider, model in self.models:
            logger.info(f"평가 중: [{provider}] {model}")
            trial_results = []

            for t in range(n_trials):
                r = self.evaluate_single(provider, model, system_prompt, user_prompt, reference_text)
                trial_results.append(r)
                if n_trials > 1:
                    logger.info(f"  Trial {t+1}/{n_trials}: latency={r.latency_sec}s, bleu={r.bleu}")

            if n_trials > 1:
                # 평균값으로 집계
                avg = EvalResult(model=model, provider=provider)
                avg.bleu          = round(sum(r.bleu for r in trial_results) / n_trials, 4)
                avg.rouge1_f      = round(sum(r.rouge1_f for r in trial_results) / n_trials, 4)
                avg.rouge2_f      = round(sum(r.rouge2_f for r in trial_results) / n_trials, 4)
                avg.rougeL_f      = round(sum(r.rougeL_f for r in trial_results) / n_trials, 4)
                avg.field_coverage = round(sum(r.field_coverage for r in trial_results) / n_trials, 4)
                avg.json_valid    = all(r.json_valid for r in trial_results)
                avg.mitre_valid   = all(r.mitre_valid for r in trial_results)
                avg.latency_sec   = round(sum(r.latency_sec for r in trial_results) / n_trials, 3)
                avg.input_tokens  = trial_results[0].input_tokens
                avg.output_tokens = int(sum(r.output_tokens for r in trial_results) / n_trials)
                avg.cost_usd      = round(sum(r.cost_usd for r in trial_results) / n_trials, 8)
                avg.raw_response  = trial_results[-1].raw_response
                results.append(avg)
            else:
                results.append(trial_results[0])

        # 종합 점수 기준 정렬
        results.sort(key=lambda r: r.overall_score, reverse=True)
        return results

    def print_report(self, results: List[EvalResult]):
        """콘솔 비교표 출력"""
        print("\n" + "=" * 90)
        print("  LLM 모델 성능 비교 리포트")
        print("=" * 90)
        header = f"{'모델':<30} {'BLEU':>6} {'R-1':>6} {'R-L':>6} {'필드':>6} {'JSON':>5} {'지연(s)':>8} {'비용($)':>10} {'종합':>7}"
        print(header)
        print("-" * 90)
        for r in results:
            row = (
                f"{r.provider+'/'+r.model:<30} "
                f"{r.bleu:>6.4f} "
                f"{r.rouge1_f:>6.4f} "
                f"{r.rougeL_f:>6.4f} "
                f"{r.field_coverage:>6.2f} "
                f"{'✓' if r.json_valid else '✗':>5} "
                f"{r.latency_sec:>8.2f} "
                f"{r.cost_usd:>10.6f} "
                f"{r.overall_score:>7.4f}"
            )
            print(row)
        print("=" * 90)
        if results:
            best = results[0]
            print(f"\n★ 최적 모델: [{best.provider}] {best.model}  (종합점수: {best.overall_score})")
        print()

    def save_report(self, results: List[EvalResult], output_path: str):
        """JSON 파일로 저장"""
        data = {
            "results": [r.to_dict() | {"overall_score": r.overall_score} for r in results],
            "best_model": results[0].to_dict() if results else {},
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"평가 결과 저장: {output_path}")
        return data