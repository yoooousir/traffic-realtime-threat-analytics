"""
main.py (Session-Centric + Eval + Viz 통합 버전)

기존 기능:
  preprocess  CSV → JSONL → Neo4j
  analyze     단일 패킷 분석
  batch       JSONL 배치 분석

신규 기능:
  eval        LLM API (Gemini/Groq/OpenAI) BLEU·ROUGE·속도·비용 비교
  optimize    최적 프롬프트 산출
  visualize   Neo4j 공격 경로 PNG 저장
"""

import os
import json
import argparse
import logging
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

from preprocessor.preprocess import run_preprocessing
from graph.neo4j_module    import Neo4jLoader, Neo4jQuerier
from rag.rag_module        import RAGExecutor, build_prompt  # main_2 프롬프트 (할루시네이션 방지)

# ── 신규 eval 모듈 ────────────────────────────────────────
from eval.model_evaluator  import ModelEvaluator
from eval.prompt_optimizer import PromptOptimizer
from eval.graph_visualizer import GraphVisualizer

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)


# ── 설정 ─────────────────────────────────────────────────

CONFIG = {
    "base_dir":       os.getenv("BASE_DIR",        "."),
    "output_dir":     os.getenv("OUTPUT_DIR",      "./output"),
    "neo4j_uri":      os.getenv("NEO4J_URI",       "bolt://localhost:7687"),
    "neo4j_user":     os.getenv("NEO4J_USER",      "neo4j"),
    "neo4j_password": os.getenv("NEO4J_PASSWORD",  ""),
    "groq_key":       os.getenv("GROQ_API_KEY",    ""),
    "openai_key":     os.getenv("OPENAI_API_KEY",  ""),
    "google_key":     os.getenv("GOOGLE_API_KEY",  ""),
    "llm_model":      os.getenv("LLM_MODEL",       "llama-3.3-70b-versatile"),
}

API_KEYS = {
    "groq":   CONFIG["groq_key"],
    "google": CONFIG["google_key"],
    "openai": CONFIG["openai_key"],
}

# ============================================================
# 공통 헬퍼
# ============================================================

def _get_querier() -> Neo4jQuerier:
    return Neo4jQuerier(
        uri=CONFIG["neo4j_uri"],
        user=CONFIG["neo4j_user"],
        password=CONFIG["neo4j_password"],
    )

def _sample_packet_from_jsonl(
    jsonl_path: str,
    severity_max: int = 2,
) -> Dict[str, Any]:
    """평가용 샘플 패킷 추출 (severity 1~2 중 첫 번째)"""
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if int(r.get("severity_numeric", 4)) <= severity_max:
                return {
                    "source":           r.get("source", ""),
                    "session_id":       r.get("session_id", ""),
                    "session_type":     r.get("session_type", ""),
                    "src_ip":           r.get("src_ip", ""),
                    "dest_ip":          r.get("dest_ip", ""),
                    "proto":            r.get("proto", ""),
                    "timestamp":        r.get("timestamp", ""),
                    "severity_numeric": r.get("severity_numeric", 4),
                    "severity":         r.get("severity", "low"),
                    "category":         r.get("category", ""),
                    "signature":        r.get("signature", ""),
                    "has_alert":        r.get("has_alert", False),
                    "alert_count":      r.get("alert_count", 0),
                    "flow_state":       r.get("flow_state", ""),
                    "total_bytes":      r.get("total_bytes", 0),
                    "pkts_toserver":    r.get("pkts_toserver", 0),
                    "pkts_toclient":    r.get("pkts_toclient", 0),
                    "anomaly_score":    r.get("anomaly_score", 0),
                    "conn_state":       r.get("conn_state", ""),
                    "orig_bytes":       r.get("orig_bytes", 0),
                    "resp_bytes":       r.get("resp_bytes", 0),
                    "dns_query":        r.get("dns_query", ""),
                    "dns_qtype":        r.get("dns_qtype", ""),
                    "http_method":      r.get("http_method", ""),
                    "http_host":        r.get("http_host", ""),
                    "http_uri":         r.get("http_uri", ""),
                    "http_user_agent":  r.get("http_user_agent", ""),
                    "risk_score":       r.get("risk_score", 0),
                    "summary":          r.get("summary", ""),
                }
    return {}


# ============================================================
# Neo4j 초기화
# ============================================================

def clean_neo4j():
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(
        CONFIG["neo4j_uri"],
        auth=(CONFIG["neo4j_user"], CONFIG["neo4j_password"])
    )
    with driver.session() as session:
        result = session.run("MATCH (n) RETURN count(n) AS count")
        before = result.single()["count"]
        logger.info(f"🗑️  Neo4j 초기화 중... (기존 노드: {before:,})")
        session.run("MATCH (n) DETACH DELETE n")
        logger.info("✅ Neo4j 초기화 완료")
    driver.close()


# ============================================================
# 1. 전처리 + Neo4j 적재
# ============================================================

def run_preprocess_pipeline(base_dir: str = None, clean: bool = False):
    logger.info("▶ Session-Centric 파이프라인 시작")

    if base_dir:
        CONFIG["base_dir"] = base_dir

    if clean:
        logger.info("━" * 55)
        logger.info("Step 0/2  Neo4j 초기화")
        clean_neo4j()

    result = run_preprocessing(
        base_dir=CONFIG["base_dir"],
        output_dir=CONFIG["output_dir"],
    )

    logger.info("━" * 55)
    logger.info("Step 2/2  Neo4j Session-Centric Graph 적재")
    try:
        loader = Neo4jLoader(
            uri=CONFIG["neo4j_uri"],
            user=CONFIG["neo4j_user"],
            password=CONFIG["neo4j_password"],
        )
        loader.create_constraints()
        loader.load_from_jsonl(result["jsonl_path"])
        loader.close()
        logger.info("✅ Neo4j 적재 완료")
    except Exception as e:
        logger.warning(f"⚠️  Neo4j 적재 실패: {e}")

    logger.info("━" * 55)
    logger.info(f"✅ 완료  |  총 {result['total_records']}건  |  {result['jsonl_path']}")
    return result


# ============================================================
# 2. 단일 패킷 분석 (main_2 프롬프트 적용)
# ============================================================

def analyze_packet(packet: Dict[str, Any]) -> Dict[str, Any]:
    src_ip = packet["src_ip"]
    try:
        querier       = _get_querier()
        graph_context = querier.get_attack_context(src_ip)
        ip_history    = querier.get_ip_history(src_ip)
        querier.close()
    except Exception as e:
        logger.warning(f"⚠️  Neo4j 조회 실패: {e}")
        graph_context = {"src_ip": src_ip, "found": False, "alerts": [], "targeted_ips": []}
        ip_history    = {"src_ip": src_ip, "known": False}

    if not CONFIG["groq_key"]:
        logger.warning("⚠️  GROQ_API_KEY not set. Skipping LLM.")
        return {"packet": packet, "graph_context": graph_context,
                "ip_history": ip_history, "xai_result": {"error": "No API key"}}

    executor = RAGExecutor(api_key=CONFIG["groq_key"], model=CONFIG["llm_model"])
    result   = executor.run(packet=packet, graph_context=graph_context, ip_history=ip_history)

    xai = result["xai_result"]
    logger.info("=" * 60)
    logger.info(f"[{packet.get('source','?')}] {src_ip} → {packet.get('dest_ip','?')}")
    logger.info(f"공격 요약   : {xai.get('attack_summary', '-')}")
    logger.info(f"공격 단계   : {xai.get('attack_stage', '-')}")
    logger.info(f"다음 예측   : {xai.get('predicted_next', '-')}")
    logger.info(f"Session 분석: {xai.get('session_analysis', '-')}")
    for m in xai.get("mitigation", []):
        logger.info(f"  대응: {m}")
    logger.info("=" * 60)
    return result


# ============================================================
# 3. 배치 분석
# ============================================================

def run_batch_analysis(
    jsonl_path: str = "./output/unified_events.jsonl",
    output_path: str = "./output/xai_results.jsonl",
    visualize: bool = False,
):
    logger.info(f"▶ 배치 분석 시작: {jsonl_path}")

    if not CONFIG["groq_key"]:
        logger.error("❌ GROQ_API_KEY not set.")
        return

    try:
        querier = _get_querier()
    except Exception as e:
        logger.error(f"❌ Neo4j 연결 실패: {e}")
        return

    executor = RAGExecutor(api_key=CONFIG["groq_key"], model=CONFIG["llm_model"])
    viz = GraphVisualizer(
        CONFIG["neo4j_uri"], CONFIG["neo4j_user"], CONFIG["neo4j_password"]
    ) if visualize else None

    total = analyzed = 0
    source_counts: Dict[str, int] = {}

    with open(jsonl_path, "r", encoding="utf-8") as f_in, \
         open(output_path, "w", encoding="utf-8") as f_out:

        for line in f_in:
            r = json.loads(line)
            total += 1
            if int(r.get("severity_numeric", 4)) > 2:
                continue

            source = r.get("source", "unknown")
            packet = {
                "source": source, "session_id": r.get("session_id", ""),
                "session_type": r.get("session_type", ""),
                "src_ip": r.get("src_ip", ""), "dest_ip": r.get("dest_ip", ""),
                "proto": r.get("proto", ""), "timestamp": r.get("timestamp", ""),
                "severity_numeric": r.get("severity_numeric", 4),
                "severity": r.get("severity", "low"),
                "category": r.get("category", ""), "signature": r.get("signature", ""),
                "has_alert": r.get("has_alert", False), "alert_count": r.get("alert_count", 0),
                "flow_state": r.get("flow_state", ""), "total_bytes": r.get("total_bytes", 0),
                "pkts_toserver": r.get("pkts_toserver", 0),
                "pkts_toclient": r.get("pkts_toclient", 0),
                "anomaly_score": r.get("anomaly_score", 0),
                "summary": r.get("summary", ""),
            }

            graph_context = querier.get_attack_context(packet["src_ip"])
            ip_history    = querier.get_ip_history(packet["src_ip"])
            result        = executor.run(packet, graph_context, ip_history)

            # 그래프 시각화 (옵션)
            if viz:
                try:
                    png_path = viz.visualize_rag_result(result, output_dir="./output/graphs")
                    result["graph_png"] = png_path
                except Exception as e:
                    logger.warning(f"그래프 시각화 실패: {e}")

            f_out.write(json.dumps(result, ensure_ascii=False) + "\n")
            analyzed += 1
            source_counts[source] = source_counts.get(source, 0) + 1

            if analyzed % 50 == 0:
                logger.info(f"  분석 {analyzed}건 완료...")

    querier.close()
    logger.info("━" * 55)
    logger.info(f"✅ 배치 분석 완료: {total}건 중 {analyzed}건 분석")
    logger.info(f"   소스별: {source_counts}  |  결과: {output_path}")


# ============================================================
# 4. LLM 모델 성능 비교 (eval)
# ============================================================

def run_eval(
    jsonl_path: str = "./output/unified_events.jsonl",
    output_path: str = "./output/eval_results.json",
    n_trials: int = 1,
    models: list = None,
):
    """
    Gemini / Groq / OpenAI 모델 BLEU·ROUGE·속도·비용 비교
    """
    logger.info("▶ LLM 모델 성능 평가 시작")

    # 샘플 패킷 추출
    packet = _sample_packet_from_jsonl(jsonl_path)
    if not packet:
        logger.error("❌ 평가용 패킷 없음 (severity 1~2 데이터 필요)")
        return

    # Neo4j 컨텍스트
    try:
        querier       = _get_querier()
        graph_context = querier.get_attack_context(packet["src_ip"])
        ip_history    = querier.get_ip_history(packet["src_ip"])
        querier.close()
    except Exception as e:
        logger.warning(f"⚠️  Neo4j 컨텍스트 없이 평가: {e}")
        graph_context = {"src_ip": packet["src_ip"], "found": False, "alerts": [], "targeted_ips": []}
        ip_history    = {"src_ip": packet["src_ip"], "known": False}

    # 프롬프트 생성 (main_2 튜닝 버전)
    from rag.rag_module import build_prompt as build_prompt_v2
    from eval.prompt_optimizer import SYSTEM_PROMPT_VARIANTS

    user_prompt   = build_prompt_v2(packet, graph_context, ip_history)
    system_prompt = SYSTEM_PROMPT_VARIANTS["strict"]

    # 모델 목록
    if models:
        model_list = [tuple(m.split("/")) for m in models]
    else:
        model_list = None  # 기본값 (API 키 있는 모델만 자동 선택)

    evaluator = ModelEvaluator(API_KEYS, models=model_list)
    results   = evaluator.evaluate_all(packet, system_prompt, user_prompt, n_trials=n_trials)

    evaluator.print_report(results)
    data = evaluator.save_report(results, output_path)

    logger.info(f"✅ 평가 완료  |  결과: {output_path}")
    return data


# ============================================================
# 5. 최적 프롬프트 산출 (optimize)
# ============================================================

def run_optimize(
    jsonl_path: str = "./output/unified_events.jsonl",
    output_path: str = "./output/prompt_optimization.json",
    target_model: str = "groq/llama-3.3-70b-versatile",
    n_trials: int = 1,
):
    """
    프롬프트 변형 × 지표 평가 → 최적 프롬프트 선정
    """
    logger.info("▶ 프롬프트 최적화 시작")

    provider, model = target_model.split("/", 1)

    packet = _sample_packet_from_jsonl(jsonl_path)
    if not packet:
        logger.error("❌ 최적화용 패킷 없음")
        return

    try:
        querier       = _get_querier()
        graph_context = querier.get_attack_context(packet["src_ip"])
        ip_history    = querier.get_ip_history(packet["src_ip"])
        querier.close()
    except Exception as e:
        logger.warning(f"⚠️  Neo4j 컨텍스트 없이 최적화: {e}")
        graph_context = {"src_ip": packet["src_ip"], "found": False, "alerts": [], "targeted_ips": []}
        ip_history    = {"src_ip": packet["src_ip"], "known": False}

    from rag.rag_module import build_prompt as build_prompt_v2

    evaluator  = ModelEvaluator(API_KEYS)
    optimizer  = PromptOptimizer(
        evaluator=evaluator,
        target_model=(provider, model),
        base_user_prompt_fn=build_prompt_v2,
    )

    best, all_variants = optimizer.optimize(
        packet=packet,
        graph_context=graph_context,
        ip_history=ip_history,
        n_trials=n_trials,
    )

    optimizer.print_report(all_variants)
    data = optimizer.save_report(best, all_variants, output_path)

    logger.info(f"✅ 최적화 완료  |  최적 변형: {best.variant_id}  |  결과: {output_path}")
    return data


# ============================================================
# 6. 그래프 시각화 (visualize)
# ============================================================

def run_visualize(
    src_ip: str = None,
    cypher: str = None,
    output_dir: str = "./output/graphs",
    layout: str = "spring",
    title: str = None,
):
    """
    Neo4j 공격 경로를 PNG로 저장
    - src_ip 지정 시 해당 IP의 공격 경로 시각화
    - cypher 지정 시 임의 쿼리 결과 시각화
    """
    logger.info("▶ 그래프 시각화 시작")

    viz = GraphVisualizer(
        CONFIG["neo4j_uri"], CONFIG["neo4j_user"], CONFIG["neo4j_password"]
    )

    if src_ip:
        path = viz.visualize_ip(src_ip=src_ip, output_dir=output_dir, layout=layout)
        if path:
            logger.info(f"✅ 그래프 저장: {path}")
        else:
            logger.warning(f"⚠️  {src_ip}에 대한 그래프 데이터 없음")
        return path

    elif cypher:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"{output_dir}/query_{ts}.png"
        path = viz.visualize_query(
            cypher=cypher,
            title=title or "Query Path Graph",
            output_path=output_path,
            layout=layout,
        )
        if path:
            logger.info(f"✅ 그래프 저장: {path}")
        return path

    else:
        # src_ip/cypher 미지정 시 전체 그래프 샘플 (LIMIT 200)
        logger.info("src_ip/cypher 미지정 → 전체 그래프 샘플 (LIMIT 200) 시각화")
        cypher = "MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 200"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"{output_dir}/full_graph_{ts}.png"
        path = viz.visualize_query(
            cypher=cypher,
            title=title or "Full Graph Sample (LIMIT 200)",
            output_path=output_path,
            layout=layout,
        )
        if path:
            logger.info(f"✅ 그래프 저장: {path}")
        return path


# ============================================================
# CLI
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Security RAG Pipeline — Session-Centric + Eval + Viz"
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # ── preprocess ──
    pre = sub.add_parser("preprocess", help="CSV → JSONL → Neo4j")
    pre.add_argument("--base-dir", default=CONFIG["base_dir"])
    pre.add_argument("--clean", action="store_true", help="Neo4j 초기화 후 재적재")

    # ── analyze ──
    ana = sub.add_parser("analyze", help="단일 패킷 분석")
    ana.add_argument("--src-ip",    required=True)
    ana.add_argument("--dest-ip",   default="")
    ana.add_argument("--signature", default="")
    ana.add_argument("--severity",  type=int, default=2)
    ana.add_argument("--source",    default="suricata_flow")

    # ── batch ──
    bat = sub.add_parser("batch", help="JSONL 배치 분석")
    bat.add_argument("--input",     default="./output/unified_events.jsonl")
    bat.add_argument("--output",    default="./output/xai_results.jsonl")
    bat.add_argument("--visualize", action="store_true", help="분석마다 그래프 PNG 저장")

    # ── eval ──
    ev = sub.add_parser("eval", help="LLM 모델 성능 비교 (BLEU/ROUGE/속도/비용)")
    ev.add_argument("--input",    default="./output/unified_events.jsonl")
    ev.add_argument("--output",   default="./output/eval_results.json")
    ev.add_argument("--trials",   type=int, default=1, help="모델당 반복 호출 수 (평균)")
    ev.add_argument(
        "--models", nargs="+",
        help="비교할 모델 목록 (예: groq/llama-3.3-70b-versatile gemini/gemini-2.0-flash)",
        default=None,
    )

    # ── optimize ──
    opt = sub.add_parser("optimize", help="최적 프롬프트 산출")
    opt.add_argument("--input",        default="./output/unified_events.jsonl")
    opt.add_argument("--output",       default="./output/prompt_optimization.json")
    opt.add_argument("--target-model", default="groq/llama-3.3-70b-versatile",
                     help="평가에 사용할 모델 (provider/model_name)")
    opt.add_argument("--trials",       type=int, default=1)

    # ── visualize ──
    viz = sub.add_parser("visualize", help="Neo4j 공격 경로 PNG 저장")
    viz.add_argument("--src-ip",    default=None, help="시각화할 소스 IP")
    viz.add_argument("--cypher",    default=None, help="임의 Cypher 쿼리")
    viz.add_argument("--output-dir",default="./output/graphs")
    viz.add_argument("--layout",    default="spring",
                     choices=["spring", "kamada_kawai", "circular"], help="그래프 레이아웃")
    viz.add_argument("--title",     default=None)

    return parser.parse_args()


def main():
    args = parse_args()

    if args.mode == "preprocess":
        run_preprocess_pipeline(base_dir=args.base_dir, clean=args.clean)

    elif args.mode == "analyze":
        packet = {
            "source":           args.source,
            "src_ip":           args.src_ip,
            "dest_ip":          args.dest_ip,
            "signature":        args.signature,
            "severity_numeric": args.severity,
            "timestamp":        datetime.now().isoformat(),
        }
        result = analyze_packet(packet)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.mode == "batch":
        run_batch_analysis(
            jsonl_path=args.input,
            output_path=args.output,
            visualize=args.visualize,
        )

    elif args.mode == "eval":
        run_eval(
            jsonl_path=args.input,
            output_path=args.output,
            n_trials=args.trials,
            models=args.models,
        )

    elif args.mode == "optimize":
        run_optimize(
            jsonl_path=args.input,
            output_path=args.output,
            target_model=args.target_model,
            n_trials=args.trials,
        )

    elif args.mode == "visualize":
        run_visualize(
            src_ip=args.src_ip,
            cypher=args.cypher,
            output_dir=args.output_dir,
            layout=args.layout,
            title=args.title,
        )


if __name__ == "__main__":
    main()