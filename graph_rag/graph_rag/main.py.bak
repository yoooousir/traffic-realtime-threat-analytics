"""
main.py (Session-Centric Version with Clean Option)
Suricata Flows + Alerts 병합 + Zeek → Neo4j → RAG
Neo4j 초기화 옵션 추가
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
from rag.rag_module        import RAGExecutor

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


# ============================================================
# Neo4j 초기화
# ============================================================

def clean_neo4j():
    """Neo4j 데이터베이스 전체 삭제"""
    try:
        from neo4j import GraphDatabase
        
        driver = GraphDatabase.driver(
            CONFIG["neo4j_uri"],
            auth=(CONFIG["neo4j_user"], CONFIG["neo4j_password"])
        )
        
        with driver.session() as session:
            # 모든 노드와 관계 삭제
            result = session.run("MATCH (n) RETURN count(n) AS count")
            before_count = result.single()["count"]
            
            logger.info(f"🗑️  Neo4j 초기화 중... (기존 노드 수: {before_count:,})")
            session.run("MATCH (n) DETACH DELETE n")
            logger.info("✅ Neo4j 데이터베이스 초기화 완료")
        
        driver.close()
    except Exception as e:
        logger.error(f"❌ Neo4j 초기화 실패: {e}")


# ============================================================
# 1. 전처리 + Neo4j 적재
# ============================================================

def run_preprocess_pipeline(base_dir: str = None, clean: bool = False):
    """CSV → JSONL → Neo4j"""
    logger.info("▶ Session-Centric 파이프라인 시작")
    
    if base_dir:
        CONFIG["base_dir"] = base_dir

    # Step 0: Neo4j 초기화 (옵션)
    if clean:
        logger.info("━" * 55)
        logger.info("Step 0/2  Neo4j 데이터베이스 초기화")
        clean_neo4j()

    # Step 1: CSV → JSONL
    result = run_preprocessing(
        base_dir   = CONFIG["base_dir"],
        output_dir = CONFIG["output_dir"],
    )

    # Step 2: Neo4j 적재
    logger.info("━" * 55)
    logger.info("Step 2/2  Neo4j Session-Centric Graph 적재")
    
    try:
        loader = Neo4jLoader(
            uri      = CONFIG["neo4j_uri"],
            user     = CONFIG["neo4j_user"],
            password = CONFIG["neo4j_password"],
        )
        loader.create_constraints()
        loader.load_from_jsonl(result["jsonl_path"])
        loader.close()
        logger.info("✅ Neo4j 적재 완료")
    except Exception as e:
        logger.warning(f"⚠️  Neo4j 적재 실패: {e}")
        logger.info("JSONL 파일은 정상 생성되었습니다.")

    logger.info("━" * 55)
    logger.info("✅ 전체 파이프라인 완료")
    logger.info(f"   소스별 레코드: {result['source_stats']}")
    logger.info(f"   총 레코드: {result['total_records']}건")
    logger.info(f"   JSONL: {result['jsonl_path']}")
    
    return result


# ============================================================
# 2. 단일 패킷 분석
# ============================================================

def analyze_packet(packet: Dict[str, Any]) -> Dict[str, Any]:
    """패킷 dict → Neo4j 탐색 → RAG → XAI"""
    src_ip = packet["src_ip"]

    try:
        querier = Neo4jQuerier(
            uri      = CONFIG["neo4j_uri"],
            user     = CONFIG["neo4j_user"],
            password = CONFIG["neo4j_password"],
        )
        graph_context = querier.get_attack_context(src_ip)
        ip_history    = querier.get_ip_history(src_ip)
        querier.close()
    except Exception as e:
        logger.warning(f"⚠️  Neo4j 조회 실패: {e}")
        graph_context = {"src_ip": src_ip, "found": False, "alerts": [], "targeted_ips": []}
        ip_history = {"src_ip": src_ip, "known": False}

    if not CONFIG["groq_key"]:
        logger.warning("⚠️  GROQ_API_KEY not set. Skipping LLM analysis.")
        return {
            "packet": packet,
            "graph_context": graph_context,
            "ip_history": ip_history,
            "xai_result": {"error": "No API key"}
        }

    executor = RAGExecutor(
        api_key = CONFIG["groq_key"],
        model   = CONFIG["llm_model"],
    )
    result = executor.run(
        packet        = packet,
        graph_context = graph_context,
        ip_history    = ip_history,
    )

    xai = result["xai_result"]
    logger.info("=" * 60)
    logger.info(f"[{packet.get('source','?')}] {src_ip} → {packet.get('dest_ip','?')}")
    logger.info(f"공격 요약  : {xai.get('attack_summary', '-')}")
    logger.info(f"공격 단계  : {xai.get('attack_stage', '-')}")
    logger.info(f"다음 예측  : {xai.get('predicted_next', '-')}")
    #logger.info(f"신뢰도     : {xai.get('confidence', 0)}%")
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
):
    """JSONL 전체 순회 → severity 1~2만 LLM 분석"""
    logger.info(f"▶ 배치 분석 시작: {jsonl_path}")

    if not CONFIG["groq_key"]:
        logger.error("❌ GROQ_API_KEY not set. Cannot run batch analysis.")
        return

    try:
        querier  = Neo4jQuerier(
            uri=CONFIG["neo4j_uri"],
            user=CONFIG["neo4j_user"],
            password=CONFIG["neo4j_password"],
        )
    except Exception as e:
        logger.error(f"❌ Neo4j 연결 실패: {e}")
        return
    
    executor = RAGExecutor(
        api_key=CONFIG["groq_key"],
        model=CONFIG["llm_model"],
    )

    total = analyzed = 0
    source_counts: Dict[str, int] = {}

    with open(jsonl_path, "r", encoding="utf-8") as f_in, \
         open(output_path, "w", encoding="utf-8") as f_out:

        for line in f_in:
            r = json.loads(line)
            total += 1

            # severity 1~2(critical/high)만 분석
            if int(r.get("severity_numeric", 4)) > 2:
                continue

            source = r.get("source", "unknown")

            # 패킷 dict 구성
            packet = {
                "source":           source,
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
                "anomaly_score":    r.get("anomaly_score", 0),
                "summary":          r.get("summary", ""),
            }

            graph_context = querier.get_attack_context(packet["src_ip"])
            ip_history    = querier.get_ip_history(packet["src_ip"])
            result        = executor.run(packet, graph_context, ip_history)

            f_out.write(json.dumps(result, ensure_ascii=False) + "\n")
            analyzed += 1
            source_counts[source] = source_counts.get(source, 0) + 1

            if analyzed % 50 == 0:
                logger.info(f"  분석 {analyzed}건 완료...")

    querier.close()
    logger.info("━" * 55)
    logger.info(f"✅ 배치 분석 완료: 전체 {total}건 중 {analyzed}건 분석")
    logger.info(f"   소스별: {source_counts}")
    logger.info(f"   결과 저장: {output_path}")


# ============================================================
# 4. CLI
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Session-Centric Security RAG Pipeline"
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # preprocess
    pre = sub.add_parser("preprocess", 
                         help="CSV → JSONL → Neo4j")
    pre.add_argument("--base-dir", default=CONFIG["base_dir"],
                     help="CSV 파일이 있는 디렉토리")
    pre.add_argument("--clean", action="store_true",
                     help="Neo4j 데이터베이스 초기화 후 적재 (중복 방지)")

    # analyze
    ana = sub.add_parser("analyze", help="단일 패킷 분석")
    ana.add_argument("--src-ip",    required=True)
    ana.add_argument("--dest-ip",   default="")
    ana.add_argument("--signature", default="")
    ana.add_argument("--severity",  type=int, default=2)
    ana.add_argument("--source",    default="suricata_flow")

    # batch
    bat = sub.add_parser("batch", help="JSONL 배치 분석")
    bat.add_argument("--input",  default="./output/unified_events.jsonl")
    bat.add_argument("--output", default="./output/xai_results.jsonl")

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
        run_batch_analysis(args.input, args.output)


if __name__ == "__main__":
    main()

