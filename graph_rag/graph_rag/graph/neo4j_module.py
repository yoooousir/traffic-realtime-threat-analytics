"""
Neo4j 그래프 모듈 (Session-Centric Version)
- Session/Host/Service/Signature 노드
- SRC/DST/TARGETS/TRIGGERED/RUNS 관계
"""

import json
import logging
from typing import Dict, List, Any

from neo4j import GraphDatabase, Driver

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


class Neo4jLoader:
    """
    unified_events.jsonl (Session-centric) → Neo4j
    
    노드: Session, Host, Service, Signature, Domain, URL
    관계: SRC, DST, TARGETS, TRIGGERED, RUNS, QUERIES, ACCESSES, RESOLVED_TO
    """

    def __init__(self, uri: str, user: str, password: str):
        self.driver: Driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def create_constraints(self):
        """인덱스 및 제약조건 생성"""
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Session)   REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Host)      REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Service)   REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Signature) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Domain)    REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:URL)       REQUIRE n.id IS UNIQUE",
        ]
        with self.driver.session() as session:
            for q in constraints:
                session.run(q)
        logger.info("Constraints created.")

    def load_from_jsonl(self, jsonl_path: str, batch_size: int = 500):
        """JSONL 파일에서 그래프 로드"""
        records = []
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                records.append(json.loads(line))

        total = len(records)
        for i in range(0, total, batch_size):
            batch = records[i: i + batch_size]
            with self.driver.session() as session:
                session.execute_write(self._write_batch, batch)
            logger.info(f"  적재 {min(i + batch_size, total)}/{total}건...")

        logger.info(f"Neo4j 적재 완료: {total}건")

    @staticmethod
    def _write_batch(tx, batch: List[Dict]):
        """배치 단위 그래프 작성"""
        for r in batch:
            session_id = r.get("session_id", "")
            if not session_id:
                continue
            
            # ── Session 노드 생성 ──
            tx.run("""
                MERGE (s:Session {id: $sid})
                SET s.type = $type,
                    s.source = $source,
                    s.timestamp = $ts,
                    s.severity = $sev,
                    s.has_alert = $has_alert
                """,
                sid=session_id,
                type=r.get("session_type", ""),
                source=r.get("source", ""),
                ts=r.get("timestamp", ""),
                sev=int(r.get("severity_numeric", 4)),
                has_alert=bool(r.get("has_alert", False))
            )
            
            # ── 노드들 생성 ──
            nodes = r.get("nodes", {})
            for node_key, node_data in nodes.items():
                node_id = node_data.get("id", "")
                node_type = node_data.get("type", "").capitalize()
                
                if not node_id or not node_type:
                    continue
                
                # 노드별 속성 설정
                props = {k: v for k, v in node_data.items() 
                        if k not in ['id', 'type']}
                props_str = ", ".join([f"n.{k} = ${k}" for k in props.keys()])
                
                query = f"""
                    MERGE (n:{node_type} {{id: $nid}})
                    SET {props_str}
                """ if props_str else f"MERGE (n:{node_type} {{id: $nid}})"
                
                tx.run(query, nid=node_id, **props)
            
            # ── 엣지들 생성 ──
            edges = r.get("edges", [])
            for edge in edges:
                from_id = edge.get("from", "")
                to_id = edge.get("to", "")
                edge_type = edge.get("type", "RELATED")
                
                if not from_id or not to_id:
                    continue
                
                # 엣지 생성 (증분 count)
                tx.run(f"""
                    MATCH (a {{id: $from_id}}), (b {{id: $to_id}})
                    MERGE (a)-[r:{edge_type}]->(b)
                    ON CREATE SET r.count = 1, r.created = timestamp()
                    ON MATCH SET r.count = r.count + 1, r.updated = timestamp()
                    """,
                    from_id=from_id,
                    to_id=to_id
                )


class Neo4jQuerier:
    """Session-centric 그래프 탐색"""

    def __init__(self, uri: str, user: str, password: str):
        self.driver: Driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def get_attack_context(self, src_ip: str) -> Dict[str, Any]:
        """특정 IP의 공격 컨텍스트 조회"""
        with self.driver.session() as session:
            # 1. 해당 IP에서 발생한 Alert
            alerts = session.run("""
                MATCH (h:Host {ip: $ip})<-[:SRC]-(s:Session)-[:TRIGGERED]->(sig:Signature)
                RETURN sig.signature AS signature,
                       sig.category AS category,
                       sig.severity AS severity,
                       s.timestamp AS timestamp
                ORDER BY sig.severity ASC
                LIMIT 10
                """, ip=src_ip).data()
            
            # 2. 타겟한 IP들
            targets = session.run("""
                MATCH (h:Host {ip: $ip})<-[:SRC]-(s:Session)-[:DST]->(dst:Host)
                WHERE s.has_alert = true
                RETURN dst.ip AS dest_ip,
                       count(s) AS attack_count,
                       min(s.severity) AS min_severity
                ORDER BY attack_count DESC
                LIMIT 5
                """, ip=src_ip).data()
            
            # 3. 연관 공격자 (같은 Signature를 트리거한 다른 IP)
            related = session.run("""
                MATCH (h:Host {ip: $ip})<-[:SRC]-(s:Session)-[:TRIGGERED]->(sig:Signature)
                      <-[:TRIGGERED]-(s2:Session)-[:SRC]->(h2:Host)
                WHERE h2.ip <> $ip
                RETURN h2.ip AS related_ip,
                       count(DISTINCT sig) AS shared_alerts
                ORDER BY shared_alerts DESC
                LIMIT 5
                """, ip=src_ip).data()
            
            # 4. DNS 질의
            dns = session.run("""
                MATCH (h:Host {ip: $ip})<-[:SRC]-(s:Session)-[:QUERIES]->(d:Domain)
                RETURN d.domain AS domain
                LIMIT 10
                """, ip=src_ip).data()
            
            # 5. HTTP 접근
            urls = session.run("""
                MATCH (h:Host {ip: $ip})<-[:SRC]-(s:Session)-[:ACCESSES]->(u:URL)
                RETURN u.url AS url
                LIMIT 10
                """, ip=src_ip).data()

        return {
            "src_ip":            src_ip,
            "alerts":            alerts,
            "targeted_ips":      targets,
            "related_attackers": related,
            "dns_queries":       [d["domain"] for d in dns],
            "http_urls":         [u["url"] for u in urls],
            "found":             len(alerts) > 0 or len(targets) > 0,
        }

    def get_ip_history(self, src_ip: str) -> Dict[str, Any]:
        """IP의 과거 이력 조회"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (h:Host {ip: $ip})<-[:SRC]-(s:Session)-[:TRIGGERED]->(sig:Signature)
                RETURN count(s) AS total_alerts,
                       min(sig.severity) AS highest_severity,
                       collect(DISTINCT sig.category) AS categories
                """, ip=src_ip).data()

        if not result or result[0]["total_alerts"] == 0:
            return {"src_ip": src_ip, "known": False}

        row = result[0]
        return {
            "src_ip":           src_ip,
            "known":            True,
            "total_alerts":     row["total_alerts"],
            "highest_severity": row["highest_severity"],
            "tactics":          [],  # 필요시 추가
            "cves":             [],  # 필요시 추가
        }
    
    def get_flow_with_alerts(self, limit: int = 10) -> List[Dict]:
        """Alert가 있는 Flow 조회"""
        with self.driver.session() as session:
            results = session.run("""
                MATCH (s:Session {has_alert: true})-[:SRC]->(src:Host)
                MATCH (s)-[:DST]->(dst:Host)
                MATCH (s)-[:TRIGGERED]->(sig:Signature)
                RETURN s.id AS session_id,
                       s.timestamp AS timestamp,
                       src.ip AS src_ip,
                       dst.ip AS dst_ip,
                       sig.signature AS signature,
                       sig.severity AS severity
                ORDER BY s.timestamp DESC
                LIMIT $limit
                """, limit=limit).data()
        
        return results

