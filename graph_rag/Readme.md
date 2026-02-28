# Graph RAG 기반 네트워크 보안 위협 분석 시스템

> Suricata + Zeek 네트워크 로그를 Session-Centric Graph로 구조화하고,  
> Neo4j 그래프 DB + LLM RAG를 통해 실시간 위협을 분석하는 파이프라인

---

## 목차

- [시스템 개요](#시스템-개요)
- [아키텍처](#아키텍처)
- [프로젝트 구조](#프로젝트-구조)
- [설치 및 환경 설정](#설치-및-환경-설정)
- [데이터 파이프라인](#데이터-파이프라인)
- [실행 방법](#실행-방법)
- [평가 및 최적화](#평가-및-최적화)
- [Neo4j 그래프 스키마](#neo4j-그래프-스키마)
- [주요 성능 지표](#주요-성능-지표)
- [트러블슈팅](#트러블슈팅)

---

## 시스템 개요

네트워크 트래픽 로그(Suricata IDS + Zeek NSM)를 Session 중심 그래프로 변환하여 Neo4j에 적재한 뒤, LLM(Groq/Gemini/OpenAI)을 통해 공격 행위를 분석하고 MITRE ATT&CK 기반의 위협 인텔리전스를 생성하는 시스템입니다.

**핵심 기능:**
- 다중 소스 로그 통합 (Suricata Flow/Alert, Zeek Conn/DNS/HTTP)
- Community ID 기반 Flow-Alert 자동 매핑
- Neo4j Session Graph 적재 및 쿼리
- LLM RAG 위협 분석 (할루시네이션 방지 강화)
- 모델 성능 비교 평가 (BLEU/ROUGE/속도/비용)
- 공격 경로 시각화 (NetworkX + Matplotlib)

---

## 아키텍처

```
[데이터 소스]
suricata_flows.csv  ─┐
suricata_alerts.csv ─┼─► [MultiSourceConverter] ──► unified_events.jsonl
zeek_conn.csv       ─┤         (schema.py)
zeek_dns.csv        ─┤    Community ID 매핑
zeek_http.csv       ─┘    Anomaly Score 계산

unified_events.jsonl ──► [Neo4jLoader] ──► Neo4j Graph DB
                        (neo4j_module.py)     Session/Host/Service
                                              Signature/Domain/URL 노드
                                              SRC/DST/TRIGGERED/QUERIES/ACCESSES 엣지

Neo4j Graph DB ──► [RAGExecutor] ──► Groq LLM ──► 위협 분석 JSON
                   (rag_module.py)   (llama-3.3-70b)  MITRE ATT&CK 매핑
                   그래프 컨텍스트                      대응 방안 생성
                   IP 이력 조회
```

---

## 프로젝트 구조

```
graph_rag/
├── graph_rag/                      # 메인 패키지
│   ├── main.py                     # CLI 진입점
│   ├── .env                        # API 키 설정
│   ├── requirements.txt
│   │
│   ├── preprocessor/
│   │   ├── preprocess.py           # CSV → JSONL 변환 파이프라인
│   │   └── schema.py               # Session-Centric 통합 스키마
│   │
│   ├── graph/
│   │   └── neo4j_module.py         # Neo4j 적재/조회
│   │
│   ├── rag/
│   │   └── rag_module.py           # LLM RAG 실행 (할루시네이션 방지)
│   │
│   ├── eval/
│   │   ├── model_evaluator.py      # LLM 모델 성능 비교
│   │   ├── prompt_optimizer.py     # 프롬프트 변형 자동 평가 (16개 조합)
│   │   └── graph_visualizer.py     # 공격 경로 PNG 시각화
│   │
│   ├── output/
│   │   ├── unified_events.jsonl    # 전처리된 통합 이벤트
│   │   ├── eval_results.json       # 모델 평가 결과
│   │   └── graphs/                 # 공격 경로 PNG
│   │
│   ├── suricata_flows.csv
│   ├── suricata_alerts.csv
│   ├── zeek_conn.csv
│   ├── zeek_dns.csv
│   └── zeek_http.csv
│
└── neo4j/                          # Neo4j Docker 설정
    ├── docker-compose.yaml         # Neo4j 5.26.0
    ├── data/
    ├── import/
    └── logs/
```

---

## 설치 및 환경 설정

### 요구사항

- Python 3.10+
- Docker + Docker Compose
- NVIDIA GPU (선택, Neo4j GPU 런타임용)

### 1. 패키지 설치

```bash
cd graph_rag/graph_rag
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Neo4j 실행

```bash
cd graph_rag/neo4j
docker compose up -d

# 상태 확인 (브라우저: http://localhost:7474)
```

### 3. 환경 변수 설정 (.env)

```env
NEO4J_PASSWORD=

GROQ_API_KEY=
GOOGLE_API_KEY=
OPENAI_API_KEY=
```

---

## 데이터 파이프라인

### 입력 데이터 형식

| 파일 | 설명 | 주요 컬럼 |
|------|------|-----------|
| `suricata_flows.csv` | IDS Flow 통계 | ts, src_ip, dest_ip, proto, community_id, pkts_*, bytes_* |
| `suricata_alerts.csv` | IDS 경보 | ts, src_ip, dest_ip, signature, category, severity, community_id |
| `zeek_conn.csv` | 연결 로그 | ts, orig_h, resp_h, proto, conn_state, orig_bytes, community_id |
| `zeek_dns.csv` | DNS 쿼리 | ts, orig_h, query, qtype_name, answers, community_id |
| `zeek_http.csv` | HTTP 요청 | ts, orig_h, method, host, uri, user_agent, community_id |

### Anomaly Score 계산 기준

| 조건 | 점수 | 탐지 대상 |
|------|------|-----------|
| Flow state 비정상 (bypassed 등) | +20 | 우회 흔적 |
| Flow state 누락 | +10 | 데이터 이상 |
| Timeout 종료 | +15 | SYN Flood, C2 장기 연결 |
| 단방향 트래픽 | +25 | 포트스캔, Null Session |
| 요청/응답 비율 극단 | +15~20 | DDoS, Exfiltration |
| UDP/ICMP 대용량 | +15 | Amplification Attack |
| 짧은 Duration + 대용량 | +10 | 자동화 공격 |

---

## 실행 방법

```bash
cd ~/traffic-realtime-threat-analytics/graph_rag/graph_rag
source .venv/bin/activate
```

### 전처리 및 Neo4j 적재

```bash
# 초기화 후 전체 재적재 (초기화 옵션: --clean)
python main.py preprocess --clean

# 적재 결과 확인하는 neo4j 쿼리
MATCH (n) RETURN labels(n)[0] as label, count(n) as cnt ORDER BY cnt DESC
```

### 위협 분석

```bash
# 단일 이벤트 분석
python main.py analyze

# 배치 분석 (severity 1~2)
python main.py batch

# 배치 분석 + 시각화
python main.py batch --visualize
```

### 모델 평가

```bash
# 전체 모델 비교 (3회 평균)
python main.py eval --trials 3

# 특정 모델만
python main.py eval \
  --models groq/llama-3.3-70b-versatile groq/llama-3.1-8b-instant \
  --trials 1
```

### 프롬프트 최적화

```bash
python main.py optimize \
  --target-model groq/llama-3.3-70b-versatile \
  --trials 2
```

### 공격 경로 시각화

```bash
# 특정 IP
python main.py visualize --src-ip 192.168.1.100 --layout spring

# 커스텀 쿼리
python main.py visualize \
  --cypher "MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 100"
```

---

## 평가 및 최적화

### 모델 평가 지표

| 지표 | 설명 |
|------|------|
| BLEU | 참조 답변과의 n-gram 겹침 (0~1) |
| ROUGE-1 | 단어 단위 겹침 (어휘 커버리지) |
| ROUGE-L | 최장 공통 부분 수열 기반 겹침 |
| 필드 | 필수 JSON 필드 7개 포함률 |
| JSON | 유효한 JSON 출력 여부 |
| 지연(s) | API 응답 시간 |
| 비용($) | 입출력 토큰 기반 USD 비용 |
| 종합 | 정확도 60% + 속도 20% + 비용 20% |

### 모델 평가 결과
[eval_results.json](/graph_rag/graph_rag/output/eval_results.json)

| 모델 | Bleu | R-1 | R-L | 필드 | Json | 지연(s) | 비용($) | 종합 |
|------|------|------|------|------|------|------|------|------|
| groq/llama-3.1-8b-instant | 0.1085 | 0.6818 | 0.4545 | 1.00 | T | 0.94 | 0.000079 | 0.7894 |
| groq/llama-3.3-70b-versatile | 0.0655 | 0.5561 | 0.4550 | 1.00 | T | 1.45 | 0.000890 | 0.7692 |
| gemini-2.0-flash (Google) | | | | | | | |
| gpt-4o-mini (OpenAI) | | | | | | | |

### 현재 최적 모델

```
groq/llama-3.3-8b-instant  (종합점수: 0.7894)
- Bleu: 0.1085
- ROUGE-1: 0.6818
- 응답 지연: 0.94s
- 비용: $0.000079/건
```

---

## Neo4j 그래프 스키마

### 노드

| 레이블 | 주요 속성 | 설명 |
|--------|-----------|------|
| Session | id, type, source, timestamp, severity, has_alert | 네트워크 세션 (중심 노드) |
| Host | id, ip | 출발지/목적지 IP |
| Service | id, address, ip, port, protocol | 네트워크 서비스 |
| Signature | id, signature, category, severity | IDS 탐지 시그니처 |
| Domain | id, domain | DNS 질의 도메인 |
| Url | id, url | HTTP 접근 URL |

### 관계

| 관계 | 방향 | 설명 |
|------|------|------|
| SRC | Session → Host | 출발지 IP |
| DST | Session → Host | 목적지 IP |
| TARGETS | Session → Service | 대상 서비스 |
| TRIGGERED | Session → Signature | IDS 경보 발생 |
| RUNS | Host → Service | 서비스 운영 |
| QUERIES | Session → Domain | DNS 질의 |
| ACCESSES | Session → Url | HTTP 접근 |
| RESOLVED_TO | Domain → Host | DNS 응답 IP |

### 유용한 Cypher 쿼리

```cypher
-- 공격 경보가 있는 세션 조회
MATCH (s:Session {has_alert: true})-[:SRC]->(h:Host)
MATCH (s)-[:TRIGGERED]->(sig:Signature)
RETURN h.ip, sig.signature, sig.category, s.timestamp
ORDER BY s.timestamp DESC LIMIT 20;

-- 특정 IP의 공격 이력
MATCH (h:Host {ip: '1.2.3.4'})<-[:SRC]-(s:Session)-[:TRIGGERED]->(sig:Signature)
RETURN sig.signature, sig.category, count(s) as cnt
ORDER BY cnt DESC;

-- 같은 시그니처를 공유하는 공격자 IP
MATCH (sig:Signature)<-[:TRIGGERED]-(s:Session)-[:SRC]->(h:Host)
WITH sig, collect(DISTINCT h.ip) as attackers
WHERE size(attackers) > 1
RETURN sig.signature, attackers;
```

---

## 주요 성능 지표

| 항목 | 수치 |
|------|------|
| 처리 건수 | ~35,000건 (Flow 10K + Zeek 30K) |
| Alert 매핑률 | ~776건 / 9,638 Flow (8%) |
| Neo4j Session 노드 | 25,337개 |
| Neo4j Host 노드 | 2,617개 |
| LLM 응답 속도 | 평균 0.87초 (Groq llama-3.3-70b) |
| 분석 비용 | ~$0.00067 / 건 |

---

## 트러블슈팅

### Neo4j 데이터가 비어있음

```bash
# Neo4j 버전 확인 (반드시 5.26.0 사용)
docker inspect neo4j | grep Image

# 권한 수정
sudo chown -R 7474:7474 ~/traffic-realtime-threat-analytics/graph_rag/neo4j/data
sudo chown -R 7474:7474 ~/traffic-realtime-threat-analytics/graph_rag/neo4j/logs
docker compose down && docker compose up -d
python main.py preprocess --clean
```

### TRIGGERED 관계 0개

```bash
docker exec -it neo4j cypher-shell -u neo4j -p lindaliam \
  "MATCH ()-[r:TRIGGERED]->() RETURN count(r)"
# 0이면 preprocess --clean 재실행
```

### suricata_flows 0건 변환

`schema.py`의 `calculate_anomaly_score`에서 타입 변환 중복 확인:
```python
# int() 변환이 한 번만 있어야 함 (중복 시 문자열로 덮어써짐)
pkts_toserver = int(float(row.get("pkts_toserver", 0) or 0))
```

### Gemini 429 오류

Free tier 일일 한도 초과. `gemini-2.0-flash-lite` 사용 권장:
```bash
python main.py eval --models groq/llama-3.3-70b-versatile gemini/gemini-2.0-flash-lite
```

### google-generativeai FutureWarning

```bash
uv pip uninstall google-generativeai
uv pip install google-genai
```
