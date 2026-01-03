# 시스템 아키텍처

## 전체 구조

### Phase 1: 데이터 수집 (Week 1-2)
- T-Pot: 다중 허니팟 플랫폼
- Zeek: 네트워크 트래픽 분석
- Suricata: IDS/IPS
- Filebeat: 로그 수집

### Phase 2: 위협 인텔리전스 (Week 2-3)
- MISP: 위협 정보 공유 플랫폼
- CAPEv2: 악성코드 샌드박스 분석

### Phase 3: ML 파이프라인 (Week 3-4)
- Airflow: 워크플로우 오케스트레이션
- ClickHouse: 고성능 데이터베이스
- ML Models: 공격 탐지/분류 모델

### Phase 4: 시각화 (Week 4)
- Kibana: 실시간 대시보드
- Custom Dashboards: 분석 결과 시각화

## 데이터 플로우
```
Honeypots → Zeek/Suricata → Filebeat → ClickHouse
                                            ↓
                                         Airflow
                                            ↓
                                        ML Models
                                            ↓
                                           MISP
                                            ↓
                                          CAPEv2
                                            ↓
                                          Kibana
```

## 기술 스택

- **Infrastructure**: AWS EC2, Docker
- **Data Collection**: T-Pot, Zeek, Suricata
- **Storage**: ClickHouse, Elasticsearch
- **Processing**: Airflow, Python, Pandas
- **ML**: TensorFlow, PyTorch, Scikit-learn
- **Visualization**: Kibana, Matplotlib
