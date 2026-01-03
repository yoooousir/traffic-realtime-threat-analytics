# Honeypot-Based Threat Detection System

AWS 기반 허니팟 네트워크 구축 및 머신러닝 기반 위협 탐지 시스템

## 프로젝트 개요

실시간 네트워크 공격 데이터를 수집하고, 머신러닝 모델을 통해 자동으로 위협을 탐지/분류하는 시스템

## 아키텍처
```
Data Collection → Threat Intel → ML Pipeline → Visualization
    ↓                 ↓              ↓              ↓
  T-Pot            MISP          Airflow        Kibana
  Zeek             CAPEv2        ClickHouse
  Suricata                       ML Models
```


## 빠른 시작

### 1. 저장소 클론
```bash
git clone https://github.com/yoooousir/traffic-realtime-threat-analytics.git
cd traffic-realtime-threat-analytics
```

### 2. AWS 인프라 설정
```bash
# AWS EC2 접속
ssh -i your-key.pem -p 64295 ubuntu@your-ec2-ip

# 프로젝트 클론
git clone https://github.com/yoooousir/traffic-realtime-threat-analytics.git
cd traffic-realtime-threat-analytics
```

### 3. T-Pot 설치
```bash
bash scripts/setup/install-tpot.sh
```

## 접속 정보

- **T-Pot Dashboard**: https://[EC2-IP]:64297
- **SSH**: ssh -p 64295 ubuntu@[EC2-IP]
- **Kibana**: (추후 추가)

## 문서

- [아키텍처 설계](docs/architecture.md)
- [설치 가이드](docs/setup-guide.md)
- [API 문서](docs/api-docs.md)

## 라이선스

MIT License
