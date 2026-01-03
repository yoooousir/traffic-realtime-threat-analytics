# 설치 가이드

## AWS EC2 인스턴스 생성

### 1. EC2 인스턴스 설정
```
AMI: Ubuntu 22.04 LTS
Instance Type: t3.xlarge (권장) 또는 t3.large (최소)
Storage: 128GB gp3
```

### 2. 보안 그룹 설정

- 관리 포트: 64295 (SSH), 64297 (Web UI) → 본인 IP만
- 허니팟 포트: 22, 80, 443 등 → 0.0.0.0/0

### 3. 키페어 다운로드

- your-key.pem 다운로드 및 안전한 곳에 보관
- `chmod 400 your-key.pem` 실행

## T-Pot 설치

### 방법 1: 자동 설치
```bash
# EC2 접속
ssh -i your-key.pem ubuntu@your-ec2-ip

# 프로젝트 클론
git clone https://github.com/yourusername/honeypot-threat-detection.git
cd honeypot-threat-detection

# 설치 스크립트 실행
bash scripts/setup/install-tpot.sh
```

### 방법 2: 수동 설치
```bash
cd /opt
sudo git clone https://github.com/telekom-security/tpotce
cd tpotce
sudo ./install.sh
# STANDARD 선택
# 계정 정보 입력
sudo reboot
```

## 설치 후 확인
```bash
# SSH 재접속 (포트 변경됨!)
ssh -i your-key.pem -p 64295 ubuntu@your-ec2-ip

# Docker 확인
sudo docker ps

# 웹 UI 접속
https://your-ec2-ip:64297
```

## 다음 단계

- [ ] MISP 설치
- [ ] CAPEv2 설치
- [ ] Zeek 설치
