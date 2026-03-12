각 태스크의 역할은 다음과 같습니다.
validate_input — 파일 존재 및 빈 파일 여부 확인, 행 수를 XCom으로 전달합니다.
extract_sessions — community_id 기반 SHA-1 앞 8자리로 session_id를 생성하고, timeline에서 zeek_conn → suricata 순으로 폴백하며 src/dst IP, http_host, uri, alert 통계를 추출합니다. 중복 community_id는 동일 session_id로 병합합니다.
extract_entities — session_gold와 timeline 원본을 함께 사용합니다. zeek_dns answers 필드에서 IPv4/CNAME을 파싱해 ip·domain entity를 등록하고, signature가 있는 suricata 이벤트만 alert entity로 집계합니다.
extract_relations — 4종 relation을 생성합니다. CONNECTED_TO(ip→ip), REQUESTED(ip→domain, HTTP host + DNS query), RESOLVED_BY(domain→ip/cname, DNS answers), TRIGGERED(session→alert). (src_type, src_value, relation_type, dst_type, dst_value, session_id) 6-tuple 기준으로 중복을 제거합니다.
report_stats — XCom으로 수집한 카운트와 각 gold 파일을 읽어 타입별 분포를 로그로 출력합니다.
경로는 /opt/airflow/data/ 기준이므로, 실제 환경에 맞게 INPUT_PATH와 OUTPUT_DIR 상단 상수를 수정하면 됩니다.
