import boto3
import pandas as pd
from fastavro import writer, parse_schema
import io
import math
import avro_schema

'''
awscli 설치 후
aws configure 명령어로 AWS 자격 증명과 기본 리전 설정
AWS_ACCESS_KEY_ID와 AWS_SECRET_ACCESS_KEY 환경 변수를 설정하여 AWS 자격 증명 제공해도 됨
'''

def load_and_save_parquets_from_s3(bucket_name, prefix, save_path):

    # s3 접속하기
    s3 = boto3.client('s3')

    # prefix 아래 모든 객체 목록 조회
    paginator = s3.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

    dfs = []
    turn_cnt = 0
    row_len = 0
    for page in pages:
        turn_cnt += 1
        for obj in page.get('Contents', []):
            key = obj['Key']
            if key.endswith('.parquet'):
                print(f"읽는 중: {key}")
                response = s3.get_object(Bucket=bucket_name, Key=key)
                df = pd.read_parquet(io.BytesIO(response['Body'].read()))
                dfs.append(df)
            row_len += len(df)
            if row_len >= 100000:
                break
        if turn_cnt == 1:
            break  # 첫 페이지까지만 읽도록 설정 (테스트용)
    
    #return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
    if dfs:
        result_df = pd.concat(dfs, ignore_index=True)
        result_df.to_csv(save_path, index=False, encoding='utf-8-sig')  # utf-8-sig: 엑셀에서 한글 깨짐 방지
        print(f"저장 완료: {save_path} ({len(result_df)} rows)")
        return result_df
    else:
        print(f"파일 없음: {prefix}")
        return pd.DataFrame()

def clean_value(v):
    """NaN float → None, 나머지는 str로 통일"""
    if isinstance(v, float) and math.isnan(v):
        return None
    return str(v) if v is not None else None

def convert_csv_to_avro(csv_path, avro_schema, avro_path):
    df = pd.read_csv(csv_path)
    schema = parse_schema(avro_schema)
    with open(avro_path, 'wb') as f:
        writer(f, schema, df.to_dict('records'))
    print(f"변환 완료: {avro_path} ({len(df)} rows)")

def convert_parquet_to_avro(parquet_path, avro_schema, avro_path):
    df = pd.read_parquet(parquet_path)
    schema = parse_schema(avro_schema)
    with open(avro_path, 'wb') as f:
        writer(f, schema, df.to_dict('records'))
    print(f"변환 완료: {avro_path} ({len(df)} rows)")



bucket_name = 'malware-project-bucket'
base_path = 'honeypot/raw/'
save_csv_dir = 'csv_files'
save_avro_dir = 'avro_files'

# df_suricata  = load_and_save_parquets_from_s3(bucket_name, base_path + 'suricata/',    save_csv_dir + '/suricata.csv')
# df_zeek_conn = load_and_save_parquets_from_s3(bucket_name, base_path + 'zeek/conn/',  save_csv_dir + '/zeek_conn.csv')
# df_zeek_dns  = load_and_save_parquets_from_s3(bucket_name, base_path + 'zeek/dns/',   save_csv_dir + '/zeek_dns.csv')
# df_zeek_http = load_and_save_parquets_from_s3(bucket_name, base_path + 'zeek/http/',  save_csv_dir + '/zeek_http.csv')

# # 데이터프레임 크기 확인하기
# suricata_df = pd.read_csv(save_csv_dir + '/suricata.csv')
# zeek_conn_df = pd.read_csv(save_csv_dir + '/zeek_conn.csv')
# zeek_dns_df = pd.read_csv(save_csv_dir + '/zeek_dns.csv') 
# zeek_http_df = pd.read_csv(save_csv_dir + '/zeek_http.csv')
# print(f"suricata_df: {len(suricata_df)} rows")
# print(f"zeek_conn_df: {len(zeek_conn_df)} rows")
# print(f"zeek_dns_df: {len(zeek_dns_df)} rows")
# print(f"zeek_http_df: {len(zeek_http_df)} rows")

# zeek_conn의 service필드에 clean_value 적용
zeek_conn_df = pd.read_csv(save_csv_dir + '/zeek_conn.csv')
zeek_conn_df['service'] = zeek_conn_df['service'].apply(clean_value)
zeek_conn_df.to_csv(save_csv_dir + '/zeek_conn.csv', index=False, encoding='utf-8-sig')

#convert_csv_to_avro(save_csv_dir + '/suricata.csv', avro_schema.SURICATA_AVRO_SCHEMA, save_avro_dir + '/suricata.avro')
convert_csv_to_avro(save_csv_dir + '/zeek_conn.csv', avro_schema.ZEEK_CONN_AVRO_SCHEMA, save_avro_dir + '/zeek_conn.avro')
convert_csv_to_avro(save_csv_dir + '/zeek_dns.csv', avro_schema.ZEEK_DNS_AVRO_SCHEMA, save_avro_dir + '/zeek_dns.avro')
convert_csv_to_avro(save_csv_dir + '/zeek_http.csv', avro_schema.ZEEK_HTTP_AVRO_SCHEMA, save_avro_dir + '/zeek_http.avro')