import streamlit as st
import boto3
import json
import pandas as pd
from dotenv import load_dotenv
import os
import time

load_dotenv()

s3_client = boto3.client('s3')
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
S3_FILE_KEY = os.getenv("S3_FILE_KEY")

try:
    data = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=S3_FILE_KEY)
    # st.success("Data loaded successfully from S3!")
except Exception as e:
    st.error(f"Error loading data from S3: {e}")


# 오늘 날짜 (yyyy-mm-dd) 가져오기 (한국 시간대)
timezone = 'Asia/Seoul'
today = pd.Timestamp.now(tz=timezone).strftime('%Y-%m-%d')
st.title(f"{today} 위협 분석 보고서")

# jsonl 형식의 data 컬럼 가져오기
try:
    jsonl_data = data['Body'].read().decode('utf-8').splitlines()
    records = [json.loads(line) for line in jsonl_data if line.strip()]

    if not records:
        st.warning("No records found in the data.")
    else:
        rows = []
        for r in records:
            session  = r.get("session", {})
            analysis = r.get("analysis", {})
            threat_score = analysis.get("threat_score", 0) / 80 * 100
            rows.append({
                "uid":                         r.get("uid"),
                "session.ts":                  session.get("ts"),
                "session.community_id":        session.get("community_id"),
                "analysis.threat_type":        analysis.get("threat_type"),
                "analysis.summary":            analysis.get("summary"),
                "analysis.recommended_action": analysis.get("recommended_action"),
                #"analysis.threat_score":       analysis.get("threat_score"),
                "analysis.threat_score":       threat_score,
                "_session_meta":               session,
            })

        df = pd.DataFrame(rows)
        df = df.sort_values(by="analysis.threat_score", ascending=False).reset_index(drop=True)

        # 요약 테이블 (session 메타 제외)
        display_cols = [c for c in df.columns if not c.startswith("_")]
        st.dataframe(df[display_cols], use_container_width=True)

        st.divider()
        st.subheader("세션 상세 정보")

        for _, row in df.iterrows():
            label = (
                f"{row['uid']} — "
                f"{row['analysis.threat_type']} "
                f"[{round(row['analysis.threat_score'], 1)}점]"
            )
            with st.expander(label):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**분석 결과**")
                    st.write("**위협 유형:**", row["analysis.threat_type"])
                    st.write("**위협 점수:**", row["analysis.threat_score"])
                    st.write("**요약:**", row["analysis.summary"])
                    st.write("**권고 조치:**", row["analysis.recommended_action"])
                with col2:
                    st.markdown("**세션 정보**")
                    st.json(row["_session_meta"])

except Exception as e:
    st.error(f"Error processing data: {e}")