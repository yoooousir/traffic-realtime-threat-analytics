"""
CTI 위협 분석 대시보드
- S3 rag_result/dt={today}/ 하위 전체 JSONL 실시간 로드 (30초 자동 갱신)
- 검색: 날짜, IP, threat_type, 키워드
- 위협 점수 상/중/하 탭 분류 (상: 80+, 중: 60~80, 하: ~60)
- 위협 분석 보고서: pagination 10개씩, 화살표 버튼
- 세션 상세 정보: 상/중/하 라디오 필터, threat_score 내림차순, 20개씩 숫자 버튼 페이지네이션
"""

import json
import os
import tempfile
from datetime import datetime, timedelta

import boto3
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from pyvis.network import Network

# ── 환경 변수 ─────────────────────────────────────────────────────────────────
load_dotenv()
S3_BUCKET_NAME  = os.getenv("S3_BUCKET_NAME", "malware-project-bucket")
S3_RAG_PREFIX   = os.getenv("S3_RAG_PREFIX", "rag_result")
KST_TZ          = "Asia/Seoul"
AUTO_REFRESH_SEC = 30

# ── 페이지 설정 ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CTI 위협 분석 대시보드",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── 커스텀 CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Noto+Sans+KR:wght@300;400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Noto Sans KR', sans-serif;
}
code, pre, .mono {
    font-family: 'JetBrains Mono', monospace !important;
}

/* 위협 등급 배지 */
.badge-high   { background:#ff4444; color:#fff; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600; }
.badge-mid    { background:#ff9900; color:#fff; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600; }
.badge-low    { background:#44aa44; color:#fff; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600; }

/* 페이지네이션 버튼 */
.page-btn { display:inline-block; margin:0 3px; }

/* 화살표 영역 */
.arrow-col button { background:transparent !important; border:none !important; font-size:28px !important; }

/* 섹션 헤더 */
.section-header {
    font-size: 18px;
    font-weight: 700;
    border-left: 4px solid #4A90D9;
    padding-left: 10px;
    margin: 20px 0 12px 0;
}
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# S3 데이터 로드
# ══════════════════════════════════════════════════════════════════════════════

@st.cache_data(ttl=AUTO_REFRESH_SEC)
def load_all_rag_results(date_str: str) -> list[dict]:
    """
    s3://bucket/rag_result/dt={date_str}/hour=*_minute=*_rag_results.jsonl
    해당 날짜의 모든 JSONL 파일을 로드해 합침.
    """
    s3        = boto3.client("s3")
    prefix    = f"{S3_RAG_PREFIX}/dt={date_str}/"
    paginator = s3.get_paginator("list_objects_v2")

    keys: list[str] = []
    try:
        for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith(".jsonl"):
                    keys.append(key)
    except Exception as e:
        st.error(f"S3 목록 조회 실패: {e}")
        return []

    records: list[dict] = []
    for key in sorted(keys):
        try:
            obj  = s3.get_object(Bucket=S3_BUCKET_NAME, Key=key)
            body = obj["Body"].read().decode("utf-8").splitlines()
            for line in body:
                if line.strip():
                    records.append(json.loads(line))
        except Exception as e:
            st.warning(f"파일 로드 실패 ({key}): {e}")

    return records


# ══════════════════════════════════════════════════════════════════════════════
# 헬퍼 함수
# ══════════════════════════════════════════════════════════════════════════════

def _fmt_ts(ts_str) -> str:
    if not ts_str:
        return "–"
    try:
        return pd.Timestamp(ts_str).tz_convert(KST_TZ).strftime("%m-%d %H:%M:%S")
    except Exception:
        return str(ts_str)[:19].replace("T", " ")


def _fmt_bytes(b) -> str:
    if b is None:
        return "–"
    try:
        b = int(b)
    except Exception:
        return "–"
    if b >= 1_048_576:
        return f"{b / 1_048_576:.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b} B"


def _score_to_grade(score: float) -> str:
    if score >= 80:
        return "상"
    if score >= 60:
        return "중"
    return "하"


def _grade_badge(grade: str) -> str:
    cls = {"상": "badge-high", "중": "badge-mid", "하": "badge-low"}.get(grade, "badge-low")
    return f'<span class="{cls}">{grade}</span>'


def _normalize_score(raw_score) -> float:
    """threat_score(0~100 범위) 정규화."""
    try:
        s = float(raw_score) / 80 * 100
        return min(s, 100.0)
    except Exception:
        return 0.0


REL_LABEL = {
    "ORIGINATED_FROM": "출발지 IP",
    "CONNECTED_TO":    "목적지 IP",
    "TRIGGERED":       "Alert 발생",
    "ENCRYPTED_WITH":  "암호화 방식",
    "SERVED_OVER_TLS": "TLS 도메인",
    "REQUESTED":       "요청 도메인",
}

NODE_COLOR = {
    "Session": "#4A90D9",
    "IP":      "#F5A623",
    "Alert":   "#D0021B",
    "Cipher":  "#7ED321",
    "Domain":  "#9B59B6",
}


# ══════════════════════════════════════════════════════════════════════════════
# 데이터 가공
# ══════════════════════════════════════════════════════════════════════════════

def build_dataframe(records: list[dict]) -> pd.DataFrame:
    rows = []
    for r in records:
        session   = r.get("session", {})
        analysis  = r.get("analysis", {})
        neighbors = r.get("neighbors", [])

        raw_score    = analysis.get("threat_score", 0)
        threat_score = _normalize_score(raw_score)
        grade        = _score_to_grade(threat_score)

        rows.append({
            "uid":               r.get("uid", "–"),
            "inference_datetime": r.get("inference_datetime", "–"),
            "ts":                session.get("ts", "–"),
            "src_ip":            session.get("src_ip", "–"),
            "dest_ip":           session.get("dest_ip", "–"),
            "dest_port":         session.get("dest_port", "–"),
            "proto":             session.get("proto", "–"),
            "threat_type":       analysis.get("threat_type", "Unknown"),
            "summary":           analysis.get("summary", "–"),
            "recommended_action": analysis.get("recommended_action", "–"),
            "threat_score":      threat_score,
            "grade":             grade,
            "_session":          session,
            "_neighbors":        neighbors,
            "_analysis":         analysis,
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("threat_score", ascending=False).reset_index(drop=True)
    return df


# ══════════════════════════════════════════════════════════════════════════════
# 컴포넌트: neighbor 카드
# ══════════════════════════════════════════════════════════════════════════════

def _render_neighbor_cards(neighbors: list[dict]):
    if not neighbors:
        st.caption("Neo4j 연관 데이터 없음 (신규 세션)")
        return

    groups: dict[str, list[dict]] = {}
    for nb in neighbors:
        rt = nb.get("rel_type", "UNKNOWN")
        groups.setdefault(rt, []).append(nb)

    for rel_type, nbs in groups.items():
        st.markdown(f"**{REL_LABEL.get(rel_type, rel_type)}**")
        for nb in nbs:
            node_label = (nb.get("node_labels") or ["?"])[0]
            value      = nb.get("node_value", "–")
            with st.container(border=True):
                if node_label == "IP":
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(f"`{value}`")
                        st.caption(f"연관 세션: **{nb.get('related_session_count','–')}**")
                    with c2:
                        st.caption(f"첫 등장: {_fmt_ts(nb.get('first_seen'))}")
                        st.caption(f"최근 등장: {_fmt_ts(nb.get('last_seen'))}")
                    st.caption(
                        f"송신: {_fmt_bytes(nb.get('total_orig_bytes'))} / "
                        f"수신: {_fmt_bytes(nb.get('total_resp_bytes'))}"
                    )
                elif node_label == "Alert":
                    st.markdown(f"`{nb.get('signature','–')}`")
                    st.caption(f"카테고리: {nb.get('category','–')}")
                    st.caption(
                        f"영향 세션: **{nb.get('related_session_count','–')}** | "
                        f"첫 발생: {_fmt_ts(nb.get('first_seen'))} | "
                        f"최근 발생: {_fmt_ts(nb.get('last_seen'))}"
                    )
                elif node_label == "Cipher":
                    st.markdown(f"`{value}`")
                else:
                    st.markdown(f"`{node_label}` : `{value}`")


# ══════════════════════════════════════════════════════════════════════════════
# 컴포넌트: pyvis 그래프
# ══════════════════════════════════════════════════════════════════════════════

def _render_graph(session: dict, neighbors: list[dict]):
    net = Network(
        height="420px", width="100%",
        bgcolor="#1a1a2e", font_color="white", directed=True,
    )
    net.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=120)

    session_id = session.get("session_id", "session")
    net.add_node(
        session_id,
        label=f"{session_id}\n{session.get('src_ip','?')} → {session.get('dest_ip','?')}",
        color=NODE_COLOR["Session"], size=28,
        title=(
            f"세션 ID: {session_id}\n"
            f"출발지: {session.get('src_ip')} : {session.get('src_port')}\n"
            f"목적지: {session.get('dest_ip')} : {session.get('dest_port')}\n"
            f"프로토콜: {session.get('proto')}\n"
            f"Alert 수: {session.get('alert_count')}\n"
            f"최고 위험도: {session.get('max_severity')}\n"
            f"연결 상태: {session.get('conn_state')}"
        ),
        shape="box",
    )

    added: set[str] = set()
    for nb in neighbors:
        node_label = (nb.get("node_labels") or ["?"])[0]
        node_value = str(nb.get("node_value") or "?")
        rel_type   = nb.get("rel_type", "")
        node_id    = f"{node_label}_{node_value}"
        color      = NODE_COLOR.get(node_label, "#888888")

        if node_label == "IP":
            tooltip      = (
                f"IP: {node_value}\n"
                f"연관 세션: {nb.get('related_session_count','–')}\n"
                f"첫 등장: {_fmt_ts(nb.get('first_seen'))}\n"
                f"최근 등장: {_fmt_ts(nb.get('last_seen'))}\n"
                f"송신: {_fmt_bytes(nb.get('total_orig_bytes'))} / "
                f"수신: {_fmt_bytes(nb.get('total_resp_bytes'))}"
            )
            display_label = node_value
        elif node_label == "Alert":
            sig           = nb.get("signature", node_value)
            display_label = sig if len(sig) <= 30 else sig[:28] + "…"
            tooltip       = (
                f"시그니처: {sig}\n"
                f"카테고리: {nb.get('category','–')}\n"
                f"영향 세션: {nb.get('related_session_count','–')}\n"
                f"첫 발생: {_fmt_ts(nb.get('first_seen'))}\n"
                f"최근 발생: {_fmt_ts(nb.get('last_seen'))}"
            )
        else:
            tooltip       = f"{node_label}: {node_value}"
            display_label = node_value

        if node_id not in added:
            net.add_node(
                node_id, label=display_label, color=color,
                size=20, title=tooltip, shape="ellipse",
            )
            added.add(node_id)

        edge_label = REL_LABEL.get(rel_type, rel_type)
        if rel_type in ("ORIGINATED_FROM", "ENCRYPTED_WITH"):
            net.add_edge(node_id, session_id, label=edge_label, color="#aaaaaa", font_size=9)
        else:
            net.add_edge(session_id, node_id, label=edge_label, color="#aaaaaa", font_size=9)

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        net.save_graph(f.name)
        html_content = open(f.name).read()
    st.components.v1.html(html_content, height=440, scrolling=False)


# ══════════════════════════════════════════════════════════════════════════════
# 컴포넌트: 세션 expander
# ══════════════════════════════════════════════════════════════════════════════

def _render_session_expander(row: pd.Series, idx: int):
    grade        = row["grade"]
    badge_html   = _grade_badge(grade)
    score_display = f"{round(row['threat_score'], 1)}점"
    label = f"[{idx+1}] {row['uid']} — {row['threat_type']}"

    with st.expander(label):
        st.markdown(
            f"{badge_html} &nbsp; 위협 점수: **{score_display}**",
            unsafe_allow_html=True,
        )
        session   = row["_session"]
        neighbors = row["_neighbors"] or []

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**분석 결과**")
            st.write("**위협 유형:**", row["threat_type"])
            st.write("**요약:**", row["summary"])
            st.write("**권고 조치:**", row["recommended_action"])
            st.write("**추론 시각:**", _fmt_ts(row["inference_datetime"]))
        with col2:
            st.markdown("**세션 정보**")
            st.json(session)

        if neighbors:
            st.divider()
            st.markdown("**연관 흐름 정보** (Neo4j 1-hop)")
            tab_card, tab_graph = st.tabs(["📋 목록", "🕸️ 그래프"])
            with tab_card:
                _render_neighbor_cards(neighbors)
            with tab_graph:
                _render_graph(session, neighbors)


# ══════════════════════════════════════════════════════════════════════════════
# 사이드바: 날짜 선택 + 검색 필터
# ══════════════════════════════════════════════════════════════════════════════
# 사이드바 상단: 날짜 선택만 먼저
with st.sidebar:
    st.markdown("### 🛡️ Threat Detection Dashboard")
    st.divider()

    # 날짜 선택
    today_kst = pd.Timestamp.now(tz=KST_TZ)
    selected_date = st.date_input(
        "📅 분석 날짜",
        value=today_kst.date(),
        max_value=today_kst.date(),
    )
    date_str = selected_date.strftime("%Y-%m-%d")

# ── 데이터 로드 ───────────────────────────────────────────────────────────────
with st.spinner(f"{date_str} 데이터 로드 중..."):
    raw_records = load_all_rag_results(date_str)

if not raw_records:
    st.info(f"📭 {date_str} 날짜의 RAG 결과가 없습니다.")
    st.stop()

df_all = build_dataframe(raw_records)

# ── 사이드바 하단 (동적 필터) ─────────────────────────────────────────────────
with st.sidebar:
    st.divider()
    st.markdown("### 🔍 검색 필터")

    search_ip        = st.text_input("IP 주소", placeholder="예: 192.168.1.1")
    
    # 동적 위협 유형 리스트
    threat_types = ["전체"] + sorted(df_all["threat_type"].dropna().unique().tolist())
    search_threat = st.selectbox("위협 유형", options=threat_types)
    
    search_keyword   = st.text_input("키워드 (요약/권고)", placeholder="예: 포트스캔")
    search_grade     = st.multiselect(
        "위협 등급",
        options=["상", "중", "하"],
        default=["상", "중", "하"],
    )

    st.divider()
    st.caption(f"🔄 {AUTO_REFRESH_SEC}초마다 자동 갱신")
    if st.button("🔄 지금 새로고침"):
        st.cache_data.clear()
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# 데이터 로드 + 필터링
# ══════════════════════════════════════════════════════════════════════════════

with st.spinner(f"{date_str} 데이터 로드 중..."):
    raw_records = load_all_rag_results(date_str)

if not raw_records:
    st.info(f"📭 {date_str} 날짜의 RAG 결과가 없습니다.")
    st.stop()

df_all = build_dataframe(raw_records)

# 필터 적용
df_filtered = df_all.copy()

if search_ip:
    mask = (
        df_filtered["src_ip"].astype(str).str.contains(search_ip, na=False) |
        df_filtered["dest_ip"].astype(str).str.contains(search_ip, na=False)
    )
    df_filtered = df_filtered[mask]

if search_threat != "전체":
    df_filtered = df_filtered[df_filtered["threat_type"] == search_threat]

if search_keyword:
    mask = (
        df_filtered["summary"].astype(str).str.contains(search_keyword, na=False) |
        df_filtered["recommended_action"].astype(str).str.contains(search_keyword, na=False)
    )
    df_filtered = df_filtered[mask]

if search_grade:
    df_filtered = df_filtered[df_filtered["grade"].isin(search_grade)]

df_filtered = df_filtered.reset_index(drop=True)


# ══════════════════════════════════════════════════════════════════════════════
# 헤더 + 요약 지표
# ══════════════════════════════════════════════════════════════════════════════

st.title(f"🛡️ {date_str} 위협 분석 보고서")
st.caption(
    f"총 {len(df_all)}건 로드 | 필터 후 {len(df_filtered)}건 표시 | "
    f"마지막 갱신: {pd.Timestamp.now(tz=KST_TZ).strftime('%H:%M:%S')} KST"
)

col_h, col_m, col_l, col_t = st.columns(4)
with col_h:
    n_high = len(df_filtered[df_filtered["grade"] == "상"])
    st.metric("🔴 상 (80점+)", n_high)
with col_m:
    n_mid = len(df_filtered[df_filtered["grade"] == "중"])
    st.metric("🟡 중 (60~80점)", n_mid)
with col_l:
    n_low = len(df_filtered[df_filtered["grade"] == "하"])
    st.metric("🟢 하 (~60점)", n_low)
with col_t:
    avg_score = df_filtered["threat_score"].mean() if not df_filtered.empty else 0
    st.metric("📊 평균 위협 점수", f"{avg_score:.1f}점")

st.divider()


# ══════════════════════════════════════════════════════════════════════════════
# 위협 유형 분포 (Group By)
# ══════════════════════════════════════════════════════════════════════════════

with st.expander("📊 위협 유형 분포 보기", expanded=False):
    if not df_filtered.empty:
        threat_counts = (
            df_filtered.groupby("threat_type")
            .agg(건수=("threat_score", "count"), 평균점수=("threat_score", "mean"))
            .sort_values("건수", ascending=False)
            .reset_index()
        )
        threat_counts["평균점수"] = threat_counts["평균점수"].round(1)
        st.dataframe(threat_counts, use_container_width=True, hide_index=True)
    else:
        st.caption("데이터 없음")

st.divider()


# ══════════════════════════════════════════════════════════════════════════════
# 섹션 1: 위협 분석 보고서 (pagination 10개, 화살표)
# ══════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="section-header">📋 위협 분석 보고서</div>', unsafe_allow_html=True)

REPORT_PAGE_SIZE = 10

if df_filtered.empty:
    st.info("표시할 결과가 없습니다.")
else:
    total_report_pages = max(1, (len(df_filtered) - 1) // REPORT_PAGE_SIZE + 1)

    if "report_page" not in st.session_state:
        st.session_state["report_page"] = 0

    # 화살표 버튼 (상단)
    col_prev, col_info, col_next = st.columns([1, 4, 1])
    with col_prev:
        if st.button("◀", key="report_prev_top", disabled=st.session_state["report_page"] == 0):
            st.session_state["report_page"] -= 1
            st.rerun()
    with col_info:
        st.markdown(
            f"<div style='text-align:center; padding-top:6px;'>"
            f"페이지 <b>{st.session_state['report_page']+1}</b> / {total_report_pages}"
            f"&nbsp;&nbsp;(총 {len(df_filtered)}건)"
            f"</div>",
            unsafe_allow_html=True,
        )
    with col_next:
        if st.button("▶", key="report_next_top",
                     disabled=st.session_state["report_page"] >= total_report_pages - 1):
            st.session_state["report_page"] += 1
            st.rerun()

    # 현재 페이지 데이터
    start = st.session_state["report_page"] * REPORT_PAGE_SIZE
    end   = start + REPORT_PAGE_SIZE
    df_page = df_filtered.iloc[start:end]

    # 테이블 표시
    display_cols = {
        "uid":          "UID",
        "ts":           "세션 시각",
        "src_ip":       "출발지 IP",
        "dest_ip":      "목적지 IP",
        "threat_type":  "위협 유형",
        "grade":        "등급",
        "threat_score": "점수",
        "summary":      "요약",
        "recommended_action": "권고 조치",
    }
    df_display = df_page[list(display_cols.keys())].rename(columns=display_cols)
    df_display["세션 시각"] = df_display["세션 시각"].apply(_fmt_ts)
    df_display["점수"]      = df_display["점수"].round(1)
    st.dataframe(df_display, use_container_width=True, hide_index=True)

    # 화살표 버튼 (하단)
    col_prev2, col_mid2, col_next2 = st.columns([1, 4, 1])
    with col_prev2:
        if st.button("◀", key="report_prev_bot", disabled=st.session_state["report_page"] == 0):
            st.session_state["report_page"] -= 1
            st.rerun()
    with col_mid2:
        st.markdown(
            f"<div style='text-align:center; padding-top:6px;'>"
            f"페이지 <b>{st.session_state['report_page']+1}</b> / {total_report_pages}"
            f"</div>",
            unsafe_allow_html=True,
        )
    with col_next2:
        if st.button("▶", key="report_next_bot",
                     disabled=st.session_state["report_page"] >= total_report_pages - 1):
            st.session_state["report_page"] += 1
            st.rerun()

st.divider()


# ══════════════════════════════════════════════════════════════════════════════
# 섹션 2: 세션 상세 정보 (상/중/하 라디오, 20개씩 숫자 버튼)
# ══════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="section-header">🔬 세션 상세 정보</div>', unsafe_allow_html=True)

DETAIL_PAGE_SIZE = 20

grade_filter = st.radio(
    "위협 등급 필터",
    options=["전체", "상", "중", "하"],
    horizontal=True,
    key="detail_grade_radio",
)

if grade_filter == "전체":
    df_detail = df_filtered.copy()
else:
    df_detail = df_filtered[df_filtered["grade"] == grade_filter].copy()

df_detail = df_detail.reset_index(drop=True)

if df_detail.empty:
    st.info("해당 등급의 세션이 없습니다.")
else:
    total_detail_pages = max(1, (len(df_detail) - 1) // DETAIL_PAGE_SIZE + 1)

    detail_page_key = f"detail_page_{grade_filter}"
    if detail_page_key not in st.session_state:
        st.session_state[detail_page_key] = 0

    current_page = st.session_state[detail_page_key]
    if current_page >= total_detail_pages:
        current_page = 0
        st.session_state[detail_page_key] = 0

    # 숫자 버튼 페이지네이션
    st.markdown(
        f"<div style='margin-bottom:8px; color:#888;'>"
        f"총 {len(df_detail)}건 | 페이지 {current_page+1}/{total_detail_pages}"
        f"</div>",
        unsafe_allow_html=True,
    )

    # 숫자 버튼 (최대 10개씩 표시)
    MAX_BTN = 10
    btn_start = max(0, current_page - MAX_BTN // 2)
    btn_end   = min(total_detail_pages, btn_start + MAX_BTN)
    btn_start = max(0, btn_end - MAX_BTN)

    btn_cols = st.columns(min(total_detail_pages, MAX_BTN) + 2)
    # 이전 버튼
    with btn_cols[0]:
        if st.button("◀", key=f"det_prev_{grade_filter}",
                     disabled=current_page == 0):
            st.session_state[detail_page_key] -= 1
            st.rerun()

    for i, page_num in enumerate(range(btn_start, btn_end)):
        with btn_cols[i + 1]:
            label    = str(page_num + 1)
            is_cur   = page_num == current_page
            btn_type = "primary" if is_cur else "secondary"
            if st.button(label, key=f"det_pg_{grade_filter}_{page_num}", type=btn_type):
                st.session_state[detail_page_key] = page_num
                st.rerun()

    # 다음 버튼
    with btn_cols[min(total_detail_pages, MAX_BTN) + 1]:
        if st.button("▶", key=f"det_next_{grade_filter}",
                     disabled=current_page >= total_detail_pages - 1):
            st.session_state[detail_page_key] += 1
            st.rerun()

    # 현재 페이지 세션 표시
    start = current_page * DETAIL_PAGE_SIZE
    end   = start + DETAIL_PAGE_SIZE
    df_page_detail = df_detail.iloc[start:end]

    for local_idx, (_, row) in enumerate(df_page_detail.iterrows()):
        global_idx = start + local_idx
        _render_session_expander(row, global_idx)

# ══════════════════════════════════════════════════════════════════════════════
# 자동 갱신 (30초)
# ══════════════════════════════════════════════════════════════════════════════

# st_autorefresh 없이 meta refresh로 구현
st.markdown(
    f"""
    <script>
    setTimeout(function() {{
        window.location.reload();
    }}, {AUTO_REFRESH_SEC * 1000});
    </script>
    """,
    unsafe_allow_html=True,
)