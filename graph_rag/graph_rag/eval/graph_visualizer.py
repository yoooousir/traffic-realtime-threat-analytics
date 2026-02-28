"""
eval/graph_visualizer.py
Neo4j 쿼리 응답 경로 시각화 모듈
- 특정 IP의 공격 컨텍스트 그래프를 PNG로 저장
- matplotlib + networkx 기반
"""

import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False
    logger.warning("networkx not available. pip install networkx")

try:
    import matplotlib
    matplotlib.use("Agg")   # 헤드리스 환경 (서버) 지원
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib import rcParams
    rcParams["font.family"] = "DejaVu Sans"
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False
    logger.warning("matplotlib not available. pip install matplotlib")


# ── 노드 타입별 스타일 ────────────────────────────────────

NODE_STYLES = {
    "Session":   {"color": "#4A90D9", "shape": "o",  "size": 1800, "zorder": 3},
    "Host":      {"color": "#E67E22", "shape": "s",  "size": 1200, "zorder": 2},
    "Service":   {"color": "#2ECC71", "shape": "D",  "size": 1000, "zorder": 2},
    "Signature": {"color": "#E74C3C", "shape": "^",  "size": 1400, "zorder": 3},
    "Domain":    {"color": "#9B59B6", "shape": "o",  "size": 1000, "zorder": 2},
    "URL":       {"color": "#1ABC9C", "shape": "p",  "size": 1000, "zorder": 2},
    "Unknown":   {"color": "#95A5A6", "shape": "o",  "size": 800,  "zorder": 1},
}

EDGE_STYLES = {
    "SRC":         {"color": "#3498DB", "style": "-",  "width": 2.0},
    "DST":         {"color": "#E67E22", "style": "-",  "width": 2.0},
    "TARGETS":     {"color": "#E74C3C", "style": "--", "width": 1.5},
    "TRIGGERED":   {"color": "#C0392B", "style": "-",  "width": 2.5},
    "RUNS":        {"color": "#27AE60", "style": ":",  "width": 1.5},
    "QUERIES":     {"color": "#8E44AD", "style": "--", "width": 1.5},
    "ACCESSES":    {"color": "#16A085", "style": "--", "width": 1.5},
    "RESOLVED_TO": {"color": "#7F8C8D", "style": ":",  "width": 1.0},
    "RELATED":     {"color": "#BDC3C7", "style": ":",  "width": 1.0},
}


def _truncate(text: str, max_len: int = 20) -> str:
    return text if len(text) <= max_len else text[:max_len - 2] + ".."


def _get_node_label(node_id: str, props: Dict) -> str:
    """노드 표시용 레이블 생성"""
    ntype = props.get("labels", ["Unknown"])[0] if props.get("labels") else "Unknown"
    if ntype == "Session":
        return f"Session\n{_truncate(node_id, 14)}"
    elif ntype == "Host":
        return props.get("ip", _truncate(node_id, 16))
    elif ntype == "Service":
        addr = props.get("address", "")
        return _truncate(addr, 18) if addr else _truncate(node_id, 16)
    elif ntype == "Signature":
        sig = props.get("signature", "")
        return _truncate(sig, 18) if sig else _truncate(node_id, 16)
    elif ntype == "Domain":
        return _truncate(props.get("domain", node_id), 20)
    elif ntype == "URL":
        return _truncate(props.get("url", node_id), 20)
    return _truncate(node_id, 16)


class GraphVisualizer:
    """
    Neo4j에서 공격 경로를 조회하고 PNG로 시각화
    """

    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.uri  = neo4j_uri
        self.user = neo4j_user
        self.pwd  = neo4j_password

    def _get_driver(self):
        from neo4j import GraphDatabase
        return GraphDatabase.driver(self.uri, auth=(self.user, self.pwd))

    # ── Neo4j 쿼리 ────────────────────────────────────────

    def fetch_attack_graph(self, src_ip: str) -> Dict[str, Any]:
        """
        특정 소스 IP 기준으로 공격 관련 노드/엣지 전체 조회
        Returns: {"nodes": [...], "edges": [...]}
        """
        driver = self._get_driver()
        nodes_map = {}
        edges = []

        queries = [
            # Session → SRC Host
            ("""
                MATCH (s:Session)-[r:SRC]->(h:Host {ip: $ip})
                RETURN s, r, h
            """, {"ip": src_ip}),
            # Session → DST Host
            ("""
                MATCH (s:Session)-[:SRC]->(h:Host {ip: $ip})
                MATCH (s)-[r:DST]->(d:Host)
                RETURN s, r, d
            """, {"ip": src_ip}),
            # Session → TRIGGERED Signature
            ("""
                MATCH (s:Session)-[:SRC]->(h:Host {ip: $ip})
                MATCH (s)-[r:TRIGGERED]->(sig:Signature)
                RETURN s, r, sig
            """, {"ip": src_ip}),
            # Session → TARGETS Service
            ("""
                MATCH (s:Session)-[:SRC]->(h:Host {ip: $ip})
                MATCH (s)-[r:TARGETS]->(svc:Service)
                RETURN s, r, svc
            """, {"ip": src_ip}),
            # Session → QUERIES Domain
            ("""
                MATCH (s:Session)-[:SRC]->(h:Host {ip: $ip})
                MATCH (s)-[r:QUERIES]->(d:Domain)
                RETURN s, r, d
            """, {"ip": src_ip}),
            # Session → ACCESSES URL
            ("""
                MATCH (s:Session)-[:SRC]->(h:Host {ip: $ip})
                MATCH (s)-[r:ACCESSES]->(u:URL)
                RETURN s, r, u
            """, {"ip": src_ip}),
        ]

        with driver.session() as session:
            for query, params in queries:
                try:
                    results = session.run(query, **params)
                    for record in results:
                        for key in record.keys():
                            item = record[key]
                            if hasattr(item, "id") and hasattr(item, "labels"):
                                # Node
                                nid = str(item.id)
                                nodes_map[nid] = {
                                    "id":     nid,
                                    "labels": list(item.labels),
                                    **dict(item.items()),
                                }
                            elif hasattr(item, "id") and hasattr(item, "type"):
                                # Relationship
                                edges.append({
                                    "from":  str(item.start_node.id),
                                    "to":    str(item.end_node.id),
                                    "type":  item.type,
                                })
                except Exception as e:
                    logger.debug(f"쿼리 일부 실패 (무시): {e}")

        driver.close()
        return {"nodes": list(nodes_map.values()), "edges": edges}

    def fetch_query_path(self, cypher: str, params: Dict = None) -> Dict[str, Any]:
        """
        임의 Cypher 쿼리 결과를 그래프 데이터로 변환
        """
        driver = self._get_driver()
        nodes_map = {}
        edges = []

        with driver.session() as session:
            results = session.run(cypher, **(params or {}))
            for record in results:
                for key in record.keys():
                    item = record[key]
                    if item is None:
                        continue
                    if hasattr(item, "labels"):
                        nid = str(item.id)
                        nodes_map[nid] = {
                            "id": nid,
                            "labels": list(item.labels),
                            **dict(item.items()),
                        }
                    elif hasattr(item, "type") and hasattr(item, "start_node"):
                        edges.append({
                            "from": str(item.start_node.id),
                            "to":   str(item.end_node.id),
                            "type": item.type,
                        })

        driver.close()
        return {"nodes": list(nodes_map.values()), "edges": edges}

    # ── 시각화 ────────────────────────────────────────────

    def visualize(
        self,
        graph_data: Dict[str, Any],
        title: str = "Attack Path Graph",
        output_path: str = "./output/graph.png",
        figsize: tuple = (18, 12),
        layout: str = "spring",
    ) -> str:
        """
        그래프 데이터를 PNG로 시각화하여 저장
        Returns: 저장된 파일 경로
        """
        if not NX_AVAILABLE or not MPL_AVAILABLE:
            raise RuntimeError("networkx 또는 matplotlib가 설치되지 않았습니다.")

        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        if not nodes:
            logger.warning("시각화할 노드가 없습니다.")
            return ""

        # NetworkX 그래프 생성
        G = nx.DiGraph()
        node_id_map = {n["id"]: n for n in nodes}

        for n in nodes:
            G.add_node(n["id"], **n)

        for e in edges:
            if e["from"] in node_id_map and e["to"] in node_id_map:
                G.add_edge(e["from"], e["to"], rel_type=e["type"])

        # 레이아웃
        if layout == "spring":
            pos = nx.spring_layout(G, k=2.5, iterations=50, seed=42)
        elif layout == "kamada_kawai":
            pos = nx.kamada_kawai_layout(G)
        elif layout == "circular":
            pos = nx.circular_layout(G)
        else:
            pos = nx.spring_layout(G, seed=42)

        # Figure 생성
        fig, ax = plt.subplots(figsize=figsize)
        ax.set_facecolor("#1a1a2e")
        fig.patch.set_facecolor("#1a1a2e")

        # 노드 타입별 분리 렌더링
        type_groups: Dict[str, List] = {}
        for nid, data in G.nodes(data=True):
            labels = data.get("labels", ["Unknown"])
            ntype = labels[0] if labels else "Unknown"
            type_groups.setdefault(ntype, []).append(nid)

        for ntype, node_list in type_groups.items():
            style = NODE_STYLES.get(ntype, NODE_STYLES["Unknown"])
            nx.draw_networkx_nodes(
                G, pos,
                nodelist=node_list,
                node_color=style["color"],
                node_size=style["size"],
                node_shape=style["shape"],
                alpha=0.9,
                ax=ax,
            )

        # 엣지 타입별 렌더링
        edge_groups: Dict[str, List] = {}
        for u, v, data in G.edges(data=True):
            rel = data.get("rel_type", "RELATED")
            edge_groups.setdefault(rel, []).append((u, v))

        for rel_type, edge_list in edge_groups.items():
            style = EDGE_STYLES.get(rel_type, EDGE_STYLES["RELATED"])
            nx.draw_networkx_edges(
                G, pos,
                edgelist=edge_list,
                edge_color=style["color"],
                style=style["style"],
                width=style["width"],
                arrows=True,
                arrowsize=20,
                arrowstyle="->",
                connectionstyle="arc3,rad=0.1",
                ax=ax,
            )

        # 노드 레이블
        labels_dict = {}
        for nid, data in G.nodes(data=True):
            labels_dict[nid] = _get_node_label(nid, data)

        nx.draw_networkx_labels(
            G, pos,
            labels=labels_dict,
            font_size=7,
            font_color="white",
            font_weight="bold",
            ax=ax,
        )

        # 엣지 레이블
        edge_labels = {(u, v): data.get("rel_type", "") for u, v, data in G.edges(data=True)}
        nx.draw_networkx_edge_labels(
            G, pos,
            edge_labels=edge_labels,
            font_size=6,
            font_color="#BDC3C7",
            ax=ax,
        )

        # 범례 (노드 타입)
        legend_handles = []
        for ntype, style in NODE_STYLES.items():
            if any(ntype in n.get("labels", []) for n in nodes):
                patch = mpatches.Patch(color=style["color"], label=ntype)
                legend_handles.append(patch)

        if legend_handles:
            ax.legend(
                handles=legend_handles,
                loc="upper left",
                fontsize=8,
                facecolor="#2d2d44",
                labelcolor="white",
                edgecolor="#555",
            )

        # 통계 텍스트
        stats_text = (
            f"Nodes: {G.number_of_nodes()}  |  "
            f"Edges: {G.number_of_edges()}  |  "
            f"Edge Types: {len(edge_groups)}"
        )
        ax.text(
            0.99, 0.01, stats_text,
            transform=ax.transAxes,
            fontsize=8, color="#95A5A6",
            ha="right", va="bottom",
        )

        ax.set_title(title, color="white", fontsize=14, pad=15, fontweight="bold")
        ax.axis("off")
        plt.tight_layout()

        # 저장
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(output_path, dpi=150, bbox_inches="tight",
                    facecolor=fig.get_facecolor())
        plt.close(fig)

        logger.info(f"그래프 저장: {output_path}  ({G.number_of_nodes()} 노드, {G.number_of_edges()} 엣지)")
        return output_path

    # ── 편의 메서드 ──────────────────────────────────────

    def visualize_ip(
        self,
        src_ip: str,
        output_dir: str = "./output/graphs",
        layout: str = "spring",
    ) -> str:
        """
        특정 소스 IP의 공격 경로 시각화
        """
        graph_data = self.fetch_attack_graph(src_ip)
        if not graph_data["nodes"]:
            logger.warning(f"{src_ip}에 대한 그래프 데이터 없음")
            return ""

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ip = src_ip.replace(".", "_")
        output_path = f"{output_dir}/{safe_ip}_{ts}.png"

        return self.visualize(
            graph_data,
            title=f"Attack Path: {src_ip}",
            output_path=output_path,
            layout=layout,
        )

    def visualize_query(
        self,
        cypher: str,
        params: Dict = None,
        title: str = "Query Path Graph",
        output_path: str = "./output/graphs/query_graph.png",
        layout: str = "spring",
    ) -> str:
        """
        임의 Cypher 쿼리 결과 시각화
        """
        graph_data = self.fetch_query_path(cypher, params)
        if not graph_data["nodes"]:
            logger.warning("시각화할 그래프 데이터 없음")
            return ""

        return self.visualize(graph_data, title=title, output_path=output_path, layout=layout)

    def visualize_rag_result(
        self,
        rag_result: Dict[str, Any],
        output_dir: str = "./output/graphs",
    ) -> str:
        """
        RAG 분석 결과에서 src_ip를 추출하여 그래프 시각화
        """
        packet = rag_result.get("packet", {})
        src_ip = packet.get("src_ip", "")
        if not src_ip:
            logger.warning("RAG 결과에 src_ip 없음")
            return ""

        xai = rag_result.get("xai_result", {})
        stage = xai.get("attack_stage", "Unknown")
        title = f"Attack Path: {src_ip}  [{stage}]"

        graph_data = self.fetch_attack_graph(src_ip)
        if not graph_data["nodes"]:
            logger.warning(f"{src_ip}에 대한 그래프 데이터 없음")
            return ""

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ip = src_ip.replace(".", "_")
        output_path = f"{output_dir}/{safe_ip}_{ts}.png"

        return self.visualize(graph_data, title=title, output_path=output_path)