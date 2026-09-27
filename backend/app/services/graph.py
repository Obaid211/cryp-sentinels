from typing import Dict, Any, List, Optional
import networkx as nx
from sqlalchemy.orm import Session
from app.models.models import Service, ServiceDependency, CryptoAsset

def build_networkx_graph(db: Session) -> nx.DiGraph:
    """
    Constructs a NetworkX directed graph from PostgreSQL/SQLite services and dependencies.
    Edge convention: Edge (u, v) denotes Service u depends on Service v.
    """
    G = nx.DiGraph()

    services = db.query(Service).all()
    for s in services:
        assets = db.query(CryptoAsset).filter(CryptoAsset.linked_service_id == s.id).all()
        asset_list = []
        max_risk = 0.0
        has_vulnerable = False

        for a in assets:
            score = float(a.risk_score or 0.0)
            if score > max_risk:
                max_risk = score
            key_type = a.cert_key_type or a.algorithm or ""
            is_vuln = bool(key_type and any(k in key_type.upper() for k in ["RSA", "ECC", "ECDSA", "DSA", "DH", "MD5", "SHA-1", "DES"]))
            if is_vuln:
                has_vulnerable = True

            asset_list.append({
                "id": a.id,
                "host": a.host,
                "port": a.port,
                "source": a.source or "tls",
                "cert_key_type": key_type,
                "cert_key_size_bits": a.cert_key_size_bits,
                "tls_version": a.tls_version,
                "risk_score": score,
                "is_vulnerable": is_vuln,
                "business_criticality": a.business_criticality or "medium",
                "data_lifetime": a.data_lifetime or "1-3y",
            })

        G.add_node(
            s.id,
            id=s.id,
            name=s.name,
            criticality=s.criticality or "P2",
            description=s.description or "",
            assets=asset_list,
            asset_count=len(asset_list),
            max_risk_score=round(max_risk, 1),
            has_vulnerable=has_vulnerable
        )

    deps = db.query(ServiceDependency).all()
    for d in deps:
        if d.service_id in G and d.depends_on_service_id in G:
            G.add_edge(d.service_id, d.depends_on_service_id, label="depends_on")

    return G


def get_graph_data(db: Session) -> Dict[str, Any]:
    """
    Serializes dependency graph with topological properties, node metrics,
    and critical path analysis for frontend canvas rendering.
    """
    G = build_networkx_graph(db)

    nodes = []
    service_names = {}
    for node_id, data in G.nodes(data=True):
        service_names[node_id] = data.get("name", f"Service-{node_id}")

    # Centrality metrics
    in_degree = dict(G.in_degree())
    out_degree = dict(G.out_degree())
    try:
        betweenness = nx.betweenness_centrality(G)
    except Exception:
        betweenness = {n: 0.0 for n in G.nodes()}

    for node_id, data in G.nodes(data=True):
        nodes.append({
            "id": node_id,
            "name": data.get("name"),
            "criticality": data.get("criticality", "P2"),
            "description": data.get("description", ""),
            "asset_count": data.get("asset_count", 0),
            "max_risk_score": data.get("max_risk_score", 0.0),
            "has_vulnerable": data.get("has_vulnerable", False),
            "assets": data.get("assets", []),
            "in_degree": in_degree.get(node_id, 0),
            "out_degree": out_degree.get(node_id, 0),
            "centrality": round(betweenness.get(node_id, 0.0), 3)
        })

    edges = []
    for u, v in G.edges():
        edges.append({
            "source": u,
            "target": v,
            "source_name": service_names.get(u, f"Service-{u}"),
            "target_name": service_names.get(v, f"Service-{v}"),
            "relation": "depends_on"
        })

    # Critical path: longest directed path in DAG
    critical_path = []
    try:
        if nx.is_directed_acyclic_graph(G) and len(G) > 0:
            longest = nx.dag_longest_path(G)
            critical_path = [service_names.get(n, str(n)) for n in longest]
    except Exception:
        critical_path = []

    is_dag = nx.is_directed_acyclic_graph(G) if len(G) > 0 else True

    return {
        "nodes": nodes,
        "edges": edges,
        "critical_path": critical_path,
        "is_dag": is_dag,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "isolated_nodes": len(list(nx.isolates(G))),
            "critical_path_length": len(critical_path)
        }
    }


def compute_blast_radius(db: Session, service_id: int) -> Dict[str, Any]:
    """
    Computes blast radius impact for a given service.
    Reversed reachability determines all downstream services that rely on this node.
    """
    G = build_networkx_graph(db)
    if service_id not in G:
        return {"error": f"Service with ID {service_id} not found in dependency graph."}

    node_data = G.nodes[service_id]
    service_name = node_data.get("name", f"Service-{service_id}")
    criticality = node_data.get("criticality", "P2")

    # In our graph, edge is: caller -> callee (Service A -> Service B means A depends on B).
    # Downstream dependents (services impacted if B fails/migrates) are found by reversing edges.
    G_rev = G.reverse(copy=True)
    dependent_node_ids = list(nx.descendants(G_rev, service_id))
    direct_dependent_ids = list(G_rev.neighbors(service_id))

    # Upstream dependencies (services this service depends on)
    upstream_node_ids = list(nx.descendants(G, service_id))
    direct_upstream_ids = list(G.neighbors(service_id))

    dependent_services = []
    for nid in dependent_node_ids:
        d_data = G.nodes[nid]
        dependent_services.append({
            "id": nid,
            "name": d_data.get("name"),
            "criticality": d_data.get("criticality"),
            "is_direct": nid in direct_dependent_ids,
            "max_risk_score": d_data.get("max_risk_score", 0.0),
            "asset_count": d_data.get("asset_count", 0)
        })

    upstream_services = []
    for uid in upstream_node_ids:
        u_data = G.nodes[uid]
        upstream_services.append({
            "id": uid,
            "name": u_data.get("name"),
            "criticality": u_data.get("criticality"),
            "is_direct": uid in direct_upstream_ids
        })

    # Collect all impacted crypto assets across service + all dependent services
    all_impacted_service_ids = [service_id] + dependent_node_ids
    impacted_assets = []
    cumulative_risk = 0.0

    for sid in all_impacted_service_ids:
        s_data = G.nodes[sid]
        for asset in s_data.get("assets", []):
            impacted_assets.append({
                **asset,
                "service_id": sid,
                "service_name": s_data.get("name")
            })
            cumulative_risk += asset.get("risk_score", 0.0)

    # Complexity rating based on blast radius count and criticality
    total_impacted_nodes = len(dependent_node_ids) + 1
    crit_weight = {"P0": 3.0, "P1": 2.0, "P2": 1.0, "P3": 0.5}.get(criticality, 1.0)
    weighted_impact = total_impacted_nodes * crit_weight

    if weighted_impact <= 2.5:
        severity = "Low"
    elif weighted_impact <= 6.0:
        severity = "Medium"
    else:
        severity = "High"

    return {
        "service_id": service_id,
        "service_name": service_name,
        "criticality": criticality,
        "blast_radius_count": total_impacted_nodes,
        "severity": severity,
        "dependent_services": dependent_services,
        "dependent_count": len(dependent_services),
        "upstream_services": upstream_services,
        "upstream_count": len(upstream_services),
        "impacted_assets": impacted_assets,
        "impacted_asset_count": len(impacted_assets),
        "cumulative_risk_score": round(cumulative_risk, 1)
    }
