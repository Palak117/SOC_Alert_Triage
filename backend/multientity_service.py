"""
Multi-Entity Supervisory Analytics & Cross-CSE Benchmarking Service
Problem Statement: SIH26157 | NTRO / NCIIPC

Provides:
1. Multi-CSE data loading & entity profile management
2. 8-Domain statutory cyber resilience scorecards
3. Cross-entity peer benchmarking & cohort robust Z-scores
4. Cross-entity telemetry coverage matrix (negative space heatmap)
5. Prioritized regulatory audit queue for NCIIPC examiners
6. Automated NCIIPC Supervisory Audit Dossier generator
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import pandas as pd
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import DATA_DIR, SCORED_DIR

MULTIENTITY_SUMMARY_FILE = SCORED_DIR / "multientity_supervisory_summary.json"
MULTIENTITY_SAMPLE_PARQUET = SCORED_DIR / "dashboard_multientity_sample.parquet"

DEFAULT_ENTITY_NAMES = {
    "ORG-0001": {"name": "National Power Grid Infrastructure", "sector": "Energy & Power", "tier": "Tier-1 Critical"},
    "ORG-0003": {"name": "Central Banking & Financial Services", "sector": "Financial / Banking", "tier": "Tier-1 Critical"},
    "ORG-0004": {"name": "Defense & National Telecommunications", "sector": "Defense / Telecom", "tier": "Tier-1 Critical"},
    "ORG-0005": {"name": "Petroleum & Pipeline Control Systems", "sector": "Oil, Gas & Energy", "tier": "Tier-1 Critical"},
}

def load_multientity_summary() -> Dict[str, Any]:
    """Load the precomputed multi-CSE supervisory summary and scorecards."""
    if MULTIENTITY_SUMMARY_FILE.exists():
        try:
            with open(MULTIENTITY_SUMMARY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"cohort_size": 0, "entities": {}, "cohort_medians": {}}


def get_entity_list() -> List[Dict[str, str]]:
    """Return list of supported Critical Sector Entities."""
    summary = load_multientity_summary()
    entities = summary.get("entities", {})
    if entities:
        return [
            {
                "org_id": org_id,
                "label": f"{org_id} — {data['entity_name']} ({data['sector']})",
                "name": data["entity_name"],
                "sector": data["sector"]
            }
            for org_id, data in entities.items()
        ]
    return [
        {"org_id": k, "label": f"{k} — {v['name']} ({v['sector']})", "name": v["name"], "sector": v["sector"]}
        for k, v in DEFAULT_ENTITY_NAMES.items()
    ]


def get_ranked_regulatory_queue() -> List[Dict[str, Any]]:
    """Return Critical Sector Entities ranked by supervisory risk index for regulatory audits."""
    summary = load_multientity_summary()
    entities = list(summary.get("entities", {}).values())
    if not entities:
        return []
    # Rank descending by supervisory risk index
    return sorted(entities, key=lambda x: x.get("supervisory_risk_index", 0), reverse=True)


def get_telemetry_coverage_matrix() -> pd.DataFrame:
    """
    Build a cross-entity telemetry coverage matrix identifying monitoring blind spots
    (Negative Space) across all Critical Sector Entities.
    """
    summary = load_multientity_summary()
    entities = summary.get("entities", {})
    if not entities:
        return pd.DataFrame()

    all_products = set()
    for ent in entities.values():
        all_products.update(ent.get("product_distribution", {}).keys())

    all_products = sorted(list(all_products))
    rows = []

    for org_id, ent in entities.items():
        row = {
            "Entity ID": org_id,
            "Critical Sector Entity": ent["entity_name"],
            "Sector": ent["sector"],
            "Total Alerts": ent["total_alerts"]
        }
        prod_dist = ent.get("product_distribution", {})
        for prod in all_products:
            cnt = prod_dist.get(prod, 0)
            pct = (cnt / ent["total_alerts"] * 100.0) if ent["total_alerts"] > 0 else 0
            # Flag 0% as BLIND SPOT if other peers have coverage
            row[prod] = f"{cnt:,} ({pct:.1f}%)" if cnt > 0 else "0 (BLIND SPOT)"
        rows.append(row)

    return pd.DataFrame(rows)


def generate_supervisory_dossier_text(org_id: str) -> str:
    """
    Generate an official NCIIPC Supervisory Audit Dossier (Markdown formatted)
    for a specific Critical Sector Entity.
    """
    summary = load_multientity_summary()
    entities = summary.get("entities", {})
    ent = entities.get(org_id)
    if not ent:
        return f"No supervisory records found for entity: {org_id}"

    scores = ent.get("scores", {})
    z_scores = ent.get("cohort_robust_z", {})
    prods = ent.get("product_distribution", {})

    dossier = f"""# NATIONAL CRITICAL INFORMATION INFRASTRUCTURE PROTECTION CENTRE (NCIIPC)
## SUPERVISORY ASSESSMENT DOSSIER — CRITICAL SECTOR ENTITY AUDIT
**Reference Problem Statement:** SIH26157 | SAT-SA Supervisory Assessment
**Entity Identifier:** {org_id}
**Entity Name:** {ent['entity_name']}
**Sector:** {ent['sector']} | **Tier:** {ent['tier']}
**Assessment Date:** {summary.get('generated_at', '2026-11-14')}
**Supervisory Classification:** {ent['audit_urgency']}
**Supervisory Risk Index:** {ent['supervisory_risk_index']} / 100.0 (Resilience Score: {scores.get('Cyber Resilience Index', 'N/A')}/100)

---

### 1. EXECUTIVE SUPERVISORY FINDINGS
1. **Regulatory Status:** Entity **{org_id}** is placed under **{ent['audit_urgency']}** based on aggregate operational discipline indicators.
2. **Total Evaluated Alerts:** {ent['total_alerts']:,} alerts submitted for supervisory sampling.
3. **High-Risk Operational Volume:** {ent['critical_high_alerts']:,} Critical/High alerts ({ent['critical_high_pct']}%), indicating {"elevated threat surface" if ent['critical_high_pct'] > 5 else "controlled operational volume"}.
4. **Evidence-Gap Rate:** {ent['evidence_gap_rate']}% of alerts exhibit missing investigation fields or truncated context.
5. **Negative Space Rate:** {ent['negative_space_rate']}% of alerts lack expected telemetry bindings relative to peer benchmarks.

---

### 2. STATUTORY 8-DOMAIN CAPABILITY RATINGS (0–100 SCALE)
- **(i). Threat Detection:** {scores.get('Threat Detection', 'N/A')}/100
- **(ii). Investigation Rigor:** {scores.get('Investigation', 'N/A')}/100
- **(iii). Escalation Timeliness:** {scores.get('Escalation', 'N/A')}/100
- **(iv). Incident Response Capability:** {scores.get('Incident Response', 'N/A')}/100
- **(v). Security Operations (SecOps):** {scores.get('Security Operations', 'N/A')}/100
- **(vi). Governance & Oversight:** {scores.get('Governance & Oversight', 'N/A')}/100
- **(vii). Operational Discipline:** {scores.get('Operational Discipline', 'N/A')}/100
- **(viii). Composite Cyber Resilience:** {scores.get('Cyber Resilience Index', 'N/A')}/100

---

### 3. CROSS-ENTITY PEER BENCHMARKING (COHORT ROBUST Z-SCORES)
*Peer cohort size: {summary.get('cohort_size', 4)} Critical Sector Entities. Baseline: Cohort Median.*
- **Negative Space Deviation (Robust Z):** {z_scores.get('negative_space_rate', 0):+.2f}
- **Evidence Gap Deviation (Robust Z):** {z_scores.get('evidence_gap_rate', 0):+.2f}
- **Anomaly Score Deviation (Robust Z):** {z_scores.get('mean_anomaly_score', 0):+.2f}
- **Supervisory Risk Index Deviation (Robust Z):** {z_scores.get('supervisory_risk_index', 0):+.2f}

---

### 4. TELEMETRY PROFILE & MONITORING COVERAGE (NEGATIVE SPACE AUDIT)
"""
    for prod, cnt in prods.items():
        pct = (cnt / ent['total_alerts'] * 100.0) if ent['total_alerts'] > 0 else 0
        dossier += f"- **{prod}:** {cnt:,} logs ({pct:.1f}%)\n"

    dossier += f"""
---

### 5. HISTORICAL OPERATIONAL TRENDS & QUARTERLY PROGRESSION
"""
    trends = ent.get("historical_trends", [])
    if trends:
        for tr in trends:
            dossier += f"- **{tr.get('period', 'N/A')} ({tr.get('start_time', '')} to {tr.get('end_time', '')}):** {tr.get('alerts', 0):,} alerts | Execution Gap: {tr.get('execution_gap_pct', 0):.2f}% | Evidence Gap: {tr.get('evidence_gap_pct', 0):.2f}% | Mean Anomaly Score: {tr.get('mean_anomaly_score', 0):.4f}\n"
    else:
        dossier += "- Single continuous evaluation period recorded.\n"

    dossier += f"""
---

### 6. SUPERVISORY ACTION RECOMMENDATIONS
1. **On-Site Inspection Focus:** Focus manual examination on samples flagged with high evidence gaps ({ent['evidence_gap_rate']}%).
2. **Escalation Record Request:** Demand formal case-management escalation tickets for Critical alerts closed without recorded escalation.
3. **Telemetry Remediation:** Verify whether blind spots reflect genuine absence of threats or unmonitored critical assets.

*CONFIDENTIAL — FOR NCIIPC SUPERVISORY EXAMINERS ONLY. GENERATED BY SAT-SA V6.*
"""
    return dossier
