"""
Tests for Multi-CSE Supervisory Analytics & Cross-Entity Benchmarking
Problem Statement: SIH26157 | NTRO / NCIIPC
Verifies:
1. Retrieval of all 4 Critical Sector Entities (ORG-0001, 0003, 0004, 0005)
2. 8-domain statutory scorecards bounded between 0 and 100
3. Cross-entity peer benchmarking & cohort robust Z-scores
4. Cross-entity telemetry coverage matrix and blind spot identification
5. Prioritized regulatory audit queue ordering
6. Supervisory Audit Dossier text generation
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.multientity_service import (
    load_multientity_summary,
    get_entity_list,
    get_ranked_regulatory_queue,
    get_telemetry_coverage_matrix,
    generate_supervisory_dossier_text
)

def test_multientity_summary_contains_four_cses():
    summary = load_multientity_summary()
    assert summary["cohort_size"] == 4
    entities = summary["entities"]
    for expected_org in ["ORG-0001", "ORG-0003", "ORG-0004", "ORG-0005"]:
        assert expected_org in entities, f"Missing {expected_org} in multi-entity summary!"


def test_statutory_eight_domain_scorecards():
    summary = load_multientity_summary()
    entities = summary["entities"]
    domains = [
        "Threat Detection",
        "Investigation",
        "Escalation",
        "Incident Response",
        "Security Operations",
        "Governance & Oversight",
        "Operational Discipline",
        "Cyber Resilience Index"
    ]
    for org_id, ent in entities.items():
        scores = ent.get("scores", {})
        for d in domains:
            assert d in scores, f"Domain {d} missing for {org_id}!"
            val = scores[d]
            assert 0.0 <= val <= 100.0, f"Domain score {d} for {org_id} out of bounds: {val}"


def test_cross_entity_peer_benchmarking_z_scores():
    summary = load_multientity_summary()
    entities = summary["entities"]
    for org_id, ent in entities.items():
        z_scores = ent.get("cohort_robust_z", {})
        assert "supervisory_risk_index" in z_scores
        assert "evidence_gap_rate" in z_scores
        assert "negative_space_rate" in z_scores


def test_telemetry_coverage_matrix():
    df_matrix = get_telemetry_coverage_matrix()
    assert not df_matrix.empty
    assert len(df_matrix) == 4
    assert "Entity ID" in df_matrix.columns
    assert "Critical Sector Entity" in df_matrix.columns
    # Check that at least one blind spot is flagged in the cohort
    has_blind_spot = df_matrix.astype(str).apply(lambda col: col.str.contains("BLIND SPOT").any()).any()
    assert has_blind_spot, "Expected at least one telemetry blind spot to be identified across CSEs"


def test_ranked_regulatory_queue():
    queue = get_ranked_regulatory_queue()
    assert len(queue) == 4
    risk_scores = [q["supervisory_risk_index"] for q in queue]
    # Verify strictly descending order
    assert risk_scores == sorted(risk_scores, reverse=True)


def test_supervisory_dossier_text_generation():
    dossier = generate_supervisory_dossier_text("ORG-0004")
    assert "NATIONAL CRITICAL INFORMATION INFRASTRUCTURE PROTECTION CENTRE" in dossier
    assert "SUPERVISORY ASSESSMENT DOSSIER" in dossier
    assert "ORG-0004" in dossier
    assert "STATUTORY 8-DOMAIN CAPABILITY RATINGS" in dossier
    assert "CROSS-ENTITY PEER BENCHMARKING" in dossier
