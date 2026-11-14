"""
Tests for ML Model Pipeline and Schema Validation.
"""

import pytest
import numpy as np
import pandas as pd

from backend.model_service import ModelService


def test_baseline_model_metadata():
    meta = ModelService.get_model_metadata("baseline")
    assert meta["n_estimators"] == 300
    assert meta["random_state"] == 42
    assert meta["feature_count"] == 54
    assert meta["target_proxy_leakage_status"] == "PRESENT (Historical Baseline)"


def test_leakage_reduced_model_metadata():
    meta = ModelService.get_model_metadata("leakage_reduced")
    assert meta["n_estimators"] == 300
    assert meta["random_state"] == 42
    assert meta["feature_count"] == 50
    assert meta["target_proxy_leakage_status"] == "REMOVED (Clean Production Ready)"

    # Verify problematic leakage features are completely excluded
    features = meta["features"]
    assert "suspicion_score" not in features, "suspicion_score must NOT be in clean model features!"
    assert "lifecycle_stage_rarity" not in features, "lifecycle_stage_rarity must NOT be in clean model features!"


def test_model_inference():
    # Test scoring synthetic sample
    features = ModelService.get_feature_names("leakage_reduced")
    assert len(features) == 50

    sample_X = pd.DataFrame(np.random.randn(10, 50), columns=features)
    scores, ranks = ModelService.score_features(sample_X, "leakage_reduced")

    assert len(scores) == 10
    assert len(ranks) == 10
    assert set(ranks) == set(range(1, 11))
    # Highest score must have rank 1
    assert ranks[np.argmax(scores)] == 1
