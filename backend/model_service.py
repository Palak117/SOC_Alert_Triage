"""
SOC Alert Triage - Model Service
Manages loading, feature validation, and scoring for both the
Original Baseline Isolation Forest model and the Leakage-Reduced model candidate.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

from backend.config import (
    BASELINE_MODEL_PATH,
    LR_MODEL_PATH,
)


class ModelService:
    """Service for managing Isolation Forest alert ranking models."""

    _models = {}

    @classmethod
    def get_model(cls, model_type: str = "leakage_reduced"):
        """Lazy loads and caches model instances."""
        if model_type not in cls._models:
            if model_type == "baseline":
                path = BASELINE_MODEL_PATH
            else:
                path = LR_MODEL_PATH

            if not path.exists():
                raise FileNotFoundError(f"Model file not found: {path}")

            model = joblib.load(path)
            cls._models[model_type] = model

        return cls._models[model_type]

    @classmethod
    def get_feature_names(cls, model_type: str = "leakage_reduced") -> List[str]:
        """Returns the list of features expected by the model."""
        model = cls.get_model(model_type)
        if hasattr(model, "feature_names_in_"):
            return list(model.feature_names_in_)
        return []

    @classmethod
    def get_model_metadata(cls, model_type: str = "leakage_reduced") -> Dict[str, Any]:
        """Returns model hyperparameters and configuration details."""
        model = cls.get_model(model_type)
        features = cls.get_feature_names(model_type)
        
        is_leakage_reduced = (model_type == "leakage_reduced")
        leakage_features = ["suspicion_score", "lifecycle_stage_rarity", "message_length_rarity", "message_word_count_rarity"]
        has_leakage = any(f in features for f in leakage_features)

        return {
            "model_type": model_type,
            "algorithm": "Isolation Forest (Unsupervised)",
            "n_estimators": getattr(model, "n_estimators", 300),
            "contamination": getattr(model, "contamination", 0.05),
            "random_state": getattr(model, "random_state", 42),
            "feature_count": getattr(model, "n_features_in_", len(features)),
            "features": features,
            "target_proxy_leakage_status": "REMOVED (Clean Production Ready)" if not has_leakage else "PRESENT (Historical Baseline)",
            "leakage_features_excluded": [f for f in leakage_features if f not in features],
        }

    @classmethod
    def score_features(cls, X: pd.DataFrame, model_type: str = "leakage_reduced") -> Tuple[np.ndarray, np.ndarray]:
        """
        Calculates anomaly scores and priority ranks from a feature dataframe.
        Anomaly score = -decision_function(X)
        Rank 1 = Highest anomaly score
        """
        model = cls.get_model(model_type)
        expected_features = cls.get_feature_names(model_type)

        # Prepare feature matrix
        if expected_features:
            missing = [f for f in expected_features if f not in X.columns]
            if missing:
                raise ValueError(f"Input data is missing expected features: {missing[:5]}...")
            X_clean = X[expected_features].copy()
        else:
            X_clean = X.copy()
            if "_alert_id" in X_clean.columns:
                X_clean = X_clean.drop(columns=["_alert_id"])

        X_clean = X_clean.apply(pd.to_numeric, errors="coerce")
        X_clean = X_clean.replace([np.inf, -np.inf], 0).fillna(0)

        # In unsupervised Isolation Forest, decision_function returns negative values for anomalies.
        # Negating it makes higher scores correspond to higher anomaly.
        raw_decision = model.decision_function(X_clean)
        anomaly_scores = -raw_decision

        ranks = pd.Series(anomaly_scores).rank(method="first", ascending=False).astype(int).values
        return anomaly_scores, ranks
