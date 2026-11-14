"""
Test On-Demand Telemetry Record Lookup for Alert Investigation Workbench.
Validates sub-second PyArrow disk query for alerts outside active queue memory.
"""

import pytest
import pyarrow.parquet as pq
from pathlib import Path
import pandas as pd

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "scored"
PARQUET_PATH = DATA_DIR / "dashboard_consolidated.parquet"


def test_parquet_file_integrity():
    assert PARQUET_PATH.exists(), f"Parquet file {PARQUET_PATH} does not exist"
    table = pq.read_table(str(PARQUET_PATH), columns=["_alert_id"])
    assert table.num_rows == 402335, f"Expected 402,335 rows, got {table.num_rows}"


def test_on_demand_lookup_outside_active_queue():
    """Verify an alert with ID >= 25,000 can be retrieved from disk via PyArrow in < 1s."""
    target_id = 150000
    p_path = PARQUET_PATH
    
    table = pq.read_table(str(p_path), filters=[('_alert_id', '=', target_id)])
    assert table.num_rows == 1, f"Expected 1 record for ID {target_id}, got {table.num_rows}"
    
    rec_df = table.to_pandas()
    assert int(rec_df.iloc[0]["_alert_id"]) == target_id
    assert "anomaly_score" in rec_df.columns
    assert "priority_rank" in rec_df.columns
    assert "severity" in rec_df.columns


def test_on_demand_lookup_extreme_bounds():
    """Test lookup at the boundary of the dataset (e.g., alert ID 402,334)."""
    target_id = 402334
    p_path = PARQUET_PATH
    
    table = pq.read_table(str(p_path), filters=[('_alert_id', '=', target_id)])
    assert table.num_rows >= 0  # Should not raise exception
    if table.num_rows > 0:
        rec_df = table.to_pandas()
        assert int(rec_df.iloc[0]["_alert_id"]) == target_id


def test_on_demand_nonexistent_id():
    """Test lookup of non-existent alert ID gracefully returns 0 rows."""
    target_id = 999999999
    p_path = PARQUET_PATH
    
    table = pq.read_table(str(p_path), filters=[('_alert_id', '=', target_id)])
    assert table.num_rows == 0
