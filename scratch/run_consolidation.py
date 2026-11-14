"""
Script to execute data consolidation for both models and build comparison artifacts.
"""

import os
import sys
import time

sys.path.insert(0, os.path.abspath("."))

from backend.config import (
    BASELINE_ALERTS_CSV,
    BASELINE_INCIDENTS_CSV,
    BASELINE_SUMMARY_CSV,
    BASELINE_REVIEW_CSV,
    CONSOLIDATED_PARQUET,
    CONSOLIDATED_CSV,
    LR_ALERTS_CSV,
    LR_INCIDENTS_CSV,
    LR_SUMMARY_CSV,
    LR_REVIEW_CSV,
    CONSOLIDATED_LR_PARQUET,
    CONSOLIDATED_LR_CSV,
    LR_VS_BASELINE_COMPARISON_CSV,
)
from backend.data_service import consolidate_data
from backend.evaluation_service import generate_comparative_benchmark, save_comparison_table

print("=" * 70)
print("STARTING DATA CONSOLIDATION PIPELINE")
print("=" * 70)

# 1. Consolidate Leakage-Reduced Dataset
t0 = time.time()
print("\n[1/3] Processing Leakage-Reduced Model Dataset...")
lr_df = consolidate_data(
    source_alerts_path=LR_ALERTS_CSV,
    output_parquet=CONSOLIDATED_LR_PARQUET,
    output_csv=CONSOLIDATED_LR_CSV,
    incidents_output_path=LR_INCIDENTS_CSV,
    summary_output_path=LR_SUMMARY_CSV,
    review_output_path=LR_REVIEW_CSV,
)
print(f"Leakage-Reduced consolidation completed in {time.time() - t0:.2f} seconds.")

# 2. Consolidate Baseline Dataset
t0 = time.time()
print("\n[2/3] Processing Original Baseline Model Dataset...")
base_df = consolidate_data(
    source_alerts_path=BASELINE_ALERTS_CSV,
    output_parquet=CONSOLIDATED_PARQUET,
    output_csv=CONSOLIDATED_CSV,
    incidents_output_path=None, # keep existing baseline incidents
    summary_output_path=None,   # keep existing baseline summary
    review_output_path=None,    # keep existing baseline review
)
print(f"Baseline consolidation completed in {time.time() - t0:.2f} seconds.")

# 3. Generate Side-by-Side Comparison Benchmark
t0 = time.time()
print("\n[3/3] Generating Side-by-Side Dual-Evaluation Comparison...")
comp_df = generate_comparative_benchmark(base_df, lr_df)
save_comparison_table(comp_df, LR_VS_BASELINE_COMPARISON_CSV)
print("\nBenchmark Comparison Results:")
print(comp_df.to_string(index=False))

print(f"\nAll consolidation steps finished in {time.time() - t0:.2f} seconds.")
print("=" * 70)
