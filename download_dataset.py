from datasets import load_dataset

print("Downloading WitFoo signals dataset...")

dataset = load_dataset(
    "witfoo/precinct6-cybersecurity",
    "signals",
    split="train"
)

print(f"Downloaded {len(dataset)} records.")

print("Converting to Pandas...")
df = dataset.to_pandas()

output_path = "data/precinct6_cybersecurity.parquet"

print(f"Saving dataset to: {output_path}")
df.to_parquet(output_path, index=False)

print("\n===================================")
print("DATASET SAVED SUCCESSFULLY")
print("===================================")
print(f"Rows: {len(df)}")
print(f"Columns: {len(df.columns)}")
print(f"File: {output_path}")
print("===================================")