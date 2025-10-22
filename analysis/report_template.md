# V2X PQC Latency Study Template

## 1. Experiment Context
- **Date:** YYYY-MM-DD
- **Binary Commit:** <git commit hash>
- **Signature Scheme:** falcon / ecdsa
- **Fragment Size (bytes):** XXX
- **Compression:** none / zstd / ...
- **Packet Loss Rate:** 0.00
- **Vehicles × Messages:** V × M
- **Hardware / Runtime Notes:**
  - CPU / RAM
  - OS + kernel
  - Additional remarks (e.g., background load, virtualization)

## 2. Measurement Commands
```bash
# Collect raw metrics
python3 scripts/run_remote_falcon.py \
  --binary build/pq-v2verifier \
  --config config.json \
  --runs 1000 \
  --scheme falcon \
  --fragment-sizes 192 256 320 \
  --compression none \
  --packet-loss 0.0 \
  --metrics-file results/falcon_metrics.csv \
  --log-dir logs/2024-XX-YY

# Summarise for reporting
python3 scripts/metrics_report.py \
  --metrics results/falcon_metrics.csv \
  --output-markdown results/summary.md \
  --output-json results/summary.json
```

## 3. Summary Table (auto-generated)
Paste the Markdown table from `results/summary.md` here.

## 4. Latency Distribution Graphs
- Generate comparison plots per fragment size (example Python snippet):
```python
import csv
import matplotlib.pyplot as plt

fragment_buckets = {}
with open("results/falcon_metrics.csv", newline="") as fh:
    reader = csv.DictReader(fh)
    for row in reader:
        note = row["note"]
        fields = dict(item.split("=", 1) for item in note.split(";") if "=" in item)
        bucket = fields.get("fragment", "unknown")
        fragment_buckets.setdefault(bucket, []).append(float(row["total_us"]))

plt.figure(figsize=(8, 4))
for fragment, values in sorted(fragment_buckets.items(), key=lambda x: float(x[0])):
    plt.plot(values, label=f"fragment={fragment} bytes")
plt.xlabel("Run index")
plt.ylabel("Completion latency (µs)")
plt.legend()
plt.tight_layout()
plt.savefig("results/latency_by_fragment.png", dpi=200)
plt.close()
```

- Overlay packet-loss scenarios by re-running with `--packet-loss` non-zero and plotting on the same axes (distinguish with legend labels `loss=VALUE`).

## 5. Multi-Vehicle Stress Test
Document follow-up runs with `--vehicles > 1` and increased `--messages`. Capture:
- Average total latency per vehicle.
- Observed outliers (max latency, standard deviation).
- Receiver log excerpts highlighting fragment reassembly behaviour.

## 6. Key Observations
- Highlight fragment size vs. latency trends.
- Note packet loss tolerance thresholds.
- Record optimised configuration achieving target (<5 ms) latency.

## 7. Residual Risks & Next Checks
- Additional validation items (e.g., real SDR hardware, larger fleet, radio impairments).
- Outstanding implementation work (e.g., compression algorithm integration).

---
*Template maintained by `analysis/report_template.md`; customise freely when preparing deliverables.*
