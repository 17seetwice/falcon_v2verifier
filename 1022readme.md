# Falcon Latency Harness Summary (2024-10)

## What Was Added
- `falcon-sim/` contains a standalone simulation binary (`falcon_sim`) ported from PQ-V2Verifier with Falcon-512 signing, signature fragmentation, reassembly, metrics logging, and optional packet-loss simulation.
- `scripts/run_remote_falcon.py` orchestrates transmitter/receiver runs, parameter sweeps (fragment size, compression, loss), and captures durability metrics to CSV.
- `scripts/metrics_report.py` aggregates the metrics into Markdown/JSON summaries; `analysis/report_template.md` provides an experiment write-up skeleton.
- `falcon_keys/` copied locally for immediate Falcon signing tests (hex-encoded, decoded at runtime).
- Root `CMakeLists.txt` now builds the `falcon_sim` target alongside existing V2Verifier components.

## Quick Usage
```bash
# Configure & build
cmake -S . -B build
cmake --build build --target falcon_sim

# Run automation (example fragment sweep)
python3 scripts/run_remote_falcon.py \
  --binary build/falcon-sim/falcon_sim \
  --config falcon-sim/config.json \
  --scheme falcon \
  --fragment-sizes 192 256 320 \
  --runs 100 \
  --metrics-file results/falcon_metrics.csv \
  --log-dir logs/falcon_baseline

# Summarise metrics
python3 scripts/metrics_report.py \
  --metrics results/falcon_metrics.csv \
  --output-markdown results/summary.md \
  --output-json results/summary.json
```

Environment variables respected by `falcon_sim`:
- `V2X_CONFIG_PATH`, `V2X_SIGNATURE_SCHEME`, `V2X_FALCON_FRAGMENT_BYTES`, `V2X_FALCON_COMPRESSION`
- `V2X_PACKET_LOSS_RATE` (transmitter drop simulation), `V2X_METRICS_FILE`, `V2X_METRICS_RUN`, `V2X_METRICS_NOTE`

> **Note:** On sandboxed systems UDP socket creation may fail; escalated permissions or alternate networking setup may be required before large-scale measurements (e.g., 1000 runs for ≤1.5 ms target latency).
