#!/usr/bin/env python3
"""
Automation harness for running PQ-V2Verifier in the run_remote configuration and
collecting latency metrics for Falcon-512 signature transport.

The script launches receiver and transmitter instances for the requested number of
iterations, records completion times exported by the receiver (via the environment
variable-driven metrics facility), and performs optional parameter sweeps across
Falcon fragment sizes and compression hints.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, Iterable, IO, List, Optional, Tuple

DEFAULT_BINARY = pathlib.Path("build") / "falcon-sim" / "falcon_sim"
DEFAULT_CONFIG = pathlib.Path("falcon-sim") / "config.json"
DEFAULT_METRICS = pathlib.Path("falcon_metrics.csv")


@dataclass
class SweepParameters:
    fragment_size: Optional[int]
    compression: Optional[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automate PQ-V2Verifier run_remote experiments with Falcon-512."
    )
    parser.add_argument("--binary", type=pathlib.Path, default=DEFAULT_BINARY,
                        help="Path to the falcon_sim executable (default: %(default)s)")
    parser.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONFIG,
                        help="Base configuration JSON used as input (default: %(default)s)")
    parser.add_argument("--runs", type=int, default=10,
                        help="Number of iterations per parameter set (default: %(default)s)")
    parser.add_argument("--scheme", choices=["ecdsa", "falcon"], default="falcon",
                        help="Signature scheme to exercise (default: %(default)s)")
    parser.add_argument("--fragment-sizes", type=int, nargs="*", default=None,
                        help="Fragment sizes (bytes) to sweep for Falcon mode")
    parser.add_argument("--compression", nargs="*", default=None,
                        help="Compression modes to sweep (default inherits from config)")
    parser.add_argument("--vehicles", type=int, default=None,
                        help="Override number of vehicles in config")
    parser.add_argument("--messages", type=int, default=None,
                        help="Override number of messages per vehicle in config")
    parser.add_argument("--packet-loss", type=float, default=0.0,
                        help="Simulated fragment loss rate (0.0-1.0) applied at the transmitter")
    parser.add_argument("--metrics-file", type=pathlib.Path, default=DEFAULT_METRICS,
                        help="CSV file to append metrics to (default: %(default)s)")
    parser.add_argument("--log-dir", type=pathlib.Path, default=None,
                        help="Optional directory for per-run stdout/stderr logs")
    parser.add_argument("--note", default="",
                        help="Free-form note stored alongside metrics entries")
    parser.add_argument("--sleep-ms", type=int, default=200,
                        help="Delay between launching receiver and transmitter (default: %(default)s ms)")
    parser.add_argument("--base-port", type=int, default=None,
                        help="Override test UDP port (default: 6666)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the derived run plan without executing it")
    parser.add_argument("--keep-temp-config", action="store_true",
                        help="Preserve generated temporary configs for inspection")
    return parser.parse_args()


def ensure_metrics_header(path: pathlib.Path) -> None:
    header = "run,scheme,total_us,first_us,last_us,note\n"
    if path.exists():
        with path.open("r", encoding="utf-8") as existing:
            first_line = existing.readline()
            if first_line.startswith("run,"):
                return
    with path.open("w", encoding="utf-8") as handle:
        handle.write(header)


def load_base_config(path: pathlib.Path) -> Dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_temp_config(base_config: Dict,
                      scheme: str,
                      vehicles: Optional[int],
                      messages: Optional[int],
                      fragment_size: Optional[int],
                      compression: Optional[str],
                      keep_file: bool) -> pathlib.Path:
    config = json.loads(json.dumps(base_config))
    scenario = config.setdefault("scenario", {})
    scenario["signatureScheme"] = scheme
    if vehicles is not None:
        scenario["numVehicles"] = vehicles
    if messages is not None:
        scenario["numMessages"] = messages

    falcon_cfg = scenario.setdefault("falcon", {})
    if fragment_size is not None:
        falcon_cfg["fragmentBytes"] = fragment_size
    if compression is not None:
        falcon_cfg["compression"] = compression

    temp_file = tempfile.NamedTemporaryFile(
        prefix="pqv2_remote_", suffix=".json", delete=False, mode="w", encoding="utf-8"
    )
    try:
        json.dump(config, temp_file, indent=2)
        temp_file.flush()
    finally:
        temp_file.close()
    return pathlib.Path(temp_file.name)


def plan_parameters(args: argparse.Namespace, base_config: Dict) -> Iterable[SweepParameters]:
    falcon_cfg = base_config.get("scenario", {}).get("falcon", {})
    default_fragment = falcon_cfg.get("fragmentBytes")
    default_compression = falcon_cfg.get("compression")

    fragment_sizes = args.fragment_sizes or [default_fragment]
    compression_modes = args.compression or [default_compression]

    # Normalise None values gracefully
    if fragment_sizes == [None]:
        fragment_sizes = [default_fragment]
    if compression_modes == [None]:
        compression_modes = [default_compression]

    seen = set()
    for fragment_size in fragment_sizes:
        for comp in compression_modes:
            key = (fragment_size, comp)
            if key in seen:
                continue
            seen.add(key)
            yield SweepParameters(fragment_size=fragment_size, compression=comp)


def launch_process(command: List[str],
                   env: Dict[str, str],
                   log_path: Optional[pathlib.Path]) -> Tuple[subprocess.Popen, Optional[IO[str]]]:
    stdout_target = subprocess.PIPE
    log_handle: Optional[IO[str]] = None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_handle = log_path.open("w", encoding="utf-8")
        stdout_target = log_handle
    process = subprocess.Popen(
        command,
        stdout=stdout_target,
        stderr=subprocess.STDOUT,
        env=env
    )
    return process, log_handle


def collect_output(process: subprocess.Popen,
                   log_handle: Optional[IO[str]],
                   log_path: Optional[pathlib.Path]) -> None:
    if log_handle is not None:
        process.wait()
        log_handle.flush()
        log_handle.close()
        return

    output = process.communicate()[0] or b""
    decoded = output.decode("utf-8", errors="replace")
    if decoded.strip():
        print(decoded)


def run_iteration(binary: pathlib.Path,
                  config_path: pathlib.Path,
                  env_template: Dict[str, str],
                  run_id: int,
                  log_dir: Optional[pathlib.Path],
                  sleep_ms: int) -> None:
    env = dict(env_template)
    env["V2X_METRICS_RUN"] = str(run_id)
    env["V2X_CONFIG_PATH"] = str(config_path)

    receiver_log = None
    transmitter_log = None
    if log_dir is not None:
        receiver_log = log_dir / f"receiver_run_{run_id:04d}.log"
        transmitter_log = log_dir / f"transmitter_run_{run_id:04d}.log"

    receiver_cmd = [str(binary), "dsrc", "receiver", "nogui", "--test"]
    transmitter_cmd = [str(binary), "dsrc", "transmitter", "nogui", "--test"]

    receiver_proc, receiver_handle = launch_process(receiver_cmd, env, receiver_log)
    time.sleep(max(sleep_ms, 0) / 1000.0)
    transmitter_proc, transmitter_handle = launch_process(transmitter_cmd, env, transmitter_log)

    transmitter_code = transmitter_proc.wait()
    collect_output(transmitter_proc, transmitter_handle, transmitter_log)
    receiver_code = receiver_proc.wait()
    collect_output(receiver_proc, receiver_handle, receiver_log)

    if transmitter_code != 0:
        raise RuntimeError(f"Transmitter exited with status {transmitter_code} for run {run_id}")
    if receiver_code != 0:
        raise RuntimeError(f"Receiver exited with status {receiver_code} for run {run_id}")


def read_metrics(metrics_path: pathlib.Path, note_filter: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    if not metrics_path.exists():
        return results
    with metrics_path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if note_filter and row.get("note", "") != note_filter:
                continue
            results.append(row)
    return results


def summarise_metrics(rows: List[Dict[str, str]]) -> Dict[str, float]:
    totals = [float(row["total_us"]) for row in rows if row.get("total_us")]
    if not totals:
        return {}
    summary = {
        "count": len(totals),
        "avg_total_us": statistics.mean(totals),
        "stdev_total_us": statistics.pstdev(totals) if len(totals) > 1 else 0.0,
        "avg_total_ms": statistics.mean(totals) / 1000.0,
    }
    return summary


def main() -> None:
    args = parse_args()

    if args.scheme == "ecdsa" and args.fragment_sizes:
        print("Warning: fragment sizes are ignored for ECDSA runs.")

    base_config = load_base_config(args.config)
    ensure_metrics_header(args.metrics_file)

    plan = list(plan_parameters(args, base_config))
    if not plan:
        plan = [SweepParameters(fragment_size=None, compression=None)]

    if args.dry_run:
        print("Dry run plan:")
        for params in plan:
            print(f"  fragment_size={params.fragment_size}, compression={params.compression}")
        return

    if not args.binary.exists():
        raise FileNotFoundError(f"Executable not found at {args.binary}")

    env_template = os.environ.copy()
    env_template["V2X_SIGNATURE_SCHEME"] = args.scheme
    env_template["V2X_METRICS_FILE"] = str(args.metrics_file)
    if args.packet_loss > 0.0:
        env_template["V2X_PACKET_LOSS_RATE"] = f"{args.packet_loss:.6f}"
    else:
        env_template.pop("V2X_PACKET_LOSS_RATE", None)
    if args.base_port is not None:
        env_template["V2X_TEST_PORT"] = str(args.base_port)
    else:
        env_template.pop("V2X_TEST_PORT", None)
    note_base = args.note.strip()

    for params in plan:
        run_note = f"scheme={args.scheme}"
        if params.fragment_size is not None:
            run_note += f";fragment={params.fragment_size}"
            env_template["V2X_FALCON_FRAGMENT_BYTES"] = str(params.fragment_size)
        elif "V2X_FALCON_FRAGMENT_BYTES" in env_template:
            env_template.pop("V2X_FALCON_FRAGMENT_BYTES", None)

        if params.compression is not None:
            env_template["V2X_FALCON_COMPRESSION"] = params.compression
            run_note += f";compression={params.compression}"
        elif "V2X_FALCON_COMPRESSION" in env_template:
            env_template.pop("V2X_FALCON_COMPRESSION", None)

        if args.packet_loss > 0.0:
            run_note += f";loss={args.packet_loss}"
        if args.base_port is not None:
            run_note += f";port={args.base_port}"

        if note_base:
            run_note += f";{note_base}"

        env_template["V2X_METRICS_NOTE"] = run_note

        temp_config = build_temp_config(
            base_config,
            args.scheme,
            args.vehicles,
            args.messages,
            params.fragment_size,
            params.compression,
            keep_file=args.keep_temp_config,
        )

        try:
            for run_index in range(args.runs):
                run_iteration(
                    binary=args.binary,
                    config_path=temp_config,
                    env_template=env_template,
                    run_id=run_index,
                    log_dir=args.log_dir,
                    sleep_ms=args.sleep_ms,
                )
        finally:
            if not args.keep_temp_config and temp_config.exists():
                temp_config.unlink(missing_ok=True)

        rows = read_metrics(args.metrics_file, run_note)
        summary = summarise_metrics(rows)
        if summary:
            print(f"Summary for {run_note}: "
                  f"{summary['count']} runs, "
                  f"avg_total_us={summary['avg_total_us']:.2f}, "
                  f"stdev_total_us={summary['stdev_total_us']:.2f}, "
                  f"avg_total_ms={summary['avg_total_ms']:.4f}")
        else:
            print(f"No metrics captured for {run_note}")


if __name__ == "__main__":
    main()
