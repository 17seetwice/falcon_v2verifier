#!/usr/bin/env python3
"""Summarise PQ-V2Verifier latency metrics and prepare reporting artefacts."""
from __future__ import annotations

import argparse
import csv
import json
import pathlib
import statistics
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

DEFAULT_METRICS = pathlib.Path("falcon_metrics.csv")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate summaries from V2X metrics CSV files")
    parser.add_argument("--metrics", type=pathlib.Path, default=DEFAULT_METRICS,
                        help="Metrics CSV produced by run_remote_falcon.py (default: %(default)s)")
    parser.add_argument("--filter", action="append", default=[],
                        help="Filter entries by key=value pairs present in the note column")
    parser.add_argument("--group", nargs="*", default=["scheme", "fragment", "compression", "loss"],
                        help="Note keys used for grouping (default: %(default)s)")
    parser.add_argument("--output-json", type=pathlib.Path, default=None,
                        help="Optional path to write the aggregated summary as JSON")
    parser.add_argument("--output-markdown", type=pathlib.Path, default=None,
                        help="Optional path to write a Markdown table summary")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress console output (useful when writing to files)")
    return parser.parse_args()


def parse_note(note: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not note:
        return result
    for chunk in note.split(";"):
        if not chunk:
            continue
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def matches_filters(note_fields: Dict[str, str], filters: Iterable[str]) -> bool:
    for item in filters:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if note_fields.get(key.strip()) != value.strip():
            return False
    return True


def group_metrics(rows: Iterable[Dict[str, str]], group_keys: Iterable[str]) -> Dict[Tuple, List[Dict[str, str]]]:
    grouped: Dict[Tuple, List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        note_fields = parse_note(row.get("note", ""))
        group_id = tuple(note_fields.get(key, "-") for key in group_keys)
        grouped[group_id].append({**row, **note_fields})
    return grouped


def summarise_group(group: List[Dict[str, str]]) -> Dict[str, float]:
    totals = [float(item["total_us"]) for item in group if item.get("total_us")]
    firsts = [float(item["first_us"]) for item in group if item.get("first_us")]
    lasts = [float(item["last_us"]) for item in group if item.get("last_us")]

    summary = {
        "count": len(totals),
        "avg_total_us": statistics.mean(totals) if totals else 0.0,
        "stdev_total_us": statistics.pstdev(totals) if len(totals) > 1 else 0.0,
        "avg_total_ms": statistics.mean(totals) / 1000.0 if totals else 0.0,
        "min_total_us": min(totals) if totals else 0.0,
        "max_total_us": max(totals) if totals else 0.0,
        "avg_first_us": statistics.mean(firsts) if firsts else 0.0,
        "avg_last_us": statistics.mean(lasts) if lasts else 0.0,
    }
    return summary


def load_rows(metrics_path: pathlib.Path, filters: Iterable[str]) -> List[Dict[str, str]]:
    if not metrics_path.exists():
        raise FileNotFoundError(f"Metrics file not found: {metrics_path}")
    with metrics_path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for row in reader:
            note_fields = parse_note(row.get("note", ""))
            if matches_filters(note_fields, filters):
                rows.append(row)
        return rows


def print_table(headers: List[str], data: List[List[str]]) -> None:
    widths = [len(h) for h in headers]
    for row in data:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    def format_row(row_values: List[str]) -> str:
        return " | ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(row_values))

    separator = "-+-".join("-" * w for w in widths)
    print(format_row(headers))
    print(separator)
    for row in data:
        print(format_row(row))


def write_markdown(headers: List[str], data: List[List[str]], output_path: pathlib.Path) -> None:
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("| " + " | ".join(headers) + " |\n")
        handle.write("| " + " | ".join(["---"] * len(headers)) + " |\n")
        for row in data:
            handle.write("| " + " | ".join(row) + " |\n")


def main() -> None:
    args = parse_args()
    rows = load_rows(args.metrics, args.filter)

    grouped = group_metrics(rows, args.group)
    headers = ["group"] + ["count", "avg_total_us", "stdev_total_us", "min_total_us", "max_total_us", "avg_total_ms"]
    table_rows: List[List[str]] = []
    json_output = {}

    for group_id, group_rows in sorted(grouped.items()):
        summary = summarise_group(group_rows)
        json_output[";".join(map(str, group_id))] = summary
        table_rows.append([
            ";".join(map(str, group_id)),
            str(summary["count"]),
            f"{summary['avg_total_us']:.2f}",
            f"{summary['stdev_total_us']:.2f}",
            f"{summary['min_total_us']:.2f}",
            f"{summary['max_total_us']:.2f}",
            f"{summary['avg_total_ms']:.4f}",
        ])

    if not args.quiet:
        print_table(headers, table_rows)

    if args.output_json:
        with args.output_json.open("w", encoding="utf-8") as handle:
            json.dump(json_output, handle, indent=2)

    if args.output_markdown:
        write_markdown(headers, table_rows, args.output_markdown)

if __name__ == "__main__":
    main()
