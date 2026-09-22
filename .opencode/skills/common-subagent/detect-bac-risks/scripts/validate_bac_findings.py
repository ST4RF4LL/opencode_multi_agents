#!/usr/bin/env python3
"""Replay the deterministic comparison from a published bundle; no target access."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="重算已封存的静态差分，核对完整结果账目。")
    parser.add_argument("--acp", required=True)
    parser.add_argument("--paths", required=True)
    parser.add_argument("--api-catalog", required=True)
    parser.add_argument("--findings", required=True)
    args = parser.parse_args()
    try:
        spec = importlib.util.spec_from_file_location("bac_comparison", Path(__file__).with_name("analyze_bac.py"))
        engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine)
        def read(path):
            return json.loads(Path(path).read_text(encoding="utf-8"))
        artifact = read(args.findings)
        observed = artifact.get("result", artifact)
        expected = engine.analyze(read(args.acp), read(args.paths), read(args.api_catalog))
        if observed != expected:
            raise ValueError("制品与当前输入的确定性重算结果不一致。")
        print(json.dumps({"valid": True, "candidates": len(expected["findings"]),
                          "analysis_complete": expected["summary"]["analysis_complete"],
                          "validation_status": "NOT_PERFORMED"}, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(f"越权差分核对失败：{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
