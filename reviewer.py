"""Terraform plan reviewer: rules decide the floor, the LLM explains, failures fall back.

Usage:
    terraform plan -out=plan.out && terraform show -json plan.out > plan.json
    python reviewer.py plan.json            # rules + LLM (needs ANTHROPIC_API_KEY)
    python reviewer.py plan.json --no-llm   # rules only

Exit codes: 0 approve, 1 review, 2 block (usable as a CI gate).
"""
import argparse
import json
import logging
import os
import sys
import time

from rules import check_plan, floor_recommendation

log = logging.getLogger("plan_reviewer")
STRICTNESS = {"approve": 0, "review": 1, "block": 2}
EXIT_CODES = {"approve": 0, "review": 1, "block": 2}


def stricter(a, b):
    return a if STRICTNESS[a] >= STRICTNESS[b] else b


def review(plan, use_llm=True, client=None):
    started = time.time()
    findings = check_plan(plan)
    floor = floor_recommendation(findings)
    result = {
        "findings": findings,
        "rule_recommendation": floor,
        "llm": None,
        "llm_error": None,
        "recommendation": floor,
    }
    if use_llm:
        try:
            from llm import llm_review
            llm = llm_review(plan, findings, client=client)
            result["llm"] = llm
            # Guardrail: the model can tighten the decision, never loosen it.
            result["recommendation"] = stricter(floor, llm["recommendation"])
        except Exception as exc:  # any LLM failure falls back to rules only
            result["llm_error"] = f"{type(exc).__name__}: {exc}"
    log.info(json.dumps({
        "event": "plan_reviewed",
        "findings": len(findings),
        "rule_recommendation": floor,
        "final_recommendation": result["recommendation"],
        "llm_used": result["llm"] is not None,
        "llm_error": result["llm_error"],
        "latency_ms": int((time.time() - started) * 1000),
    }))
    return result


def format_report(result):
    lines = [f"RECOMMENDATION: {result['recommendation'].upper()}", ""]
    if result["findings"]:
        lines.append("Findings:")
        for f in result["findings"]:
            lines.append(f"  [{f['severity']}] {f['rule']} - {f['address']}: {f['message']}")
    else:
        lines.append("Findings: none")
    if result["llm"]:
        lines += ["", "AI summary:", f"  {result['llm']['summary']}"]
    elif result["llm_error"]:
        lines += ["", f"AI summary unavailable ({result['llm_error']}); rules-only decision used."]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review a Terraform plan JSON file")
    parser.add_argument("plan_json")
    parser.add_argument("--no-llm", action="store_true", help="rules only")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")

    with open(args.plan_json) as fh:
        plan = json.load(fh)

    use_llm = not args.no_llm and bool(os.environ.get("ANTHROPIC_API_KEY"))
    if not args.no_llm and not use_llm:
        print("Note: ANTHROPIC_API_KEY not set, running rules only.\n", file=sys.stderr)

    result = review(plan, use_llm=use_llm)
    print(format_report(result))
    return EXIT_CODES[result["recommendation"]]


if __name__ == "__main__":
    sys.exit(main())
