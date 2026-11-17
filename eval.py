"""Evaluate the rule engine against labelled plans.

Reports per-case pass/fail plus precision and recall over rule ids.
Exit code 1 if any case fails, so it can run in CI.
"""
import sys

from fixtures import CASES
from rules import check_plan, floor_recommendation


def main():
    tp = fp = fn = 0
    failures = 0
    for name, plan, expected_rules, expected_rec in CASES:
        findings = check_plan(plan)
        got_rules = {f["rule"] for f in findings}
        want_rules = set(expected_rules)
        got_rec = floor_recommendation(findings)

        tp += len(got_rules & want_rules)
        fp += len(got_rules - want_rules)
        fn += len(want_rules - got_rules)

        ok = got_rules == want_rules and got_rec == expected_rec
        failures += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'}  {name:24s} rules={sorted(got_rules)} -> {got_rec}")
        if not ok:
            print(f"      expected rules={sorted(want_rules)} -> {expected_rec}")

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    print(f"\ncases: {len(CASES)}  failed: {failures}  precision: {precision:.2f}  recall: {recall:.2f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
