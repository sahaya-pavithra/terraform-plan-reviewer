# Terraform Plan Reviewer

A small tool that reviews `terraform plan` output before `apply`. Fixed safety rules decide the minimum risk level, and an LLM (optional) explains the risk in plain language. The LLM can make the decision stricter, never looser.

## Problem

Terraform plans can be long, and a destroyed database or an SSH port open to the world is easy to miss. This tool flags those changes automatically and can be used as a CI gate.

## How it works

```
terraform show -json plan.out > plan.json
        |
        v
  rules.py      deterministic checks -> findings + floor recommendation
        |
        v
  llm.py        model reads findings, may call read-only tool
                get_resource_details(address), returns JSON summary
        |
        v
  reviewer.py   final = stricter(rule floor, model recommendation)
                any LLM failure -> rules-only decision
```

**Rules (rules.py):** destroy / replace (stateful resources are CRITICAL), security group ingress open to `0.0.0.0/0` (CRITICAL on SSH/RDP/all ports), IAM `Action: "*"`, public S3 ACLs.

**Recommendation:** `approve` (exit 0), `review` (exit 1), `block` (exit 2).

## Controls and guardrails

| Concern | What the code does |
|---|---|
| Permissions | The model's only tool is read-only and only returns resources that exist in the plan. Unknown tools or addresses return an error. |
| Secrets | Fields named like password / secret / token / key / credential are redacted before the model sees them. |
| Output quality | Model output must be valid JSON with `recommendation` in approve/review/block and a non-empty summary, or it is rejected. |
| Model disagreement | The model cannot loosen a decision: a model saying "approve" on a database delete is overruled (`tests.py`, `GuardrailTests`). |
| Failures | API errors, bad output, or a tool loop past `max_turns` fall back to the rules-only decision and the error is reported. |
| Monitoring | Each review logs one JSON line to stderr: findings, decisions, whether the LLM was used, error, latency. |

## Run it

```
python reviewer.py example_plan.json --no-llm        # rules only, no dependencies
pip install anthropic
export ANTHROPIC_API_KEY=...                          # enables the AI summary
python reviewer.py example_plan.json
```

Optional: `REVIEWER_MODEL` env var selects the model.

## Evaluation and tests

```
python eval.py                  # 10 labelled plans: precision / recall of rules
python -m unittest tests -v     # 12 tests, LLM replaced by a fake client
```

Current result: 10/10 cases pass, precision 1.00, recall 1.00 on the labelled set.

## Limitations

- The eval set is small and hand-written, so 1.00 means "passes my cases", not "catches everything". It only covers a few AWS resource types.
- The LLM path is tested with a fake client. Run it with a real API key and check real outputs before trusting it.
- Not production-ready: no CI integration yet, no model-output quality evaluation beyond schema validation, and no real plans from live infrastructure in the eval set.

## Next steps

- Add real (sanitized) plans to the eval set and measure false positives.
- Add rules for more resource types and for Azure/GCP.
- Build an eval for the LLM summaries (e.g. does it mention every CRITICAL finding).
