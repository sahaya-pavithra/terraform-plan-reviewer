"""LLM layer: the model explains risk and may call one read-only tool.

Controls:
- Tool is read-only and only returns resources that exist in the plan.
- Secret-looking fields are redacted before the model sees them.
- Model output must be valid JSON with an allowed recommendation, or it is rejected.
- Turn limit prevents endless tool loops.
"""
import json
import os
import re

MODEL_DEFAULT = "claude-sonnet-5-5"
VALID_RECOMMENDATIONS = ("approve", "review", "block")
SENSITIVE = re.compile(r"(password|secret|token|key|credential)", re.I)

SYSTEM = (
    "You review Terraform plans for an engineer about to run apply. "
    "You receive a list of changes and findings from a fixed rule engine. "
    "You may call get_resource_details to inspect a specific resource. "
    "Reply with ONLY a JSON object: "
    '{"summary": "<2-4 sentences, plain language, what could go wrong>", '
    '"recommendation": "approve" | "review" | "block"}. '
    "Do not invent resources or facts that are not in the data."
)

TOOLS = [
    {
        "name": "get_resource_details",
        "description": "Read-only. Returns the before/after values of one resource in the plan.",
        "input_schema": {
            "type": "object",
            "properties": {"address": {"type": "string", "description": "Terraform resource address"}},
            "required": ["address"],
        },
    }
]


def redact(value):
    if isinstance(value, dict):
        return {k: ("***REDACTED***" if SENSITIVE.search(k) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def run_tool(plan, name, tool_input):
    if name != "get_resource_details":
        return {"error": f"unknown tool: {name}"}
    address = (tool_input or {}).get("address")
    for rc in plan.get("resource_changes") or []:
        if rc.get("address") == address:
            change = rc.get("change") or {}
            return redact({
                "address": address,
                "type": rc.get("type"),
                "actions": change.get("actions"),
                "before": change.get("before"),
                "after": change.get("after"),
            })
    return {"error": "address not found in plan"}


def parse_review(text):
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model output")
    data = json.loads(text[start:end + 1])
    if data.get("recommendation") not in VALID_RECOMMENDATIONS:
        raise ValueError("invalid recommendation value")
    summary = data.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("missing summary")
    return {"summary": summary.strip(), "recommendation": data["recommendation"]}


def llm_review(plan, findings, client=None, model=None, max_turns=6):
    if client is None:
        import anthropic  # imported lazily so rules-only mode needs no dependency
        client = anthropic.Anthropic()
    model = model or os.environ.get("REVIEWER_MODEL", MODEL_DEFAULT)

    changes = [
        {"address": rc.get("address"), "type": rc.get("type"), "actions": _actions(rc)}
        for rc in plan.get("resource_changes") or []
    ]
    messages = [{"role": "user", "content": json.dumps({"changes": changes, "rule_findings": findings})}]

    for _ in range(max_turns):
        resp = client.messages.create(
            model=model, max_tokens=1024, system=SYSTEM, tools=TOOLS, messages=messages
        )
        if resp.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": resp.content})
            results = []
            for block in resp.content:
                if block.type == "tool_use":
                    out = run_tool(plan, block.name, block.input)
                    results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(out),
                    })
            messages.append({"role": "user", "content": results})
            continue
        text = "".join(b.text for b in resp.content if b.type == "text")
        return parse_review(text)
    raise RuntimeError("model did not finish within max_turns")


def _actions(rc):
    return (rc.get("change") or {}).get("actions") or []
