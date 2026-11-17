"""Deterministic risk rules for Terraform plan JSON.

Input is the output of:  terraform show -json plan.out > plan.json
These rules are the safety floor: the LLM can add explanation, but it can
never make the final recommendation less strict than what the rules decide.
"""
import json

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

STATEFUL_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_s3_bucket",
    "aws_dynamodb_table",
    "aws_ebs_volume",
    "aws_efs_file_system",
    "google_sql_database_instance",
    "azurerm_mssql_database",
}

ADMIN_PORTS = (22, 3389)
OPEN_CIDRS = ("0.0.0.0/0", "::/0")
IAM_POLICY_TYPES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}
PUBLIC_ACLS = {"public-read", "public-read-write"}


def _finding(rule, severity, address, message):
    return {"rule": rule, "severity": severity, "address": address, "message": message}


def _actions(rc):
    return (rc.get("change") or {}).get("actions") or []


def _after(rc):
    return (rc.get("change") or {}).get("after") or {}


def _is_destroy(actions):
    return "delete" in actions and "create" not in actions


def _is_replace(actions):
    return "delete" in actions and "create" in actions


def _writes(actions):
    return "create" in actions or "update" in actions


def _check_destroy_replace(rc):
    actions = _actions(rc)
    addr, rtype = rc.get("address"), rc.get("type")
    stateful = rtype in STATEFUL_TYPES
    if _is_destroy(actions):
        sev = "CRITICAL" if stateful else "HIGH"
        note = " (stateful resource: data loss risk)" if stateful else ""
        return [_finding("DESTROY", sev, addr, f"{rtype} will be destroyed{note}")]
    if _is_replace(actions):
        sev = "CRITICAL" if stateful else "HIGH"
        note = " (stateful resource: data loss risk)" if stateful else ""
        return [_finding("REPLACE", sev, addr, f"{rtype} will be destroyed and recreated{note}")]
    return []


def _exposes_admin(rule):
    if str(rule.get("protocol")) == "-1":
        return True
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if lo is None or hi is None:
        return False
    return any(lo <= p <= hi for p in ADMIN_PORTS)


def _ingress_rules(rc):
    after = _after(rc)
    rtype = rc.get("type")
    if rtype == "aws_security_group":
        return after.get("ingress") or []
    if rtype == "aws_security_group_rule" and after.get("type") == "ingress":
        return [after]
    return []


def _check_open_ingress(rc):
    if not _writes(_actions(rc)):
        return []
    out = []
    for rule in _ingress_rules(rc):
        cidrs = (rule.get("cidr_blocks") or []) + (rule.get("ipv6_cidr_blocks") or [])
        if any(c in OPEN_CIDRS for c in cidrs):
            admin = _exposes_admin(rule)
            sev = "CRITICAL" if admin else "HIGH"
            port = f"{rule.get('from_port')}-{rule.get('to_port')}"
            what = "admin/all ports" if admin else f"port(s) {port}"
            out.append(_finding("OPEN_INGRESS", sev, rc.get("address"),
                                f"Ingress open to the internet on {what}"))
    return out


def _statements(policy_json):
    try:
        doc = json.loads(policy_json) if isinstance(policy_json, str) else policy_json
    except (TypeError, ValueError):
        return []
    stmts = (doc or {}).get("Statement", [])
    return [stmts] if isinstance(stmts, dict) else list(stmts or [])


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _check_iam_wildcard(rc):
    if rc.get("type") not in IAM_POLICY_TYPES or not _writes(_actions(rc)):
        return []
    out = []
    for st in _statements(_after(rc).get("policy")):
        if st.get("Effect") != "Allow":
            continue
        if "*" in _as_list(st.get("Action", [])):
            all_resources = "*" in _as_list(st.get("Resource", []))
            sev = "CRITICAL" if all_resources else "HIGH"
            msg = "IAM policy allows Action '*'" + (" on Resource '*'" if all_resources else "")
            out.append(_finding("IAM_WILDCARD", sev, rc.get("address"), msg))
    return out


def _check_public_acl(rc):
    if not _writes(_actions(rc)):
        return []
    if rc.get("type") in ("aws_s3_bucket", "aws_s3_bucket_acl"):
        if _after(rc).get("acl") in PUBLIC_ACLS:
            return [_finding("PUBLIC_ACL", "HIGH", rc.get("address"),
                             f"S3 ACL is {_after(rc).get('acl')}")]
    return []


CHECKS = (_check_destroy_replace, _check_open_ingress, _check_iam_wildcard, _check_public_acl)


def check_plan(plan):
    """Return findings sorted most severe first."""
    findings = []
    for rc in plan.get("resource_changes") or []:
        for check in CHECKS:
            findings.extend(check(rc))
    return sorted(findings, key=lambda f: -SEVERITY_ORDER[f["severity"]])


def floor_recommendation(findings):
    """CRITICAL -> block, HIGH -> review, otherwise approve."""
    sevs = {f["severity"] for f in findings}
    if "CRITICAL" in sevs:
        return "block"
    if "HIGH" in sevs:
        return "review"
    return "approve"
