"""Labelled sample plans used by eval.py and tests.py."""
import json


def rc(address, rtype, actions, before=None, after=None):
    return {
        "address": address,
        "type": rtype,
        "change": {"actions": actions, "before": before, "after": after},
    }


def plan(*changes):
    return {"resource_changes": list(changes)}


def sg(port_from, port_to, cidr, protocol="tcp"):
    return {
        "ingress": [{
            "from_port": port_from, "to_port": port_to, "protocol": protocol,
            "cidr_blocks": [cidr], "ipv6_cidr_blocks": [],
        }]
    }


ADMIN_POLICY = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
S3_READ_POLICY = json.dumps({"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]})

# name, plan, expected rule ids, expected rule-only recommendation
CASES = [
    ("safe_tag_update",
     plan(rc("aws_instance.web", "aws_instance", ["update"], {"tags": {}}, {"tags": {"env": "dev"}})),
     [], "approve"),
    ("create_only",
     plan(rc("aws_instance.new", "aws_instance", ["create"], None, {"ami": "ami-1"})),
     [], "approve"),
    ("destroy_database",
     plan(rc("aws_db_instance.main", "aws_db_instance", ["delete"], {"engine": "postgres"}, None)),
     ["DESTROY"], "block"),
    ("replace_ec2",
     plan(rc("aws_instance.web", "aws_instance", ["delete", "create"], {"ami": "a"}, {"ami": "b"})),
     ["REPLACE"], "review"),
    ("open_ssh_to_world",
     plan(rc("aws_security_group.bastion", "aws_security_group", ["create"], None, sg(22, 22, "0.0.0.0/0"))),
     ["OPEN_INGRESS"], "block"),
    ("open_https_to_world",
     plan(rc("aws_security_group.lb", "aws_security_group", ["create"], None, sg(443, 443, "0.0.0.0/0"))),
     ["OPEN_INGRESS"], "review"),
    ("private_ssh_ok",
     plan(rc("aws_security_group.bastion", "aws_security_group", ["create"], None, sg(22, 22, "10.0.0.0/8"))),
     [], "approve"),
    ("iam_admin_policy",
     plan(rc("aws_iam_policy.admin", "aws_iam_policy", ["create"], None, {"policy": ADMIN_POLICY})),
     ["IAM_WILDCARD"], "block"),
    ("iam_scoped_policy_ok",
     plan(rc("aws_iam_policy.read", "aws_iam_policy", ["create"], None, {"policy": S3_READ_POLICY})),
     [], "approve"),
    ("public_bucket",
     plan(rc("aws_s3_bucket_acl.site", "aws_s3_bucket_acl", ["create"], None, {"acl": "public-read"})),
     ["PUBLIC_ACL"], "review"),
]
