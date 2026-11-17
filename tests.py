"""Unit tests. Run with:  python -m unittest tests -v
The LLM is replaced by a fake client, so no API key or network is needed.
"""
import json
import unittest
from types import SimpleNamespace as NS

from fixtures import CASES, plan, rc
from llm import llm_review, parse_review, redact, run_tool
from reviewer import review, stricter
from rules import check_plan, floor_recommendation

DB_DESTROY = dict((c[0], c[1]) for c in CASES)["destroy_database"]
SAFE = dict((c[0], c[1]) for c in CASES)["safe_tag_update"]


def text_resp(text):
    return NS(stop_reason="end_turn", content=[NS(type="text", text=text)])


def tool_resp(address, tool_id="t1"):
    block = NS(type="tool_use", id=tool_id, name="get_resource_details", input={"address": address})
    return NS(stop_reason="tool_use", content=[block])


class FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.messages = NS(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class RuleTests(unittest.TestCase):
    def test_all_labelled_cases(self):
        for name, p, rules, rec in CASES:
            with self.subTest(name):
                findings = check_plan(p)
                self.assertEqual({f["rule"] for f in findings}, set(rules))
                self.assertEqual(floor_recommendation(findings), rec)

    def test_destroy_with_null_after_does_not_crash(self):
        self.assertTrue(check_plan(DB_DESTROY))


class LlmTests(unittest.TestCase):
    def test_tool_loop_returns_validated_review(self):
        client = FakeClient([
            tool_resp("aws_db_instance.main"),
            text_resp('{"summary": "Deletes the production database.", "recommendation": "block"}'),
        ])
        out = llm_review(DB_DESTROY, check_plan(DB_DESTROY), client=client)
        self.assertEqual(out["recommendation"], "block")
        # tool result was fed back to the model on the second call
        second_call_messages = client.calls[1]["messages"]
        self.assertEqual(second_call_messages[-1]["content"][0]["type"], "tool_result")

    def test_tool_refuses_addresses_not_in_plan(self):
        self.assertIn("error", run_tool(DB_DESTROY, "get_resource_details", {"address": "nope"}))
        self.assertIn("error", run_tool(DB_DESTROY, "delete_everything", {}))

    def test_secrets_are_redacted(self):
        out = redact({"db_password": "hunter2", "nested": {"api_token": "x", "name": "ok"}})
        self.assertEqual(out["db_password"], "***REDACTED***")
        self.assertEqual(out["nested"]["api_token"], "***REDACTED***")
        self.assertEqual(out["nested"]["name"], "ok")

    def test_invalid_model_output_is_rejected(self):
        for bad in ["not json", '{"summary": "x", "recommendation": "ship it"}', '{"recommendation": "approve"}']:
            with self.subTest(bad), self.assertRaises(ValueError):
                parse_review(bad)

    def test_turn_limit_stops_endless_tool_loop(self):
        client = FakeClient([tool_resp("aws_db_instance.main", f"t{i}") for i in range(10)])
        with self.assertRaises(RuntimeError):
            llm_review(DB_DESTROY, [], client=client, max_turns=3)


class GuardrailTests(unittest.TestCase):
    def test_llm_cannot_loosen_a_blocking_decision(self):
        """Real-failure guardrail: a model that says 'approve' on a DB delete must be overruled."""
        client = FakeClient([text_resp('{"summary": "Looks fine.", "recommendation": "approve"}')])
        result = review(DB_DESTROY, client=client)
        self.assertEqual(result["llm"]["recommendation"], "approve")
        self.assertEqual(result["recommendation"], "block")

    def test_llm_can_tighten_a_clean_plan(self):
        client = FakeClient([text_resp('{"summary": "Unusual, check manually.", "recommendation": "review"}')])
        self.assertEqual(review(SAFE, client=client)["recommendation"], "review")

    def test_llm_failure_falls_back_to_rules(self):
        client = FakeClient([text_resp("garbage output")])
        result = review(DB_DESTROY, client=client)
        self.assertIsNone(result["llm"])
        self.assertIn("ValueError", result["llm_error"])
        self.assertEqual(result["recommendation"], "block")

    def test_api_exception_falls_back_to_rules(self):
        def boom(**kwargs):
            raise ConnectionError("network down")
        client = NS(messages=NS(create=boom))
        result = review(DB_DESTROY, client=client)
        self.assertEqual(result["recommendation"], "block")
        self.assertIn("ConnectionError", result["llm_error"])

    def test_stricter(self):
        self.assertEqual(stricter("approve", "block"), "block")
        self.assertEqual(stricter("block", "approve"), "block")


if __name__ == "__main__":
    unittest.main()
