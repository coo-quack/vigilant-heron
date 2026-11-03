"""eval/rules.py: rule blocks and the combined rule-or-model pipeline."""

import re
import unittest

from support import ROOT, load_script

rules = load_script("rules")


def item(row_id, label, kind, reason="model", action="allow", split="dev", rule_id=None):
    return {
        "id": row_id,
        "label": label,
        "kind": kind,
        "split": split,
        "reason": reason,
        "action": action,
        "rule_id": rule_id,
        "status": 200,
        "missing_log": False,
    }


class Thresholds(unittest.TestCase):
    def test_pipeline_thresholds_are_the_router_defaults(self):
        source = (ROOT / "src" / "config.rs").read_text(encoding="utf-8")
        block = float(re.search(r"const DEFAULT_BLOCK_THRESHOLD: f64 = ([0-9.]+);", source).group(1))
        instruction = float(re.search(r"const DEFAULT_INSTRUCTION_THRESHOLD: f64 = ([0-9.]+);", source).group(1))
        self.assertEqual(rules.MODEL_BLOCK_THRESHOLD, block)
        self.assertEqual(rules.MODEL_INSTRUCTION_THRESHOLD, instruction)


class RuleBlocked(unittest.TestCase):
    def test_only_a_rule_block_counts(self):
        self.assertTrue(rules.rule_blocked(item("dev-001", "block", "xss", reason="rule", action="block")))
        self.assertFalse(rules.rule_blocked(item("dev-002", "block", "xss", reason="model", action="block")))
        self.assertFalse(rules.rule_blocked(item("dev-003", "allow", "search", reason="skip_rule")))


class Pipeline(unittest.TestCase):
    def test_rule_or_model_score_blocks_and_credential_attacks_are_left_out(self):
        rule_results = [
            item("dev-001", "block", "sql_injection", reason="rule", action="block", rule_id="vh-sqli-001"),
            item("dev-002", "block", "sql_injection"),
            item("dev-003", "block", "sql_injection"),
            item("dev-004", "block", "credential_attack"),
            item("dev-005", "allow", "search"),
            item("dev-006", "allow", "search"),
            item("hold-001", "block", "xss", split="holdout"),
        ]
        scores = {
            "dev-001": {"attack": 0.1, "ai_instruction": 0.1},
            "dev-002": {"attack": rules.MODEL_BLOCK_THRESHOLD, "ai_instruction": 0.0},
            "dev-003": {"attack": None, "ai_instruction": None},
            "dev-004": {"attack": 0.99, "ai_instruction": 0.0},
            "dev-005": {"attack": 0.1, "ai_instruction": rules.MODEL_INSTRUCTION_THRESHOLD},
        }
        metrics = rules.pipeline_metrics(rule_results, scores, "dev")
        self.assertEqual(metrics["per_kind"]["sql_injection"], [2, 3])
        self.assertEqual(metrics["model_per_kind"]["sql_injection"], [1, 3])
        self.assertNotIn("credential_attack", metrics["per_kind"])
        self.assertEqual(metrics["allow_total"], 1)
        self.assertEqual(metrics["allow_flagged"], 1)
        self.assertEqual(metrics["flagged_ids"], ["dev-005"])
        self.assertEqual(metrics["missing"], 1)
        self.assertEqual(metrics["unscored_ids"], ["dev-003"])

    def test_ratio_formats_and_handles_an_empty_total(self):
        self.assertEqual(rules.ratio(1, 3), "1/3 (33.3%)")
        self.assertEqual(rules.ratio(0, 0), "n/a")


class RuleReport(unittest.TestCase):
    def test_allow_rows_hit_by_a_rule_or_a_skip_rule_are_listed(self):
        results = [
            item("dev-001", "block", "xss", reason="rule", action="block", rule_id="vh-xss-001"),
            item("dev-002", "allow", "search", reason="rule", action="block", rule_id="vh-sqli-002"),
            item("dev-003", "allow", "search", reason="skip_rule", rule_id="local-search"),
            item("dev-004", "allow", "search"),
        ]
        text = rules.rule_report(results, ["dev"])
        self.assertIn("block rows decided by a rule: 1; allow rows hit by a rule: 2", text)
        self.assertIn("| xss | 1 | 1 | vh-xss-001 x1 |", text)
        self.assertIn("| dev-002 | vh-sqli-002 | rule |", text)
        self.assertIn("| dev-003 | local-search | skip_rule |", text)


if __name__ == "__main__":
    unittest.main()
