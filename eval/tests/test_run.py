"""eval/run.py: split selection, log parsing, the budget guard and the report."""

import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from support import DATASET_DIR, load_script

run = load_script("run")


def result(row_id, label, kind, attack, instruction, blocked=False):
    return {
        "id": row_id,
        "label": label,
        "kind": kind,
        "status": 403 if blocked else 200,
        "blocked": blocked,
        "action": "block" if blocked else "allow",
        "reason": "model",
        "attack": attack,
        "ai_instruction": instruction,
        "category": None,
        "input_tokens": 1000,
        "latency_ms": 100,
        "join_ok": True,
    }


class Splits(unittest.TestCase):
    def test_every_dataset_file_is_a_split_choice(self):
        for name in [path.stem for path in DATASET_DIR.glob("*.jsonl")] + ["both"]:
            with self.subTest(split=name):
                self.assertEqual(run.build_parser().parse_args(["--split", name]).split, name)

    def test_an_unknown_split_is_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            run.build_parser().parse_args(["--split", "nope"])

    def test_default_split_is_both(self):
        self.assertEqual(run.build_parser().parse_args([]).split, "both")

    def test_both_runs_dev_and_holdout_only(self):
        self.assertEqual(run.splits_to_run("both"), ["dev", "holdout"])
        self.assertEqual(run.splits_to_run("adversarial"), ["adversarial"])

    def test_load_rows_tags_each_row_with_its_split(self):
        rows = run.load_rows("both")
        self.assertEqual({row["split"] for row in rows}, {"dev", "holdout"})
        self.assertEqual({row["split"] for row in run.load_rows("adversarial")}, {"adversarial"})


class Numbers(unittest.TestCase):
    def test_to_float_and_to_int_read_log_strings(self):
        self.assertEqual(run.to_float("0.87"), 0.87)
        self.assertIsNone(run.to_float(""))
        self.assertIsNone(run.to_float(None))
        self.assertIsNone(run.to_float("n/a"))
        self.assertEqual(run.to_int("1500"), 1500)
        self.assertIsNone(run.to_int(""))
        self.assertIsNone(run.to_int("1.5"))

    def test_percentile_picks_the_nearest_rank(self):
        self.assertIsNone(run.percentile([], 0.5))
        self.assertEqual(run.percentile([5, 1, 3], 0.5), 3)
        self.assertEqual(run.percentile(list(range(1, 101)), 0.95), 95)
        self.assertEqual(run.percentile([7], 0.99), 7)

    def test_predicted_block_uses_both_scores_and_the_inclusive_threshold(self):
        record = {"attack": 0.7, "ai_instruction": 0.1}
        self.assertTrue(run.predicted_block(record, 0.7))
        self.assertFalse(run.predicted_block(record, 0.71))
        self.assertTrue(run.predicted_block({"attack": 0.0, "ai_instruction": run.INSTRUCTION_THRESHOLD}, 0.9))
        self.assertFalse(run.predicted_block({"attack": None, "ai_instruction": 1.0}, 0.5))


class LogIndexing(unittest.TestCase):
    def test_lines_are_indexed_by_request_id(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "access.jsonl"
            lines = [
                "not json",
                json.dumps(["a", "list"]),
                json.dumps({"request_id": "", "attack": "0.9"}),
                json.dumps({"request_id": "adv-001", "attack": "0.99", "ai_instruction": "", "input_tokens": "1124"}),
                json.dumps({"request_id": "adv-001", "attack": "0.5"}),
            ]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            index = run.LogIndex(path)
            try:
                events = index.wait_for("adv-001", timeout=5)
                missing = index.wait_for("adv-002", timeout=0.1)
            finally:
                index.close()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["attack"], 0.99)
        self.assertIsNone(events[0]["ai_instruction"])
        self.assertEqual(events[0]["input_tokens"], 1124)
        self.assertEqual(missing, [])
        self.assertEqual(set(index.events), {"adv-001"})

    def test_a_line_written_in_two_parts_is_read_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "access.jsonl"
            line = json.dumps({"request_id": "dev-001", "attack": "0.2"})
            path.write_text(line[:10], encoding="utf-8")
            index = run.LogIndex(path)
            try:
                self.assertEqual(index.wait_for("dev-001", timeout=0.2), [])
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(line[10:] + "\n")
                events = index.wait_for("dev-001", timeout=5)
            finally:
                index.close()
        self.assertEqual(len(events), 1)


class BudgetGuard(unittest.TestCase):
    def test_first_reservation_uses_the_fixed_estimate(self):
        # A price of 1,000,000 / JPY_PER_USD USD per million tokens makes one token cost 1 JPY.
        budget = run.Budget(base_yen=0, max_yen=10_000, usd_per_mtok=1_000_000 / run.JPY_PER_USD)
        self.assertAlmostEqual(budget.reserve(), run.FIRST_REQUEST_TOKEN_ESTIMATE)

    def test_reservation_is_the_larger_of_average_and_largest(self):
        budget = run.Budget(base_yen=0, max_yen=100_000, usd_per_mtok=1_000_000 / run.JPY_PER_USD)
        for tokens in (100, 100, 1000):
            budget.settle(budget.reserve(), tokens)
        self.assertAlmostEqual(budget.reserve(), 1000)

    def test_a_reservation_that_reaches_the_limit_exactly_is_allowed(self):
        estimate = run.Budget(base_yen=0, max_yen=100, usd_per_mtok=0.0375).reserve()
        budget = run.Budget(base_yen=0, max_yen=2 * estimate, usd_per_mtok=0.0375)
        self.assertIsNotNone(budget.reserve())
        self.assertIsNotNone(budget.reserve())
        self.assertIsNone(budget.reserve())

    def test_in_flight_reservations_count_against_the_limit(self):
        budget = run.Budget(base_yen=0, max_yen=3500, usd_per_mtok=1_000_000 / run.JPY_PER_USD)
        self.assertIsNotNone(budget.reserve())
        self.assertIsNotNone(budget.reserve())
        self.assertIsNone(budget.reserve())
        self.assertTrue(budget.stopped)
        self.assertIsNone(budget.reserve(), "a stopped budget stays stopped")

    def test_settling_replaces_the_reservation_with_real_tokens(self):
        budget = run.Budget(base_yen=5, max_yen=100_000, usd_per_mtok=1_000_000 / run.JPY_PER_USD)
        budget.settle(budget.reserve(), 200)
        budget.settle(budget.reserve(), None)
        self.assertAlmostEqual(budget.reserved_yen, 0)
        self.assertEqual(budget.run_tokens(), 200)
        self.assertAlmostEqual(budget.spent_yen(), 205)

    def test_base_spend_counts_against_the_limit(self):
        # The first reservation at the Jev price is 1500 tokens, about 0.0089 JPY.
        self.assertIsNotNone(run.Budget(base_yen=29.99, max_yen=30, usd_per_mtok=0.0375).reserve())
        self.assertIsNone(run.Budget(base_yen=29.995, max_yen=30, usd_per_mtok=0.0375).reserve())


class FakeLog:
    def __init__(self, events):
        self.events = events

    def wait_for(self, request_id, timeout=30):
        return list(self.events.get(request_id, []))


def event(method="GET", path="/", tokens=900, attack=0.1):
    return {"method": method, "path": path, "action": "allow", "reason": "model", "attack": attack,
            "ai_instruction": 0.0, "category": None, "input_tokens": tokens, "latency_ms": 50}


def row(row_id, method="GET", path="/"):
    return {"id": row_id, "label": "allow", "kind": "search",
            "request": {"method": method, "path": path, "query": None, "headers": {},
                        "content_type": None, "body": None}}


class Join(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(run, "send_row", return_value=(200, "action=allow"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.budget = run.Budget(base_yen=0, max_yen=100, usd_per_mtok=0.0375)

    def test_one_matching_event_is_joined_and_its_tokens_settled(self):
        result = run.run_row(row("dev-001"), 0, FakeLog({"dev-001": [event()]}), self.budget, "dev")
        self.assertTrue(result["join_ok"])
        self.assertEqual(result["attack"], 0.1)
        self.assertEqual(self.budget.run_tokens(), 900)
        self.assertAlmostEqual(self.budget.reserved_yen, 0)

    def test_a_missing_duplicated_or_different_event_stops_the_run(self):
        cases = {
            "none": [],
            "two": [event(), event()],
            "other method": [event(method="POST")],
            "other path": [event(path="/other")],
        }
        for name, events in cases.items():
            with self.subTest(case=name):
                budget = run.Budget(base_yen=0, max_yen=100, usd_per_mtok=0.0375)
                with self.assertRaises(run.JoinError):
                    run.run_row(row("dev-001"), 0, FakeLog({"dev-001": events}), budget, "dev")
                self.assertTrue(budget.stopped)
                self.assertAlmostEqual(budget.reserved_yen, 0)

    def test_a_send_error_releases_the_reservation(self):
        run.send_row.side_effect = OSError("refused")
        with self.assertRaises(OSError):
            run.run_row(row("dev-001"), 0, FakeLog({}), self.budget, "dev")
        self.assertAlmostEqual(self.budget.reserved_yen, 0)
        self.assertFalse(self.budget.stopped)

    def test_run_split_aborts_at_the_first_row_without_an_event(self):
        # eval/README.md: the run aborts with a clear error if any row has no
        # decision event, and rows after it are not sent.
        rows = [row("dev-001"), row("dev-002"), row("dev-003")]
        log = FakeLog({"dev-001": [event()], "dev-003": [event()]})
        with self.assertRaises(run.JoinError) as raised:
            run.run_split("dev", rows, 0, log, self.budget, 1)
        self.assertIn("dev-002", str(raised.exception))
        self.assertEqual(run.send_row.call_count, 2)

    def test_run_split_returns_results_in_dataset_order(self):
        rows = [row("dev-001"), row("dev-002"), row("dev-003")]
        log = FakeLog({row_id: [event()] for row_id in ("dev-001", "dev-002", "dev-003")})
        results = run.run_split("dev", rows, 0, log, self.budget, 3)
        self.assertEqual([item["id"] for item in results], ["dev-001", "dev-002", "dev-003"])


class Report(unittest.TestCase):
    def test_report_counts_misses_and_false_positives_at_the_primary_threshold(self):
        results = [
            result("adv-001", "block", "adv_judge", 0.99, 0.9, blocked=True),
            result("adv-032", "block", "adv_limit", 0.26, 0.02),
            result("adv-041", "allow", "adv_allow", 0.88, 0.98, blocked=True),
            result("adv-042", "allow", "adv_allow", 0.02, 0.17),
        ]
        text = run.report("adversarial", 4, results, False, 0, 0.0375)
        self.assertIn("## Split: adversarial", text)
        self.assertIn("- Labels: 2 block, 2 allow", text)
        self.assertIn("false negatives ['adv-032']", text)
        self.assertIn("false positives ['adv-041']", text)

    def test_report_marks_a_partial_run(self):
        text = run.report("dev", 10, [result("dev-001", "block", "xss", 0.9, 0.1, True)], True, 0, 0.0375)
        self.assertIn("Stopped by the budget guard: yes, partial run", text)


if __name__ == "__main__":
    unittest.main()
