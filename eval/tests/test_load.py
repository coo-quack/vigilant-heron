"""eval/load.py: latency percentiles and decision errors read from the access log."""

import json
import pathlib
import tempfile
import unittest

from support import load_script

load = load_script("load")


class Percentile(unittest.TestCase):
    def test_percentile_picks_the_nearest_rank(self):
        self.assertEqual(load.percentile([3.0, 1.0, 2.0], 0.5), 2.0)
        self.assertEqual(load.percentile(list(range(1, 101)), 0.99), 99)
        self.assertEqual(load.percentile([4.0], 0.95), 4.0)


class DecisionErrors(unittest.TestCase):
    def test_counts_decisions_and_failures_by_cause(self):
        lines = [
            "not json",
            json.dumps("a string"),
            json.dumps({"request_id": "", "decision_error": "timeout"}),
            json.dumps({"request_id": "load-1", "decision_error": ""}),
            json.dumps({"request_id": "load-2", "decision_error": "timeout"}),
            json.dumps({"request_id": "load-3", "decision_error": "timeout"}),
            json.dumps({"request_id": "load-4", "decision_error": "client_busy"}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "access.jsonl"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            decisions, counts = load.decision_errors(path)
        self.assertEqual(decisions, 4)
        self.assertEqual(counts, {"timeout": 2, "client_busy": 1})


if __name__ == "__main__":
    unittest.main()
