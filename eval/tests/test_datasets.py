"""The labelled datasets: row shape, labels, and the counts the README states."""

import collections
import json
import re
import unittest

from support import DATASET_DIR, EVAL_DIR

ID_PREFIX = {"dev": "dev-", "holdout": "hold-", "field": "field-", "adversarial": "adv-"}
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
REQUEST_KEYS = {"method", "path", "query", "headers", "content_type", "body"}


def read_split(name):
    with (DATASET_DIR / f"{name}.jsonl").open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def all_rows():
    for split in ID_PREFIX:
        for row in read_split(split):
            yield split, row


def inspect_body_bytes():
    template = (EVAL_DIR / "config.template.conf").read_text(encoding="utf-8")
    return int(re.search(r"^\s*inspect_body\s+(\d+);", template, re.MULTILINE).group(1))


class EveryRow(unittest.TestCase):
    def test_every_dataset_file_is_covered(self):
        files = {path.stem for path in DATASET_DIR.glob("*.jsonl")}
        self.assertEqual(files, set(ID_PREFIX))

    def test_rows_have_the_shape_run_py_sends(self):
        for split, prefix in ID_PREFIX.items():
            for row in read_split(split):
                with self.subTest(split=split, id=row.get("id")):
                    self.assertTrue(row["id"].startswith(prefix))
                    self.assertIn(row["label"], {"block", "allow"})
                    self.assertTrue(row["kind"])
                    self.assertTrue(row["note"])
                    request = row["request"]
                    self.assertEqual(set(request), REQUEST_KEYS)
                    self.assertIn(request["method"], METHODS)
                    self.assertTrue(request["path"].startswith("/"))
                    self.assertIsInstance(request["headers"], dict)
                    if request["body"] is not None:
                        self.assertIsInstance(request["body"], str)
                        self.assertTrue(request["content_type"], "a row with a body names its content type")

    def test_header_names_and_values_can_be_sent(self):
        # run.py sends rows with http.client, which encodes header values as Latin-1
        # and sets Host, X-Request-Id and Content-Length itself.
        reserved = {"host", "x-request-id", "content-length", "content-type"}
        for split, row in all_rows():
            for name, value in row["request"]["headers"].items():
                with self.subTest(split=split, id=row["id"], header=name):
                    self.assertNotIn(name.lower(), reserved)
                    self.assertIsNotNone(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name))
                    self.assertIsInstance(value, str)
                    value.encode("latin-1")
                    self.assertNotRegex(value, r"[\r\n]")

    def test_ids_are_unique_across_all_splits(self):
        ids = [row["id"] for _, row in all_rows()]
        duplicates = [item for item, count in collections.Counter(ids).items() if count > 1]
        self.assertEqual(duplicates, [])

    def test_multipart_bodies_use_their_boundary(self):
        multipart = 0
        for split, row in all_rows():
            content_type = row["request"]["content_type"] or ""
            if not content_type.startswith("multipart/form-data"):
                continue
            multipart += 1
            with self.subTest(split=split, id=row["id"]):
                boundary = re.search(r"boundary=([^;]+)", content_type).group(1)
                body = row["request"]["body"]
                self.assertTrue(body.startswith(f"--{boundary}\r\n"))
                self.assertTrue(body.endswith(f"--{boundary}--\r\n"))
        self.assertGreater(multipart, 0)


class DevAndHoldout(unittest.TestCase):
    def test_each_split_has_the_counts_the_readme_states(self):
        # eval/README.md: 211 rows each, 93 block and 118 allow.
        for split in ("dev", "holdout"):
            labels = collections.Counter(row["label"] for row in read_split(split))
            with self.subTest(split=split):
                self.assertEqual(labels, {"block": 93, "allow": 118})

    def test_the_japanese_rows_are_the_last_eleven(self):
        # eval/README.md: ids ending in 201 to 211, eight allow rows and three
        # prompt-injection block rows.
        for split in ("dev", "holdout"):
            prefix = ID_PREFIX[split]
            rows = {row["id"]: row for row in read_split(split)}
            japanese = [rows[f"{prefix}{number}"] for number in range(201, 212)]
            with self.subTest(split=split):
                self.assertEqual([row["label"] for row in japanese], ["allow"] * 8 + ["block"] * 3)
                self.assertEqual({row["kind"] for row in japanese[8:]}, {"prompt_injection"})


class Adversarial(unittest.TestCase):
    def setUp(self):
        self.rows = read_split("adversarial")

    def test_kinds_have_the_counts_and_labels_the_readme_states(self):
        counts = collections.Counter((row["kind"], row["label"]) for row in self.rows)
        self.assertEqual(
            counts,
            {
                ("adv_judge", "block"): 16,
                ("adv_app", "block"): 15,
                ("adv_limit", "block"): 2,
                ("adv_allow", "allow"): 15,
            },
        )

    def padded_and_file_part_rows(self):
        rows = [row for row in self.rows if row["kind"] == "adv_limit"]
        padded = [row for row in rows if "filename=" not in row["request"]["body"]]
        file_part = [row for row in rows if "filename=" in row["request"]["body"]]
        return padded, file_part

    def test_limit_rows_are_out_of_the_judges_sight(self):
        padded, file_part = self.padded_and_file_part_rows()
        self.assertEqual((len(padded), len(file_part)), (1, 1))
        body = padded[0]["request"]["body"].encode("utf-8")
        self.assertGreater(body.index(b"UNION"), inspect_body_bytes())

    def test_every_other_body_fits_in_the_inspected_bytes(self):
        limit = inspect_body_bytes()
        padded, _ = self.padded_and_file_part_rows()
        others = [row for row in self.rows if row is not padded[0] and row["request"]["body"] is not None]
        self.assertGreater(len(others), 30)
        for row in others:
            with self.subTest(id=row["id"]):
                self.assertLessEqual(len(row["request"]["body"].encode("utf-8")), limit)


if __name__ == "__main__":
    unittest.main()
