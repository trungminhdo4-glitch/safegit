"""Audit queries stay bounded and return the latest matching valid records."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import tracemalloc
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from safegit import cli, receipt


class AuditQueryTests(unittest.TestCase):
    path: pathlib.Path = pathlib.Path()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="safegit-audit-query-")
        self.addCleanup(tmp.cleanup)
        self.path = pathlib.Path(tmp.name) / "audit.jsonl"

    def write_records(self) -> None:
        records = [
            {"verdict": verdict, "reason_code": str(index)}
            for index, verdict in enumerate(["DENY", "ALLOW", "DENY", "UNKNOWN", "ALLOW"])
        ]
        self.path.write_text("\n".join(map(json.dumps, records)) + "\n", encoding="utf-8")

    def test_filter_precedes_tail_and_keeps_log_order(self) -> None:
        self.write_records()
        entries = receipt.read_audit(self.path, limit=2, verdict="DENY")
        self.assertEqual([entry["reason_code"] for entry in entries], ["0", "2"])
        self.assertEqual(receipt.read_audit(self.path, limit=1, verdict="DENY"), entries[-1:])
        self.assertEqual(receipt.read_audit(self.path, verdict="REQUIRE_OWNER"), [])

    def test_summary_uses_the_same_filter_over_the_whole_log(self) -> None:
        self.write_records()
        summary = receipt.summarize_audit(self.path, verdict="DENY")
        self.assertEqual(summary.entries, 2)
        self.assertEqual(summary.verdicts, {"DENY": 2})
        self.assertEqual(receipt.summarize_audit(self.path).entries, 5)

    def test_invalid_lines_do_not_hide_valid_tail_records(self) -> None:
        self.path.write_bytes(
            b'{"verdict":"DENY"}\r\nnull\n[]\n42\n"text"\n{partial\n'
            b'{"verdict":"\xff"}\n\n{"verdict":"ALLOW"}'
        )
        self.assertEqual(
            receipt.read_audit(self.path, limit=2), [{"verdict": "DENY"}, {"verdict": "ALLOW"}]
        )
        self.assertEqual(receipt.summarize_audit(self.path).verdicts, {"DENY": 1, "ALLOW": 1})

    def test_oversized_and_deeply_nested_lines_are_skipped(self) -> None:
        oversized = b'{"verdict":"DENY","padding":"' + b"x" * 100_000 + b'"}\n'
        nested = b"[" * 2000 + b"0" + b"]" * 2000 + b"\n"
        self.path.write_bytes(oversized + nested + b'{"verdict":"ALLOW"}\n')
        self.assertEqual(receipt.read_audit(self.path), [{"verdict": "ALLOW"}])
        self.assertEqual(receipt.summarize_audit(self.path).entries, 1)

    def test_missing_and_unreadable_logs_keep_best_effort_behavior(self) -> None:
        self.assertEqual(receipt.read_audit(self.path), [])
        self.assertEqual(receipt.summarize_audit(self.path).entries, 0)
        self.write_records()
        with mock.patch.object(pathlib.Path, "open", side_effect=PermissionError):
            self.assertEqual(receipt.read_audit(self.path), [])
            self.assertEqual(receipt.summarize_audit(self.path).entries, 0)

    def test_queries_do_not_materialize_the_entire_log(self) -> None:
        line = json.dumps({"verdict": "ALLOW", "padding": "x" * 1000}) + "\n"
        with self.path.open("w", encoding="utf-8") as handle:
            for _ in range(10_000):
                handle.write(line)
        tracemalloc.start()
        try:
            self.assertEqual(len(receipt.read_audit(self.path, limit=3)), 3)
            self.assertEqual(receipt.summarize_audit(self.path).entries, 10_000)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 2_000_000, "a 10 MB log must not be loaded into memory")

    def run_audit(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(["audit", "--path", str(self.path), *args])
            except SystemExit as exc:
                code = int(str(exc.code))
        return code, out.getvalue(), err.getvalue()

    def test_cli_filter_applies_to_json_text_and_summary(self) -> None:
        self.write_records()
        code, out, err = self.run_audit("--verdict", "DENY", "--tail", "1", "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), [{"verdict": "DENY", "reason_code": "2"}])
        code, out, err = self.run_audit("--verdict", "DENY")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(out.splitlines()), 2)
        self.assertNotIn("ALLOW", out)
        code, out, err = self.run_audit("--verdict", "DENY", "--summary", "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["verdicts"], {"DENY": 2})

    def test_cli_rejects_unknown_verdict_without_reading_log(self) -> None:
        with mock.patch.object(receipt, "read_audit") as read:
            code, out, err = self.run_audit("--verdict", "DNEY")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("invalid choice", err)
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
