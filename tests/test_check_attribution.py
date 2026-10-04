#!/usr/bin/env python3
"""Local tests for scripts/check_attribution.py (stdlib only).

Builds a throwaway git repo, makes one branch per scenario, writes a fake
pull_request event payload, and runs the checker as a subprocess.
Run: python3 tests/test_check_attribution.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "scripts", "check_attribution.py")

BASE_FILES = {
    "LICENSE": "MIT License\n\nCopyright (c) 2026 Michael Gannotti\n",
    "NOTICE": "SMF Works example project\n",
    "README.md": "# Demo\n\n## Credits\nSee CREDITS.md.\n",
    "CREDITS.md": (
        "# Credits\n\n"
        "| Source | Link | License | What | Where | Version |\n|---|---|---|---|---|---|\n"
        "| Alpha Dev (@alpha), alpha-lib | https://github.com/alpha/alpha-lib | MIT | parser | `src/parse.py` | v1.0 |\n"
        "| Beta Org (@beta), beta-kit | https://github.com/beta/beta-kit | Apache-2.0 | icons | `assets/icons/` | unknown |\n"
        "| **EXAMPLE (not a real entry):** Jane Example | https://example.com | MIT | example | `example.py` | unknown |\n"
    ),
    "src/app.py": "print('hi')\n",
}
NEW_CREDIT = "| Gamma Co (@gamma), gamma-utils | https://github.com/gamma/gamma-utils | BSD-3-Clause | retry helper | `src/retry.py` | 2.3.1 |\n"
FOREIGN = "# Copyright (c) 2021 Gamma Co\n# SPDX-License-Identifier: BSD-3-Clause\ndef retry(): pass\n"


def sh(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, text=True).stdout.strip()


def body(sources):
    if sources is None:
        return "## Summary\nStuff.\n\n## Test plan\nRan it.\n"
    return f"## Summary\nStuff.\n\n## Sources\n{sources}\n\n## Test plan\nRan it.\n"


class AttributionCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.repo = cls.tmp.name
        sh(cls.repo, "init", "-q", "-b", "main")
        sh(cls.repo, "config", "user.email", "t@example.com")
        sh(cls.repo, "config", "user.name", "Test")
        for path, text in BASE_FILES.items():
            cls.write(path, text)
        sh(cls.repo, "add", "-A")
        sh(cls.repo, "commit", "-qm", "base")
        cls.base = sh(cls.repo, "rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def write(cls, path, text):
        full = os.path.join(cls.repo, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)

    def scenario(self, name, pr_body, changes=(), deletes=(), renames=(), labels=()):
        sh(self.repo, "checkout", "-q", "-B", name, self.base)
        for path, text in changes:
            self.write(path, text)
        for path in deletes:
            sh(self.repo, "rm", "-q", path)
        for old, new in renames:
            os.makedirs(os.path.join(self.repo, os.path.dirname(new) or "."), exist_ok=True)
            sh(self.repo, "mv", old, new)
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-q", "--allow-empty", "-m", name)
        head = sh(self.repo, "rev-parse", "HEAD")
        event = {"pull_request": {"number": 1, "body": pr_body,
                                  "labels": [{"name": l} for l in labels],
                                  "base": {"sha": self.base}, "head": {"sha": head}}}
        ev = os.path.join(self.tmp.name, f"{name}.event.json")
        with open(ev, "w") as fh:
            json.dump(event, fh)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        res = subprocess.run([sys.executable, SCRIPT, "--event", ev, "--repo", self.repo],
                             capture_output=True, text=True, env=env)
        out = res.stdout + res.stderr
        print(f"\n--- {name} (exit {res.returncode})\n{out.strip()}")
        return res.returncode, out

    def credits_plus(self, line=NEW_CREDIT):
        return ("CREDITS.md", BASE_FILES["CREDITS.md"] + line)

    # ---- pass cases
    def test_pass_none_no_reuse(self):
        code, out = self.scenario("pass-none", body("none"), [("src/new.py", "x = 1\n")])
        self.assertEqual(code, 0); self.assertNotIn("WARNING", out)

    def test_pass_none_variants_crlf(self):
        code, _ = self.scenario("pass-none-crlf", body("- None.").replace("\n", "\r\n"))
        self.assertEqual(code, 0)

    def test_pass_credited_reuse(self):
        code, out = self.scenario(
            "pass-credited",
            body("Gamma Co (@gamma), https://github.com/gamma/gamma-utils, BSD-3-Clause, retry helper"),
            [self.credits_plus(), ("src/retry.py", FOREIGN)])
        self.assertEqual(code, 0); self.assertNotIn("WARNING", out)

    def test_pass_own_copyright_header(self):
        code, out = self.scenario("pass-own-header", body("none"),
                                  [("src/mine.py", "# Copyright (c) 2026 Michael Gannotti\nx = 1\n")])
        self.assertEqual(code, 0); self.assertNotIn("WARNING", out)

    def test_pass_credits_reordered(self):
        lines = BASE_FILES["CREDITS.md"].splitlines(keepends=True)
        reordered = "".join(lines[:4] + [lines[5], lines[4], lines[6]])
        code, _ = self.scenario("pass-reorder", body("none"), [("CREDITS.md", reordered)])
        self.assertEqual(code, 0)

    def test_pass_example_row_removed(self):
        trimmed = "".join(BASE_FILES["CREDITS.md"].splitlines(keepends=True)[:-1])
        code, out = self.scenario("pass-example-removed", body("none"),
                                  [("CREDITS.md", trimmed)])
        self.assertEqual(code, 0); self.assertNotIn("credits-edit-ok", out)

    def test_pass_credits_removal_with_label(self):
        lines = BASE_FILES["CREDITS.md"].splitlines(keepends=True)
        trimmed = "".join(lines[:-2] + lines[-1:])
        code, out = self.scenario("pass-label", body("none"), [("CREDITS.md", trimmed)],
                                  labels=["credits-edit-ok"])
        self.assertEqual(code, 0); self.assertIn("allowed by the 'credits-edit-ok' label", out)

    def test_warn_foreign_copyright(self):
        code, out = self.scenario("warn-foreign", body("none"), [("src/acme.py", "/* Copyright 2019-2021 Acme Corp. All rights reserved. */\n")])
        self.assertEqual(code, 0); self.assertIn("'Acme Corp'", out)

    def test_warn_spdx_only(self):
        code, out = self.scenario("warn-spdx", body("none"), [("src/lib.js", "// SPDX-License-Identifier: Apache-2.0\n")])
        self.assertEqual(code, 0); self.assertIn("SPDX-License-Identifier 'Apache-2.0'", out)

    def test_warn_sources_url_mismatch(self):
        code, out = self.scenario("warn-mismatch",
                                  body("Delta (@delta) https://github.com/delta/delta-x MIT"),
                                  [self.credits_plus()])
        self.assertEqual(code, 0); self.assertIn("isn't in CREDITS.md", out)

    # ---- fail cases
    def test_fail_no_sources_section(self):
        code, out = self.scenario("fail-no-section", body(None))
        self.assertEqual(code, 1); self.assertIn("no \"## Sources\" section", out)

    def test_fail_null_body(self):
        code, _ = self.scenario("fail-null-body", None)
        self.assertEqual(code, 1)

    def test_fail_empty_sources_template_only(self):
        code, out = self.scenario("fail-empty", body("<!-- Required. If nothing was reused, write just: none -->"))
        self.assertEqual(code, 1); self.assertIn("is empty", out)

    def test_fail_sources_without_credits(self):
        code, out = self.scenario("fail-no-credits", body("Gamma Co https://github.com/gamma/gamma-utils"),
                                  [("src/retry.py", FOREIGN)])
        self.assertEqual(code, 1); self.assertIn("wasn't changed", out)

    def test_fail_license_deleted(self):
        code, out = self.scenario("fail-license-del", body("none"), deletes=["LICENSE"])
        self.assertEqual(code, 1); self.assertIn("LICENSE is deleted", out)

    def test_fail_notice_emptied(self):
        code, out = self.scenario("fail-notice-empty", body("none"), [("NOTICE", "\n")])
        self.assertEqual(code, 1); self.assertIn("NOTICE is empty", out)

    def test_fail_license_renamed_away(self):
        code, out = self.scenario("fail-license-rename", body("none"), renames=[("LICENSE", "docs/old.txt")])
        self.assertEqual(code, 1); self.assertIn("renamed", out)

    def test_fail_credits_line_removed(self):
        lines = BASE_FILES["CREDITS.md"].splitlines(keepends=True)
        trimmed = "".join(lines[:-2] + lines[-1:])
        code, out = self.scenario("fail-credits-removed", body("none"), [("CREDITS.md", trimmed)])
        self.assertEqual(code, 1); self.assertIn("credits-edit-ok", out)

    def test_fail_credits_deleted(self):
        code, _ = self.scenario("fail-credits-deleted", body("none"), deletes=["CREDITS.md"])
        self.assertEqual(code, 1)

    def test_label_does_not_excuse_license_delete(self):
        code, _ = self.scenario("fail-license-del-label", body("none"), deletes=["NOTICE"],
                                labels=["credits-edit-ok"])
        self.assertEqual(code, 1)

    def test_license_removal_label_allows_license_delete(self):
        code, out = self.scenario("warn-license-del-label", body("none"), deletes=["LICENSE"],
                                  labels=["license-removal-ok"])
        self.assertEqual(code, 0)
        self.assertIn("LICENSE is deleted", out)
        self.assertIn("license-removal-ok", out)

    def test_license_removal_label_allows_notice_empty(self):
        code, out = self.scenario("warn-notice-empty-label", body("none"), [("NOTICE", "\n")],
                                  labels=["license-removal-ok"])
        self.assertEqual(code, 0)
        self.assertIn("NOTICE is empty", out)
        self.assertIn("license-removal-ok", out)

    def test_license_removal_label_allows_license_renamed_away(self):
        code, out = self.scenario("warn-license-rename-label", body("none"),
                                  renames=[("LICENSE", "docs/old.txt")], labels=["license-removal-ok"])
        self.assertEqual(code, 0)
        self.assertIn("LICENSE was renamed to docs/old.txt", out)
        self.assertIn("license-removal-ok", out)

    # ---- header matching: only real header lines count (regression for the
    # false positives on the kit's own docstring and test fixture)
    def test_no_warn_copyright_mentioned_in_prose_or_string(self):
        prose = ('"""Helper.\n\n  * warns when a file carries a copyright or SPDX header\n"""\n'
                 'FIXTURE = "# Copyright (c) 2021 Gamma Co\\n# SPDX-License-Identifier: BSD-3-Clause\\n"\n'
                 'msg = f"copyright header for {holder}"  # see SPDX-License-Identifier: docs\n')
        code, out = self.scenario("no-warn-prose", body("none"), [("src/prose.py", prose)])
        self.assertEqual(code, 0); self.assertNotIn("is a new file", out)

    def test_no_warn_kit_files_themselves(self):
        with open(SCRIPT, encoding="utf-8") as fh:
            script = fh.read()
        with open(os.path.abspath(__file__), encoding="utf-8") as fh:
            tests = fh.read()
        code, out = self.scenario("no-warn-kit-files", body("none"),
                                  [("scripts/check_attribution.py", script),
                                   ("tests/test_check_attribution.py", tests)])
        self.assertEqual(code, 0); self.assertNotIn("is a new file", out)

    def test_warn_header_styles_still_detected(self):
        cases = [("src/a.py", '"""Copyright (c) 2021 Gamma Co\n"""\n', "'Gamma Co'"),
                 ("src/b.html", "<!-- Copyright 2020 Delta Ltd -->\n", "'Delta Ltd'"),
                 ("src/c.sql", "-- SPDX-FileCopyrightText: 2022 Epsilon Inc\n", "'Epsilon Inc'"),
                 ("src/d.c", " * Copyright \u00a9 2018 Zeta GmbH\n", "'Zeta GmbH'"),
                 ("src/e.ts", "/*\n * SPDX-License-Identifier: MPL-2.0\n */\n", "'MPL-2.0'")]
        code, out = self.scenario("warn-header-styles", body("none"), [(p, t) for p, t, _ in cases])
        self.assertEqual(code, 0)
        for _, _, expected in cases:
            self.assertIn(expected, out)


class WorkflowCommandEscapingTests(unittest.TestCase):
    def load(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("check_attribution_under_test", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_annotation_values_are_escaped(self):
        mod = self.load()
        self.assertEqual(mod._gha_data("50%\r\n::error::x"), "50%25%0D%0A::error::x")
        self.assertEqual(mod._gha_prop("a,b:c\n::error::x"), "a%2Cb%3Ac%0A%3A%3Aerror%3A%3Ax")

    def test_newline_in_file_name_cannot_fake_an_annotation(self):
        import contextlib
        import io
        from unittest import mock
        mod = self.load()
        rep = mod.Report()
        rep.warn("odd file", "src/x\n::error::forged.py")
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": ""}), \
                contextlib.redirect_stdout(buf):
            mod.emit(rep)
        lines = buf.getvalue().splitlines()
        self.assertFalse(any(line.startswith("::error::") for line in lines))
        self.assertTrue(lines[0].startswith("::warning file=src/x%0A%3A%3Aerror%3A%3Aforged.py::"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
