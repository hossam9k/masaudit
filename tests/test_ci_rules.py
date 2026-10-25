# SPDX-License-Identifier: Apache-2.0
"""CI rules: per-finding severity tiers, repository identity, and the near-miss / must-fire fixtures."""

import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from helpers import FIXTURES, scan_dir
from masaudit import cli, engine, profile, safety
from masaudit.detectors import ci
from masaudit.model import Project
from masaudit.parsers import workflows as wf

PROFILE = profile.make("banking", "flag")


def calibrated(path, rule_id, env=None):
    with mock.patch.dict(os.environ, env or {}, clear=False):
        if env is None:
            os.environ.pop("GITHUB_WORKSPACE", None)
            os.environ.pop("GITHUB_REPOSITORY", None)
        findings = engine.calibrate(scan_dir(path, {rule_id}), PROFILE)
    return {(f.location.path, f.location.line): f for f in findings}


def severities(findings):
    return {key: f.effective_severity for key, f in findings.items()}


def fixture(rule_id, variant):
    return os.path.join(FIXTURES, rule_id, variant)


class UnpinnedAction(unittest.TestCase):
    """CI-001: same repository -> notes, same org and GitHub-owned -> medium, zizmor policy -> one lower."""

    def env(self, variant):
        return {"GITHUB_WORKSPACE": fixture("CI-001", variant), "GITHUB_REPOSITORY": "acme/app"}

    def test_near_miss_never_reaches_fix_before_release(self):
        got = calibrated(fixture("CI-001", "nearmiss"), "CI-001", self.env("nearmiss"))
        self.assertEqual(severities(got), {
            (".github/workflows/ci.yml", 5): "info",     # acme/app/.github/workflows/_version.yml@main
            (".github/workflows/ci.yml", 10): "info",    # acme/app/.github/actions/log-inputs@main
            (".github/workflows/ci.yml", 11): "low",     # acme/gh-actions/* is ref-pin in zizmor.yml
            (".github/workflows/ci.yml", 12): "low",
        })
        self.assertIn("acme/gh-actions/*: ref-pin", got[(".github/workflows/ci.yml", 11)].acknowledged)
        self.assertIn("`./.github/workflows/_version.yml`", got[(".github/workflows/ci.yml", 5)].message)

    def test_must_fire(self):
        got = severities(calibrated(fixture("CI-001", "mustfire"), "CI-001", self.env("mustfire")))
        self.assertEqual(got, {
            (".github/workflows/ci.yml", 5): "high",     # acmecorp/app: lookalike owner
            (".github/workflows/ci.yml", 9): "high",     # acme-evil/gh-actions: lookalike owner
            (".github/workflows/ci.yml", 10): "medium",  # same org, not covered by the policy
            (".github/workflows/ci.yml", 11): "medium",  # same org, another repository
            (".github/workflows/ci.yml", 12): "medium",  # actions/checkout@v4
            (".github/workflows/ci.yml", 13): "high",    # third party
            (".github/workflows/ci.yml", 14): "high",    # no ref at all
            (".github/actions/setup/action.yml", 6): "medium",
            (".github/actions/setup/action.yml", 10): "high",
            ("tools/lint-image/action.yaml", 4): "high",
        })

    def test_without_identity_same_repo_is_not_lowered(self):
        got = severities(calibrated(fixture("CI-001", "nearmiss"), "CI-001"))
        self.assertEqual(got[(".github/workflows/ci.yml", 5)], "high")

    def test_github_repository_is_ignored_when_the_root_is_not_the_workspace(self):
        env = {"GITHUB_WORKSPACE": FIXTURES, "GITHUB_REPOSITORY": "acme/app"}
        got = severities(calibrated(fixture("CI-001", "nearmiss"), "CI-001", env))
        self.assertEqual(got[(".github/workflows/ci.yml", 5)], "high")

    def test_identity_from_the_origin_remote(self):
        tmp = tempfile.mkdtemp(prefix="masaudit-ci-")
        self.addCleanup(shutil.rmtree, tmp)
        root = os.path.join(tmp, "repo")
        shutil.copytree(fixture("CI-001", "nearmiss"), root)
        os.mkdir(os.path.join(root, ".git"))
        with open(os.path.join(root, ".git", "config"), "w", encoding="utf-8") as fh:
            fh.write('[core]\n\tbare = false\n[remote "upstream"]\n\turl = https://github.com/other/app.git\n'
                     '[remote "origin"]\n\turl = git@github.com:Acme/App.git\n')
        got = severities(calibrated(root, "CI-001"))
        self.assertEqual(got[(".github/workflows/ci.yml", 5)], "info")

    def test_a_linked_config_is_not_read(self):
        tmp = tempfile.mkdtemp(prefix="masaudit-ci-")
        self.addCleanup(shutil.rmtree, tmp)
        root = os.path.join(tmp, "repo")
        shutil.copytree(fixture("CI-001", "nearmiss"), root)
        outside = os.path.join(tmp, "outside-config")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write('[remote "origin"]\n\turl = https://github.com/acme/app\n')
        os.mkdir(os.path.join(root, ".git"))
        try:
            os.symlink(outside, os.path.join(root, ".git", "config"))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        got = severities(calibrated(root, "CI-001"))
        self.assertEqual(got[(".github/workflows/ci.yml", 5)], "high")

    def test_policy_precedence_follows_zizmor(self):
        policies = {"acme/*": "ref-pin", "acme/tools/*": "hash-pin", "acme/tools/lint": "any", "*": "hash-pin"}
        self.assertEqual(ci._policy_for("acme/tools/lint", policies), ("acme/tools/lint", "any"))
        self.assertEqual(ci._policy_for("acme/tools/fmt", policies), ("acme/tools/*", "hash-pin"))
        self.assertEqual(ci._policy_for("acme/other", policies), ("acme/*", "ref-pin"))
        self.assertEqual(ci._policy_for("evil/x", policies), ("*", "hash-pin"))
        self.assertIsNone(ci._policy_for("evil/x", {}))


class GithubOrigin(unittest.TestCase):
    def test_remote_forms(self):
        cases = {
            "https://github.com/bitwarden/android.git": ("bitwarden", "android"),
            "git@github.com:Acme/App.git": ("acme", "app"),
            "ssh://git@github.com:22/acme/app": ("acme", "app"),
            "https://x-access-token:abc@github.com/acme/app/": ("acme", "app"),
            '"https://github.com/acme/app"': ("acme", "app"),
            "https://evilgithub.com/acme/app": None,
            "https://github.com.evil.example/acme/app": None,
            "https://github.com/acme/app/extra": None,
            "/srv/mirrors/app.git": None,
        }
        for url, want in cases.items():
            with self.subTest(url=url):
                self.assertEqual(wf.github_origin(f'[remote "origin"]\n\turl = {url}\n'), want)

    def test_only_origin_counts(self):
        self.assertIsNone(wf.github_origin('[remote "fork"]\n\turl = https://github.com/me/app\n'))
        self.assertEqual(wf.github_origin("[remote.origin]\nurl = https://github.com/me/app\n"), ("me", "app"))

    def test_hostile_text_is_fast_and_safe(self):
        for text in ("[remote \"origin\"]\nurl = https://github.com/" + "a" * 100000,
                     "[" * 100000, "url = " + "@" * 100000, '[remote "origin"]\n' + "url=x\n" * 50000):
            start = time.monotonic()
            wf.github_origin(text)
            self.assertLess(time.monotonic() - start, 2.0)


class ParserAdditions(unittest.TestCase):
    def test_input_types_and_conditions(self):
        w = wf.parse_workflow(
            "on:\n  workflow_dispatch:\n    inputs:\n      lane: { type: choice, options: [a, b] }\n"
            "      notes:\n        description: x\n  workflow_call:\n    inputs:\n      lane:\n        type: string\n"
            "jobs:\n  a:\n    if: github.event.pull_request.head.repo.fork == false\n    steps:\n"
            "      - if: always()\n        run: echo\n")
        self.assertEqual(w.input_types, {"lane": ["choice", "string"], "notes": ["string"]})
        self.assertEqual(w.jobs[0].if_, "github.event.pull_request.head.repo.fork == false")
        self.assertEqual(w.jobs[0].steps[0].if_, "always()")

    def test_action_metadata(self):
        a = wf.parse_action("runs:\n  using: 'Composite'\n  steps:\n    - uses: a/b@v1\n    - run: echo\n")
        self.assertEqual(a.using, "composite")
        self.assertEqual([(s.uses, s.uses.line) for s in a.steps if s.uses], [("a/b@v1", 4)])
        self.assertEqual(wf.parse_action("runs:\n  using: docker\n  image: Dockerfile\n").image, "Dockerfile")
        self.assertIsNone(wf.parse_action("steps:\n  - uses: a/b@v1\n"))
        self.assertIsNone(wf.parse_action("runs: node\n"))

    def test_snippet_keeps_a_public_action_name(self):
        tmp = tempfile.mkdtemp(prefix="masaudit-ci-")
        self.addCleanup(shutil.rmtree, tmp)
        os.makedirs(os.path.join(tmp, ".github", "workflows"))
        with open(os.path.join(tmp, ".github", "workflows", "a.yml"), "w", encoding="utf-8") as fh:
            fh.write("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"
                     "      - uses: davidSchuppa/base64Secret-toFile-action@v2\n")
        got = calibrated(tmp, "CI-001")
        self.assertEqual(got[(".github/workflows/a.yml", 6)].location.snippet,
                         "- uses: davidSchuppa/base64Secret-toFile-action@v2")

    def test_zizmor_policies(self):
        text = "rules:\n  unpinned-uses:\n    config:\n      policies:\n        Acme/*: Ref-Pin\n        '*': hash-pin\n"
        self.assertEqual(wf.unpinned_uses_policies(text), {"acme/*": "ref-pin", "*": "hash-pin"})
        self.assertEqual(wf.unpinned_uses_policies("rules: {}\n"), {})


class TokenPermissions(unittest.TestCase):
    def test_reusable_only_workflow_is_a_note(self):
        self.assertEqual(set(severities(calibrated(fixture("CI-002", "nearmiss"), "CI-002")).values()), {"info"})
        self.assertEqual(set(severities(calibrated(fixture("CI-002", "mustfire"), "CI-002")).values()), {"medium"})


class PrtCheckout(unittest.TestCase):
    def test_gated_jobs_are_high_and_ungated_stay_critical(self):
        got = severities(calibrated(fixture("CI-003", "mustfire"), "CI-003"))
        self.assertEqual(got, {
            (".github/workflows/bot.yml", 9): "high",       # job if: head.repo.full_name == github.repository
            (".github/workflows/bot.yml", 16): "critical",  # refs/pull/N/merge, no gate
            (".github/workflows/bot.yml", 26): "medium",    # exits for forks, then only `gh pr merge`
            (".github/workflows/bot.yml", 33): "critical",  # `!=` lets forks in; merge_commit_sha fetched
            (".github/workflows/bot.yml", 41): "medium",    # gated, and nothing runs the checkout
        })
        self.assertEqual(calibrated(fixture("CI-003", "nearmiss"), "CI-003"), {})


class ScriptInjection(unittest.TestCase):
    def test_near_miss_is_notes_only(self):
        got = severities(calibrated(fixture("CI-004", "nearmiss"), "CI-004"))
        self.assertEqual(got, {(".github/workflows/a.yml", 22): "info"})   # head.repo.full_name

    def test_must_fire(self):
        got = severities(calibrated(fixture("CI-004", "mustfire"), "CI-004"))
        self.assertEqual(got, {
            (".github/workflows/a.yml", 18): "high",     # pull_request.title
            (".github/workflows/a.yml", 19): "high",     # head.ref
            (".github/workflows/a.yml", 20): "medium",   # free-text dispatch input
            (".github/workflows/a.yml", 21): "medium",   # choice for dispatch, string for workflow_call
            (".github/workflows/a.yml", 22): "high",     # head_commit.message: `_sha` doesn't over-match
        })


class PersistCredentials(unittest.TestCase):
    def test_near_miss_is_notes_only(self):
        got = severities(calibrated(fixture("CI-005", "nearmiss"), "CI-005"))
        self.assertEqual(set(got.values()), {"info"})

    def test_must_fire(self):
        got = calibrated(fixture("CI-005", "mustfire"), "CI-005")
        self.assertEqual(severities(got), {
            (".github/workflows/a.yml", 7): "high",      # PAT persisted, nothing pushes
            (".github/workflows/a.yml", 14): "medium",   # v4, token in .git/config
            (".github/workflows/a.yml", 19): "medium",   # v7 by comment, but the workspace is uploaded
            (".github/workflows/a.yml", 26): "low",      # v6, token under $RUNNER_TEMP
            (".github/workflows/a.yml", 31): "low",      # pushes: make it explicit
            (".github/workflows/a.yml", 36): "low",      # explicit true, nothing pushes (acknowledged)
            (".github/workflows/a.yml", 43): "medium",   # explicit true with a PAT, nothing pushes
            (".github/workflows/a.yml", 51): "low",      # `git -c k=v push` is a push
        })
        self.assertEqual(got[(".github/workflows/a.yml", 36)].acknowledged, "persist-credentials: true")

    def test_fastlane_and_token_remote_count_as_pushes(self):
        got = calibrated(fixture("CI-005", "mustfire_fastlane"), "CI-005")
        self.assertEqual(severities(got), {
            (".github/workflows/release.yml", 8): "low",     # fastlane tag_and_push_release pushes
            (".github/workflows/release.yml", 15): "high",   # the PAT is written into the remote URL
        })
        for f in got.values():
            self.assertNotIn("nothing in this job pushes", f.message)
        self.assertIn("secrets.PAT", got[(".github/workflows/release.yml", 15)].message)
        self.assertIn(".git/config whatever `persist-credentials` says",
                      got[(".github/workflows/release.yml", 15)].message)
        self.assertTrue(ci._pushes("bundle exec fastlane android tag_and_push_release_version app_version:1"))
        self.assertFalse(ci._pushes("bundle exec fastlane deploy_playstore"))
        self.assertFalse(ci._pushes("bundle exec fastlane update_release_notes_playstore release_number:1"))
        self.assertFalse(ci._pushes("os.makedirs(f'fastlane/metadata/{code}'); open('release_notes.txt')"))
        self.assertTrue(ci._pushes("bundle exec fastlane hotfix-finish"))
        self.assertFalse(ci._pushes('gh release create v1 --notes "x"'))     # the API, not git credentials

    def test_push_detection_is_linear(self):
        for text in ("git " + "-c x " * 20000 + "nope", "git tag v1 " + "&& " * 50000, "git -" + "-" * 100000):
            start = time.monotonic()
            ci._pushes(text)
            self.assertLess(time.monotonic() - start, 2.0)
        self.assertTrue(ci._pushes("git -C repo push origin main"))
        self.assertFalse(ci._pushes("echo 'git pushed nothing'"))


class SigningMaterial(unittest.TestCase):
    def test_near_miss(self):
        got = severities(calibrated(fixture("CI-006", "nearmiss"), "CI-006"))
        self.assertEqual(got, {("keystores/debug-bwa.keystore", 0): "info", ("repo.keystore", 0): "info"})

    def test_must_fire(self):
        got = severities(calibrated(fixture("CI-006", "mustfire"), "CI-006"))
        self.assertEqual(got, {
            ("app/release.jks", 0): "critical",
            # create("release") below getByName("debug"); its password comes from the environment (one lower),
            # and the debug block's "android" password doesn't count for it
            ("app/upload.keystore", 0): "high",
            ("keystores/debugger-tools.jks", 0): "critical",
            ("app/nightly.keystore", 0): "high",
        })

    def test_password_kept_out_of_the_repository_is_one_level_lower(self):
        got = calibrated(fixture("CI-006", "mustfire_password_env"), "CI-006")
        self.assertEqual(severities(got), {("app/qa.keystore", 0): "medium"})
        self.assertIn("brute-forced offline", got[("app/qa.keystore", 0)].message)
        self.assertEqual(severities(calibrated(fixture("CI-006", "mustfire_password_literal"), "CI-006")),
                         {("app/qa.keystore", 0): "high"})
        workflow = "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: {}\n"
        for name, text, want in (
                ("qa.yml", workflow.format('apksigner sign --ks-pass pass:"$KS_PASS" --ks qa.keystore'), "external"),
                ("qa.yml", workflow.format("apksigner sign --ks-pass pass:hunter2 --ks qa.keystore"), "literal"),
                ("build.gradle.kts", 'create("qa") {\n  storeFile = file("qa.keystore")\n  storePassword = '
                                     'environmentOrGradleValue("PASS", "signing.qa.storePassword")\n}\n', "external"),
                ("build.gradle.kts", 'getByName("debug") {\n  storePassword = "android"\n}\ncreate("qa") {\n'
                                     '  storeFile = file("qa.keystore")\n}\n', "")):
            self.assertEqual(self._password(name, text), want, text)

    def _password(self, name, text):
        tmp = tempfile.mkdtemp(prefix="masaudit-ci-")
        self.addCleanup(shutil.rmtree, tmp)
        folder = os.path.join(tmp, ".github", "workflows") if name.endswith(".yml") else os.path.join(tmp, "app")
        os.makedirs(folder)
        with open(os.path.join(folder, name), "w", encoding="utf-8") as fh:
            fh.write(text)
        project = Project(root=tmp, platforms=["ci"], files=safety.walk(tmp))
        return ci._keystore_password(engine.Context(project), "qa.keystore")


class MissingLockfile(unittest.TestCase):
    def test_large_verification_metadata_is_read_from_its_head(self):
        tmp = tempfile.mkdtemp(prefix="masaudit-ci-")
        self.addCleanup(shutil.rmtree, tmp)
        os.makedirs(os.path.join(tmp, "gradle"))
        with open(os.path.join(tmp, "settings.gradle.kts"), "w", encoding="utf-8") as fh:
            fh.write('rootProject.name = "x"\n')
        with open(os.path.join(tmp, "gradle", "verification-metadata.xml"), "w", encoding="utf-8") as fh:
            fh.write("<verification-metadata><configuration><verify-metadata>true</verify-metadata>"
                     "</configuration><components>\n" + "<component/>\n" * 250000 + "</components>\n")
        self.assertGreater(os.path.getsize(os.path.join(tmp, "gradle", "verification-metadata.xml")), 2 * 1024 * 1024)
        self.assertEqual(calibrated(tmp, "CI-008"), {})


if __name__ == "__main__":
    unittest.main()


class FindingCap(unittest.TestCase):
    def test_one_rule_lists_at_most_50_findings_per_file(self):
        # An audit's crafted 2 MiB workflow produced 34,950 findings; the report must stay usable.
        tmp = tempfile.mkdtemp(prefix="masaudit-cap-")
        self.addCleanup(shutil.rmtree, tmp)
        os.makedirs(os.path.join(tmp, ".github", "workflows"))
        steps = "".join(f"      - uses: someone/action{i}@v1\n" for i in range(300))
        with open(os.path.join(tmp, ".github", "workflows", "ci.yml"), "w", encoding="utf-8") as fh:
            fh.write("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + steps)
        result = cli.scan(tmp, cli_type="banking", cfg={}, allow_prompt=False)
        unpinned = [f for f in result.findings if f.rule.id == "CI-001"]
        self.assertEqual(len(unpinned), engine.MAX_HITS_PER_FILE)
        self.assertIn("CI-001 matched 300 times in .github/workflows/ci.yml; the report lists the first 50.",
                      result.project.unknowns)
