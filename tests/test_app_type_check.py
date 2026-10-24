# SPDX-License-Identifier: Apache-2.0
"""The code can suggest a riskier app type than the one chosen. masaudit warns, never switches silently."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import helpers  # noqa: F401  (sets sys.path)
from masaudit import cli, engine, profile, safety
from masaudit.report import jsonout, markdown, sarif

RULES = engine.load_rules()


def clues_for(files):
    root = tempfile.mkdtemp()
    try:
        for rel, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(root, rel)) or root, exist_ok=True)
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write(text)
        return cli.collect_clues(root, safety.walk(root))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def warnings_for(app_type, files):
    return profile.check(profile.make(app_type, "flag"), clues_for(files), RULES)


CARD = {"app/src/main/java/a/Checkout.kt": "class Checkout { var cardNumber = \"\"; var cvv = \"\" }"}


class Evidence(unittest.TestCase):
    """False clues found on real apps during the precision review (2026-10-24)."""

    def test_words_that_only_look_like_payments_are_not_clues(self):
        self.assertEqual(clues_for({
            # Signal iOS names a ConversationViewController `cvc`.
            "Signal/ConversationCollectionView.swift": "func cvc_reloadData(cvc: ConversationViewController) {}",
            # Bitwarden lists website names for autofill; Wikipedia declares a URL scheme.
            "app/src/main/kotlin/a/KnownUsernameFieldUtil.kt": 'val sites = listOf("paypal", "amazon")',
            "Wikipedia/Info.plist": "<string>paypal</string>",
            # AntennaPod is a podcast player with Android Auto, not a car controller.
            "gradle/libs.versions.toml": 'car = { module = "androidx.car.app:app", version = "1.4.0" }',
            # Signal and Thunderbird show .pkpass attachments; they don't issue passes.
            "app/src/main/java/a/MimeTypeUtil.java": 'map.put("pkpass", "application/vnd.apple.pkpass");',
        }), [])

    def test_real_sdks_are_clues(self):
        labels = {c.label for c in clues_for({
            "app/build.gradle.kts": 'dependencies { implementation("com.paypal.android:paypal-web-payments:1.5.0") }',
            "ios/Podfile": "pod 'Adyen'",
            "lib/pubspec.yaml": "dependencies:\n  flutter_stripe: ^11.0.0\n",
            "ios/App/Health.swift": "import HealthKit\nlet store = HKHealthStore()",
        })}
        self.assertEqual(labels, {"a payment SDK", "a payment SDK (Stripe)", "a health data API"})

    def test_every_kind_of_evidence_is_found(self):
        # One real-world example per clue, so a too-narrow prefilter can't hide a match.
        examples = {
            "a payment SDK (Stripe)": 'implementation("com.stripe:stripe-android:21.0.0")',
            "a payment SDK": "import PayPalCheckout",
            "Google Pay or Apple Pay": "let request = PKPaymentRequest()",
            "card-number fields": "var cardExpiry = \"\"",
            "an open-banking SDK": 'implementation("com.plaid.link:sdk-core:4.0.0")',
            "a crypto wallet library": 'implementation("org.web3j:core:4.12.0")',
            "an identity-verification (KYC) SDK": "import Onfido",
            "passport or ID-card NFC reading": "val tag = IsoDep.get(nfcTag)",
            "a health data API": "val client = HealthConnectClient.getOrCreate(context)",
            "a smart-home API": "let manager = HMHomeManager()",
            "managed-device (MDM) configuration": 'val r = "android.content.APP_RESTRICTIONS"',
            "a game engine": "class Main : UnityPlayerActivity()",
            "a Google Wallet pass": "walletClient.savePasses(json, activity, 1000)",
            "loyalty or points code": "val RewardPoints = 1",
        }
        self.assertEqual(set(examples), {label for _p, label, _t, _n in profile.CLUES})
        for label, code in examples.items():
            with self.subTest(label=label):
                self.assertIn(label, {c.label for c in clues_for({"app/src/main/java/a/Code.kt": code})})

    def test_comments_tests_and_demos_are_not_evidence(self):
        self.assertEqual(clues_for({
            "app/src/main/java/a/Notes.kt": "// TODO: maybe accept cardNumber here one day",
            "app/src/test/java/a/CheckoutTest.kt": "val cardNumber = \"4242\"",
            "sample/src/main/java/a/Demo.kt": "val cardNumber = \"4242\"",
        }), [])


class Check(unittest.TestCase):
    def test_card_fields_in_a_news_app_warn_with_the_type_to_use(self):
        warnings = warnings_for("content", CARD)
        self.assertEqual(len(warnings), 1)
        w = warnings[0]
        self.assertEqual((w.suggested, w.evidence, w.path), ("ecommerce-cards", "card-number fields",
                                                             "app/src/main/java/a/Checkout.kt"))
        self.assertIn("To fix:     run again with --app-type ecommerce-cards.", w.lines())

    def test_evidence_that_changes_nothing_stays_quiet(self):
        # A payment SDK suggests ecommerce, which runs the same checks as a news app.
        self.assertEqual(warnings_for("content", {"app/build.gradle.kts": 'implementation("com.stripe:stripe-android:21.0.0")'}), [])
        # A riskier choice than the evidence is never a problem.
        self.assertEqual(warnings_for("banking", CARD), [])
        self.assertEqual(warnings_for("identity", {"a/Env.swift": 'let k = "com.apple.configuration.managed"'}), [])

    def test_any_kind_of_evidence_can_warn(self):
        self.assertTrue(warnings_for("general", {"unity/build.gradle": "implementation 'com.unity3d.ads:unity-ads:4.0'"}))
        self.assertTrue(warnings_for("social", {"ios/App/Kyc.swift": "import Onfido"}))
        self.assertTrue(warnings_for("content", {"a/Home.swift": "let manager = HMHomeManager()"}))

    def test_the_warning_names_findings_that_were_hidden_as_not_needed(self):
        f = engine.Finding(rule=next(r for r in RULES if r.id == "AND-007"),
                           location=engine.Location(path="app/src/main/AndroidManifest.xml", line=1))
        f.bucket = "not-needed"
        w = profile.check(profile.make("content", "flag"), clues_for(CARD), RULES, [f])[0]
        self.assertEqual(w.hidden[0][0], "AND-007")
        f.status = "suppressed"           # an accepted finding is not hidden by the app type
        self.assertEqual(profile.check(profile.make("content", "flag"), clues_for(CARD), RULES, [f])[0].hidden, [])

    def test_counts_only_checks_for_this_projects_platforms(self):
        clues = clues_for(CARD)
        everything = profile.check(profile.make("content", "flag"), clues, RULES)[0].extra_checks
        android = profile.check(profile.make("content", "flag"), clues, RULES,
                                applies=lambda r: engine.applies_to_platforms(r, ["android"]))[0].extra_checks
        self.assertLess(android, everything)

    def test_a_warning_another_covers_is_dropped(self):
        # Bitwarden iOS: MDM suggests enterprise, card fields suggest ecommerce-cards, which needs
        # every check enterprise needs and more. Offer only the one that covers both.
        warnings = warnings_for("content", dict(CARD, **{"a/Env.swift": 'let k = "com.apple.configuration.managed"'}))
        self.assertEqual([w.suggested for w in warnings], ["ecommerce-cards"])

    def test_a_reviewed_type_does_not_warn(self):
        self.assertEqual(profile.check(profile.make("content", "config"), clues_for(CARD), RULES,
                                       reviewed=["ecommerce-cards"]), [])

    def test_advice_matches_where_the_type_came_from(self):
        clues = clues_for(CARD)
        config_w = profile.check(profile.make("content", "config"), clues, RULES)[0].lines()
        self.assertIn("To fix:     set app_type = ecommerce-cards in .masaudit.ini.", config_w)
        default_w = profile.check(profile.make("general", "default"), clues, RULES)[0].lines()
        self.assertIn("No app type was given, so masaudit assumed general.", default_w)
        self.assertTrue(all(len(line) < 120 and line.isascii() for line in config_w))


class Outputs(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "app/src/main/java/a"))
        with open(os.path.join(self.root, "app/src/main/AndroidManifest.xml"), "w") as fh:
            fh.write('<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                     '<uses-permission android:name="android.permission.INTERNET" /><application /></manifest>')
        with open(os.path.join(self.root, "app/src/main/java/a/Checkout.kt"), "w") as fh:
            fh.write(CARD["app/src/main/java/a/Checkout.kt"])

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_every_report_carries_the_warning(self):
        result = cli.scan(self.root, cli_type="news", allow_prompt=False)
        self.assertEqual(len(result.profile.warnings), 1)
        md = markdown.render(result)
        self.assertIn("**⚠ Check your app type.**", md)
        self.assertIn("check your app type first", md)
        data = json.loads(jsonout.render(result))["profile"]["warnings"][0]
        self.assertEqual((data["suggested"], data["evidence"]["path"]), ("ecommerce-cards", "app/src/main/java/a/Checkout.kt"))
        note = sarif.to_dict(result)["runs"][0]["invocations"][0]["toolConfigurationNotifications"][0]
        self.assertEqual(note["descriptor"]["id"], "masaudit/app-type")
        self.assertEqual(note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "app/src/main/java/a/Checkout.kt")
        # The Clue line for the same evidence isn't repeated under the warning.
        self.assertFalse(any("card-number" in s for s in result.profile.suggestions))

    def test_github_annotation_goes_to_stderr_so_stdout_stays_valid_json(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            cli.main([self.root, "--app-type", "news", "--format", "json"])
        json.loads(out.getvalue())
        self.assertIn("::warning file=app/src/main/java/a/Checkout.kt,title=masaudit - check your app type::",
                      err.getvalue())

    def test_annotation_properties_are_escaped(self):
        self.assertEqual(cli._gh_escape("a:b,c%\nd", True), "a%3Ab%2Cc%25%0Ad")

    def test_the_first_run_question_offers_the_suggested_type(self):
        answers = iter(["news", "y", "n"])
        with mock.patch.object(cli, "_is_interactive", return_value=True), \
                mock.patch.object(cli, "_ask", side_effect=lambda prompt: next(answers)), \
                contextlib.redirect_stderr(io.StringIO()):
            result = cli.scan(self.root)
        self.assertEqual(result.profile.app_type, "ecommerce-cards")
        self.assertEqual(result.profile.warnings, [])

    def test_the_question_accepts_another_type_by_name(self):
        answers = iter(["news", "banking", "n"])
        with mock.patch.object(cli, "_is_interactive", return_value=True), \
                mock.patch.object(cli, "_ask", side_effect=lambda prompt: next(answers)), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.scan(self.root).profile.app_type, "banking")

    def test_a_reviewed_type_in_the_config_file_is_quiet_and_noted(self):
        with open(os.path.join(self.root, ".masaudit.ini"), "w") as fh:
            fh.write("[masaudit]\napp_type = news\napp_type_reviewed = ecommerce-cards\n")
        result = cli.scan(self.root, allow_prompt=False)
        self.assertEqual(result.profile.warnings, [])
        self.assertTrue(any("app_type_reviewed" in n for n in result.notes))


class Hostile(unittest.TestCase):
    def test_a_folder_name_cannot_steer_the_suggestion(self):
        clues = clues_for({"--app-type nope/src/main/java/a/Checkout.kt": CARD["app/src/main/java/a/Checkout.kt"]})
        w = profile.check(profile.make("content", "prompt"), clues, RULES)[0]
        self.assertEqual(w.suggested, "ecommerce-cards")

    def test_comment_stripping_is_linear_on_blank_lines(self):
        import time
        text = "pod 'X'\n" + "\n" * 400_000 + "# pod 'Stripe'\n"
        start = time.monotonic()
        cli._without_comments("ios/Podfile", text)
        self.assertLess(time.monotonic() - start, 1.0)

    def test_a_shipping_catalog_folder_still_counts(self):
        self.assertTrue(clues_for({"Shop/Catalog/Checkout.swift": "var cardNumber = \"\""}))


if __name__ == "__main__":
    unittest.main()
