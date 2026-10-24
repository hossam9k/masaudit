# SPDX-License-Identifier: Apache-2.0
"""Android rules: per-finding severity and message fixes from the precision audit of real apps.

Each case scans a fixture under tests/fixtures/<RULE>/<variant> and checks the calibrated severity of
every finding by (file name, line), so a precision fix can't quietly turn into a severity regression.
"""

import os
import unittest

from helpers import FIXTURES, scan_dir
from masaudit import engine, profile
from masaudit.parsers import xmlsafe

PROFILE = profile.make("banking", "flag")


def found(rule_id, variant):
    findings = engine.calibrate(scan_dir(os.path.join(FIXTURES, rule_id, variant), {rule_id}), PROFILE)
    return {(f.location.path.rsplit("/", 1)[-1], f.location.line): f for f in findings}


def severities(rule_id, variant):
    return {key: f.effective_severity for key, f in found(rule_id, variant).items()}


class Precision(unittest.TestCase):
    def test_sql_in_migrations(self):
        self.assertEqual(severities("AND-020", "clean_migration"), {})
        self.assertEqual(severities("AND-020", "vulnerable_provider_uri"), {("NotesProvider.kt", 7): "high"})
        got = found("AND-020", "vulnerable_migration_db_value")
        self.assertEqual({k: f.effective_severity for k, f in got.items()}, {("DBUpgrader.java", 10): "low"})
        self.assertIn("read back from the database", got[("DBUpgrader.java", 10)].message)

    def test_object_input_stream(self):
        self.assertEqual(severities("AND-032", "clean_hardened_and_clone"), {})
        self.assertEqual(severities("AND-032", "clean_dead_code"), {})
        self.assertEqual(severities("AND-032", "vulnerable_sources"), {
            ("Sources.java", 13): "high",      # the binder caller's stream
            ("Sources.java", 19): "medium",    # new ObjectInputStream(new FileInputStream(file))
            ("Sources.java", 26): "medium",    # through a FileInputStream variable
        })

    def test_exported_components(self):
        self.assertEqual(severities("AND-015", "clean_interop"), {})
        self.assertEqual(severities("AND-015", "vulnerable_must_stay_high"), {
            ("AndroidManifest.xml", 4): "high", ("AndroidManifest.xml", 5): "high", ("AndroidManifest.xml", 9): "high"})
        got = found("AND-015", "vulnerable_caller_check")
        self.assertEqual({k: f.effective_severity for k, f in got.items()}, {("AndroidManifest.xml", 4): "low"})
        self.assertIn("checks the calling app", got[("AndroidManifest.xml", 4)].message)
        self.assertNotIn("any app can read or change", got[("AndroidManifest.xml", 4)].message)

    def test_phone_number_is_not_a_hardware_id(self):
        self.assertEqual(severities("AND-042", "clean_phone_number"), {})
        got = found("AND-042", "vulnerable_imei")
        self.assertEqual(len(got), 2)
        for f in got.values():
            self.assertIn("getImei(", f.message)
            self.assertNotIn("().", f.message)       # the name shown doesn't start inside the cast

    def test_background_location_is_not_fraud_tooling(self):
        self.assertEqual(severities("AND-072", "clean_background_location"), {})
        got = found("AND-072", "vulnerable_install")
        self.assertEqual(len(got), 1)
        message = next(iter(got.values())).message
        self.assertIn("REQUEST_INSTALL_PACKAGES", message)
        self.assertNotIn("ACCESS_BACKGROUND_LOCATION", message)


class Severity(unittest.TestCase):
    def test_webview_content_access(self):
        self.assertEqual(severities("AND-059", "vulnerable_web_only"), {("Captcha.kt", 7): "low"})
        self.assertEqual(severities("AND-059", "vulnerable_local_page"), {("Help.kt", 7): "medium"})

    def test_webview_file_access(self):
        self.assertEqual(severities("AND-010", "vulnerable_web_only"), {("CommunicationBridge.kt", 8): "low"})
        self.assertEqual(severities("AND-010", "vulnerable_file_page"), {("Reader.kt", 7): "high"})

    def test_js_bridge(self):
        self.assertEqual(severities("AND-012", "vulnerable_fixed_origin"), {("Dashboard.kt", 8): "medium"})
        self.assertEqual(severities("AND-012", "vulnerable_intent_url"), {("Viewer.kt", 9): "high"})

    def test_file_provider_paths(self):
        self.assertEqual(severities("AND-016", "severity_tiers"), {
            ("file_paths.xml", 3): "medium",    # external-path "."
            ("file_paths.xml", 4): "medium",    # root-path /storage/
            ("file_paths.xml", 5): "high",      # root-path "."
            ("file_paths.xml", 6): "high",      # files-path "."
        })

    def test_shared_storage(self):
        self.assertEqual(severities("AND-060", "vulnerable_user_download"), {("Downloader.kt", 9): "low"})
        self.assertEqual(severities("AND-060", "vulnerable"), {("Export.kt", 6): "medium"})


class Messages(unittest.TestCase):
    def test_import_finding_is_on_the_import_line(self):
        got = found("AND-022", "vulnerable_import_line")
        self.assertEqual(list(got), [("LegacySecureStorage.kt", 3)])
        self.assertIn("import androidx.security.crypto", next(iter(got.values())).location.snippet)

    def test_exported_receiver_reported_at_helper_callers(self):
        got = found("AND-056", "vulnerable_helper")
        self.assertEqual(list(got), [("Callers.kt", 7)])
        self.assertIn("actionWidgetAdded", got[("Callers.kt", 7)].message)
        self.assertIn("registerExportedReceiver()", got[("Callers.kt", 7)].message)

    def test_acknowledgement_quotes_the_comment_before_the_element(self):
        root = xmlsafe.parse(
            '<network-security-config xmlns:tools="http://schemas.android.com/tools">\n'
            '  <base-config>\n'
            '    <trust-anchors>\n'
            '      <!-- Additionally trust user added CAs -->\n'
            '      <certificates\n'
            '          src="user"\n'
            '          tools:ignore="AcceptsUserCertificates" />\n'
            '    </trust-anchors>\n'
            '  </base-config>\n'
            '\n'
            '  <!-- Cleartext for CRL and OCSP hosts -->\n'
            '  <domain-config cleartextTrafficPermitted="true"><domain>c.lencr.org</domain></domain-config>\n'
            '</network-security-config>\n')
        cert = next(e for e in root.iter("certificates"))
        self.assertEqual(xmlsafe.ack_text(cert, "AcceptsUserCertificates"),
                         "tools:ignore=AcceptsUserCertificates — Additionally trust user added CAs")

    def test_acknowledgement_ignores_a_comment_after_the_element(self):
        root = xmlsafe.parse(
            '<network-security-config xmlns:tools="http://schemas.android.com/tools">\n'
            '  <base-config>\n'
            '    <trust-anchors>\n'
            '      <certificates src="system" />\n'
            '      <certificates\n'
            '          src="user"\n'
            '          tools:ignore="AcceptsUserCertificates" />\n'
            '    </trust-anchors>\n'
            '  </base-config>\n'
            '\n'
            '  <!-- Allow clearText traffic on some specified host -->\n'
            '  <domain-config cleartextTrafficPermitted="true"><domain>localhost</domain></domain-config>\n'
            '</network-security-config>\n')
        cert = [e for e in root.iter("certificates")][1]
        self.assertEqual(xmlsafe.ack_text(cert, "AcceptsUserCertificates"), "tools:ignore=AcceptsUserCertificates")
        # A trailing comment on the element's own line still counts.
        root = xmlsafe.parse('<a xmlns:tools="http://schemas.android.com/tools">\n'
                             '  <b tools:ignore="X" /> <!-- needed for the QA proxy -->\n'
                             '  <c />\n</a>\n')
        self.assertEqual(xmlsafe.ack_text(root.find("b"), "X"), "tools:ignore=X — needed for the QA proxy")


if __name__ == "__main__":
    unittest.main()
