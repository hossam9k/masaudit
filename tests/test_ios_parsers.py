# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the iOS parsers: plist (XML + binary), project.pbxproj, and .xcconfig."""

import os
import plistlib
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit.detectors import ios as ios_detectors
from masaudit.parsers import pbxproj, plist, xcconfig

APPLE_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
)

INFO_PLIST = APPLE_HEADER + """<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.demo</string>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
		<key>NSPinnedDomains</key>
		<dict>
			<key>api.example.com</key>
			<dict>
				<key>NSPinnedCAIdentities</key>
				<array>
					<dict>
						<key>SPKI-SHA256-BASE64</key>
						<string>YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</string>
					</dict>
				</array>
			</dict>
		</dict>
	</dict>
</dict>
</plist>
"""


class PlistTests(unittest.TestCase):
    def test_xml_with_apple_doctype(self):
        data = plist.loads(INFO_PLIST.encode())
        self.assertEqual(data["CFBundleIdentifier"], "com.example.demo")
        self.assertTrue(plist.get(data, "NSAppTransportSecurity", "NSAllowsArbitraryLoads"))
        self.assertEqual(len(plist.get(data, "NSAppTransportSecurity", "NSPinnedDomains",
                                       "api.example.com", "NSPinnedCAIdentities")), 1)

    def test_binary_plist(self):
        obj = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}, "Count": 3}
        raw = plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)
        self.assertTrue(plist.is_binary(raw))
        self.assertEqual(plist.loads(raw), obj)
        self.assertEqual(plist.key_lines(raw.decode("latin-1")), {})   # no lines for binary

    def test_rejects_entities_and_unknown_doctypes(self):
        entity = (APPLE_HEADER.replace('.dtd">', '.dtd" [<!ENTITY x "boom">]>')
                  + "<plist><dict><key>a</key><string>&x;</string></dict></plist>")
        self.assertIsNone(plist.loads(entity.encode()))
        bare_entity = '<?xml version="1.0"?><!ENTITY x "y"><plist><dict/></plist>'
        self.assertIsNone(plist.loads(bare_entity.encode()))
        other = '<?xml version="1.0"?>\n<!DOCTYPE plist SYSTEM "http://evil.example/x.dtd">\n<plist><dict/></plist>'
        self.assertIsNone(plist.loads(other.encode()))
        self.assertFalse(plist.safe_xml(other))
        self.assertEqual(plist.key_lines(entity), {})

    def test_no_doctype_and_legacy_doctype(self):
        self.assertEqual(plist.loads(b'<plist version="1.0"><dict><key>a</key><true/></dict></plist>'),
                         {"a": True})
        legacy = ('<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" '
                  '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist><dict/></plist>')
        self.assertTrue(plist.safe_xml(legacy))

    def test_invalid_input(self):
        self.assertIsNone(plist.loads(b""))
        self.assertIsNone(plist.loads(b"<plist><dict><key>a</key></plist>"))
        self.assertIsNone(plist.loads(b"bplist00garbage"))

    def test_key_lines(self):
        lines = plist.key_lines(INFO_PLIST)
        text_lines = INFO_PLIST.splitlines()
        ats = lines[("NSAppTransportSecurity", "NSAllowsArbitraryLoads")]
        self.assertIn("<key>NSAllowsArbitraryLoads</key>", text_lines[ats - 1])
        pins = lines[("NSAppTransportSecurity", "NSPinnedDomains", "api.example.com", "NSPinnedCAIdentities")]
        self.assertIn("NSPinnedCAIdentities", text_lines[pins - 1])
        first_pin = lines[("NSAppTransportSecurity", "NSPinnedDomains", "api.example.com",
                           "NSPinnedCAIdentities", 0)]
        self.assertIn("<dict>", text_lines[first_pin - 1])
        # Deepest known prefix when the exact path is missing.
        self.assertEqual(plist.line_of(lines, "NSAppTransportSecurity", "Missing"),
                         lines[("NSAppTransportSecurity",)])

    def test_truthy(self):
        for v in (True, "YES", "true", 1):
            self.assertTrue(plist.truthy(v))
        for v in (False, "NO", 0, None, {}):
            self.assertFalse(plist.truthy(v))


PBXPROJ = r"""// !$*UTF8*$!
{
	archiveVersion = 1;
	classes = {
	};
	objectVersion = 77;
	objects = {

/* Begin PBXBuildFile section */
		13B07FBC1A68108700A75B9A /* AppDelegate.swift in Sources */ = {isa = PBXBuildFile; fileRef = 13B07FB01A68108700A75B9A /* AppDelegate.swift */; };
		13B07FBF1A68108700A75B9A /* PrivacyInfo.xcprivacy in Resources */ = {isa = PBXBuildFile; fileRef = 13B07FB51A68108700A75B9A /* PrivacyInfo.xcprivacy */; };
/* End PBXBuildFile section */

/* Begin PBXFileReference section */
		13B07FB01A68108700A75B9A /* AppDelegate.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = AppDelegate.swift; sourceTree = "<group>"; };
		13B07FB51A68108700A75B9A /* PrivacyInfo.xcprivacy */ = {isa = PBXFileReference; lastKnownFileType = text.xml; path = PrivacyInfo.xcprivacy; sourceTree = "<group>"; };
		13B07FB61A68108700A75B9A /* Release.xcconfig */ = {isa = PBXFileReference; lastKnownFileType = text.xcconfig; name = Release.xcconfig; path = Config/Release.xcconfig; sourceTree = SOURCE_ROOT; };
		13B07F961A680F5B00A75B9A /* Demo.app */ = {isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = Demo.app; sourceTree = BUILT_PRODUCTS_DIR; };
/* End PBXFileReference section */

/* Begin PBXFileSystemSynchronizedRootGroup section */
		5A1B2C3D4E5F60718293A4B5 /* Widget */ = {
			isa = PBXFileSystemSynchronizedRootGroup;
			path = Widget;
			sourceTree = "<group>";
		};
/* End PBXFileSystemSynchronizedRootGroup section */

/* Begin PBXGroup section */
		83CBB9F61A601CBA00E9B192 = {
			isa = PBXGroup;
			children = (
				13B07FAE1A68108700A75B9A /* Demo */,
				5A1B2C3D4E5F60718293A4B5 /* Widget */,
				83CBBA001A601CBA00E9B192 /* Products */,
			);
			indentWidth = 2;
			sourceTree = "<group>";
		};
		13B07FAE1A68108700A75B9A /* Demo */ = {
			isa = PBXGroup;
			children = (
				13B07FB01A68108700A75B9A /* AppDelegate.swift */,
				13B07FB51A68108700A75B9A /* PrivacyInfo.xcprivacy */,
			);
			name = Demo;
			path = "Demo App";
			sourceTree = "<group>";
		};
		83CBBA001A601CBA00E9B192 /* Products */ = {
			isa = PBXGroup;
			children = (
				13B07F961A680F5B00A75B9A /* Demo.app */,
			);
			name = Products;
			sourceTree = "<group>";
		};
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
		13B07F861A680F5B00A75B9A /* Demo */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = 13B07F931A680F5B00A75B9A /* Build configuration list for PBXNativeTarget "Demo" */;
			buildPhases = (
				13B07F871A680F5B00A75B9A /* Sources */,
				13B07F8E1A680F5B00A75B9A /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
			);
			fileSystemSynchronizedGroups = (
				5A1B2C3D4E5F60718293A4B5 /* Widget */,
			);
			name = Demo;
			productName = Demo;
			productReference = 13B07F961A680F5B00A75B9A /* Demo.app */;
			productType = "com.apple.product-type.application";
		};
/* End PBXNativeTarget section */

/* Begin PBXProject section */
		83CBB9F71A601CBA00E9B192 /* Project object */ = {
			isa = PBXProject;
			attributes = {
				LastUpgradeCheck = 1610;
				TargetAttributes = {
					13B07F861A680F5B00A75B9A = {
						LastSwiftMigration = 1120;
					};
				};
			};
			buildConfigurationList = 83CBB9FA1A601CBA00E9B192 /* Build configuration list for PBXProject "Demo" */;
			developmentRegion = en;
			knownRegions = (
				en,
				Base,
			);
			mainGroup = 83CBB9F61A601CBA00E9B192;
			productRefGroup = 83CBBA001A601CBA00E9B192 /* Products */;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				13B07F861A680F5B00A75B9A /* Demo */,
			);
		};
/* End PBXProject section */

/* Begin PBXResourcesBuildPhase section */
		13B07F8E1A680F5B00A75B9A /* Resources */ = {
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
				13B07FBF1A68108700A75B9A /* PrivacyInfo.xcprivacy in Resources */,
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXResourcesBuildPhase section */

/* Begin XCBuildConfiguration section */
		13B07F941A680F5B00A75B9A /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ENABLE_TESTABILITY = YES;
				INFOPLIST_FILE = "Demo App/Info-Debug.plist";
				OTHER_SWIFT_FLAGS = (
					"$(inherited)",
					"-D",
					DEBUG,
				);
				"SWIFT_ACTIVE_COMPILATION_CONDITIONS[sdk=iphonesimulator*]" = "DEBUG SIMULATOR";
			};
			name = Debug;
		};
		13B07F951A680F5B00A75B9A /* Release */ = {
			isa = XCBuildConfiguration;
			baseConfigurationReference = 13B07FB61A68108700A75B9A /* Release.xcconfig */;
			buildSettings = {
				// Hand-edited: line comments are legal in old-style plists.
				INFOPLIST_FILE = "$(SRCROOT)/Demo App/Info.plist";
				PRODUCT_BUNDLE_IDENTIFIER = com.example.demo;
				PRODUCT_NAME = "Demo \"Pro\"\t\U00e9";
			};
			name = Release;
		};
		83CBBA201A601CBA00E9B192 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ALWAYS_SEARCH_USER_PATHS = NO;
				ENABLE_TESTABILITY = YES;
			};
			name = Debug;
		};
		83CBBA211A601CBA00E9B192 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ALWAYS_SEARCH_USER_PATHS = NO;
				VALIDATE_PRODUCT = YES;
			};
			name = Release;
		};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
		13B07F931A680F5B00A75B9A /* Build configuration list for PBXNativeTarget "Demo" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				13B07F941A680F5B00A75B9A /* Debug */,
				13B07F951A680F5B00A75B9A /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
		83CBB9FA1A601CBA00E9B192 /* Build configuration list for PBXProject "Demo" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				83CBBA201A601CBA00E9B192 /* Debug */,
				83CBBA211A601CBA00E9B192 /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
/* End XCConfigurationList section */
	};
	rootObject = 83CBB9F71A601CBA00E9B192 /* Project object */;
}
"""


class PbxprojTests(unittest.TestCase):
    def setUp(self):
        self.data = pbxproj.parse(PBXPROJ)
        self.assertIsNotNone(self.data)
        self.proj = pbxproj.Project(self.data, "ios/Demo.xcodeproj/project.pbxproj")

    def test_values_and_escapes(self):
        self.assertEqual(self.data["rootObject"], "83CBB9F71A601CBA00E9B192")
        cfg = self.proj.objects["13B07F951A680F5B00A75B9A"]
        self.assertEqual(cfg["buildSettings"]["PRODUCT_NAME"], 'Demo "Pro"\té')
        debug = self.proj.objects["13B07F941A680F5B00A75B9A"]["buildSettings"]
        self.assertEqual(debug["OTHER_SWIFT_FLAGS"], ["$(inherited)", "-D", "DEBUG"])
        self.assertIn("SWIFT_ACTIVE_COMPILATION_CONDITIONS[sdk=iphonesimulator*]", debug)

    def test_line_numbers(self):
        lines = PBXPROJ.splitlines()
        target = self.proj.targets()[0]
        self.assertIn("13B07F861A680F5B00A75B9A /* Demo */ = {", lines[target.line - 1])
        release = target.configs["Release"]
        self.assertIn("PRODUCT_BUNDLE_IDENTIFIER", lines[release.lines["PRODUCT_BUNDLE_IDENTIFIER"] - 1])

    def test_targets_and_configurations(self):
        [target] = self.proj.targets()
        self.assertEqual(target.name, "Demo")
        self.assertTrue(target.is_app)
        self.assertFalse(target.is_test)
        self.assertEqual(sorted(target.configs), ["Debug", "Release"])
        self.assertEqual(target.configs["Debug"].settings["ENABLE_TESTABILITY"], "YES")
        self.assertEqual(target.configs["Release"].base_xcconfig, "ios/Config/Release.xcconfig")
        self.assertIsNone(target.configs["Debug"].base_xcconfig)
        self.assertEqual(target.synchronized_groups, ["ios/Widget"])
        proj_cfgs = self.proj.project_configs()
        self.assertEqual(proj_cfgs["Release"].settings["VALIDATE_PRODUCT"], "YES")
        self.assertNotIn("ENABLE_TESTABILITY", proj_cfgs["Release"].settings)

    def test_paths(self):
        self.assertEqual(self.proj.file_path("13B07FB51A68108700A75B9A"), "ios/Demo App/PrivacyInfo.xcprivacy")
        self.assertIsNone(self.proj.file_path("13B07F961A680F5B00A75B9A"))      # BUILT_PRODUCTS_DIR
        self.assertEqual(self.proj.settings_path("$(SRCROOT)/Demo App/Info.plist"), "ios/Demo App/Info.plist")
        self.assertIsNone(self.proj.settings_path("$(CONFIGURATION)/Info.plist"))
        [target] = self.proj.targets()
        refs = self.proj.phase_files(target, "PBXResourcesBuildPhase")
        self.assertEqual([self.proj.file_name(r) for r in refs], ["PrivacyInfo.xcprivacy"])

    def test_debug_config_names(self):
        for name in ("Debug", "Debug-Staging", "Development", "dev", "StagingDebug", "DEBUG", "MyAppUITests",
                     "Test-QA", "App Tests", "unit_tests"):
            self.assertTrue(pbxproj.is_debug_config(name), name)
        # Whole words and CamelCase tokens only: these contain "test" but are release names.
        for name in ("Release", "Staging", "AppStore", "MASTestApp", "Contest", "Latest", "mastestapp", "Attestation"):
            self.assertFalse(pbxproj.is_debug_config(name), name)

    def test_malformed(self):
        for text in ("", "{", "{ a = b }", "{ a = (b, c; }", "{ a = \"open; }", "{ objects = 1; }", "( a )"):
            self.assertIsNone(pbxproj.parse(text), text)
        self.assertIsNone(pbxproj.parse("{ objects = {" + "{" * 200 + "}" * 200 + "}; }"))

    def test_loads_generic(self):
        self.assertEqual(pbxproj.loads("( a, \"b c\", <0aff>, )"), ["a", "b c", b"\x0a\xff"])
        d = pbxproj.loads("/* c */ { k = v; /* x */ n = { }; // tail\n }")
        self.assertEqual(d, {"k": "v", "n": {}})


class XcconfigTests(unittest.TestCase):
    def test_parse(self):
        cfg = xcconfig.parse(
            '#include "Base.xcconfig"\n'
            "// a comment\n"
            "ENABLE_TESTABILITY = YES\n"
            "API_URL = https://api.example.com\n"
            "OTHER_FLAGS = $(inherited) -DFOO\n"
            "ENABLE_TESTABILITY[sdk=iphonesimulator*] = NO\n"
            "#include? \"Local.xcconfig\"\n"
        )
        self.assertEqual(cfg.includes, [("Base.xcconfig", False, 1), ("Local.xcconfig", True, 7)])
        settings = {k: v for k, v, _ in cfg.settings}
        self.assertEqual(settings["ENABLE_TESTABILITY"], "YES")
        self.assertEqual(settings["API_URL"], "https:")            # `//` starts a comment (book §15.8)
        self.assertEqual(settings["OTHER_FLAGS"], "$(inherited) -DFOO")
        self.assertEqual(settings["ENABLE_TESTABILITY[sdk=iphonesimulator*]"], "NO")
        self.assertTrue(xcconfig.is_unresolved(settings["OTHER_FLAGS"]))
        self.assertTrue(xcconfig.is_yes("YES") and xcconfig.is_no("NO") and not xcconfig.is_yes("$(X)"))

    def test_resolve_includes_in_order(self):
        files = {
            "cfg/Release.xcconfig": '#include "Shared.xcconfig"\nENABLE_TESTABILITY = NO\n#include "Late.xcconfig"\n',
            "cfg/Shared.xcconfig": "ENABLE_TESTABILITY = YES\nSWIFT_VERSION = 6.0\n",
            "cfg/Late.xcconfig": "SWIFT_VERSION = 5.10\n",
            "cfg/Loop.xcconfig": '#include "Loop.xcconfig"\nA = 1\n',
        }
        read = lambda _root, rel: files.get(rel)  # noqa: E731
        unknowns = []
        out = xcconfig.resolve("/", "cfg/Release.xcconfig", read=read, unknowns=unknowns)
        self.assertEqual(out["ENABLE_TESTABILITY"].value, "NO")
        self.assertEqual(out["ENABLE_TESTABILITY"].path, "cfg/Release.xcconfig")
        self.assertEqual(out["SWIFT_VERSION"].value, "5.10")
        self.assertEqual(unknowns, [])
        loop = xcconfig.resolve("/", "cfg/Loop.xcconfig", read=read, unknowns=unknowns)
        self.assertEqual(loop["A"].value, "1")
        self.assertTrue(unknowns)
        missing = []
        xcconfig.resolve("/", "cfg/Release.xcconfig", read=lambda r, p: files.get(p) if "Late" not in p else None,
                         unknowns=missing)
        self.assertTrue(any("Late.xcconfig" in m for m in missing))
        self.assertIsNone(xcconfig.include_path("a/b.xcconfig", "../../outside.xcconfig"))

    def test_resolve_reuses_a_file_only_where_the_same_cuts_apply(self):
        # Shared.xcconfig is resolved first one level down (whole), then eight levels down, where its own
        # include lies past the depth cap: the second use must be cut there, not copied from the first.
        files = {f"L{k}.xcconfig": f'#include "L{k + 1}.xcconfig"\n' for k in range(1, 7)}
        files["Top.xcconfig"] = '#include "Shared.xcconfig"\n#include "L1.xcconfig"\n'
        files["L7.xcconfig"] = '#include "Shared.xcconfig"\n'
        files["Shared.xcconfig"] = '#include "Leaf.xcconfig"\nS = 1\n'
        files["Leaf.xcconfig"] = "LEAF = 1\n"
        unknowns = []
        out = xcconfig.resolve("/", "Top.xcconfig", read=lambda _r, rel: files.get(rel), unknowns=unknowns)
        self.assertEqual(out["LEAF"].value, "1")
        self.assertEqual(unknowns, ["xcconfig include chain too deep or circular at Leaf.xcconfig",
                                    "Couldn't read Leaf.xcconfig, included from Shared.xcconfig:1"])

    def test_resolve_include_fan_out_is_linear(self):
        # Eight files that each include the next one six times: 6**8 expansions without reuse.
        files = {f"F{k}.xcconfig": f'#include "F{k + 1}.xcconfig"\n' * 6 + f"K{k} = {k}\n" for k in range(8)}
        files["F8.xcconfig"] = "LAST = 1\n"
        reads = []
        out = xcconfig.resolve("/", "F0.xcconfig", read=lambda _r, rel: reads.append(rel) or files.get(rel))
        self.assertEqual(out["LAST"].value, "1")
        self.assertEqual(len(reads), 9)


class DebugBlockTests(unittest.TestCase):
    def test_blank_debug(self):
        code = (
            "a()\n#if DEBUG\nb()\n#elseif STAGING\nc()\n#else\nd()\n#endif\n"
            "#if !DEBUG\ne()\n#else\nf()\n#endif\n"
            "#ifdef DEBUG\ng()\n#endif\n#if DEBUG && targetEnvironment(simulator)\nh()\n#endif\n"
            "#if os(iOS)\n#if DEBUG\ni()\n#endif\nj()\n#endif\n"
        )
        out = ios_detectors._blank_debug(code)
        self.assertEqual(len(out), len(code))
        kept = {c for c in "abcdefghij" if f"{c}()" in out}
        self.assertEqual(kept, {"a", "c", "d", "e", "j"})


class BinaryPlistScanTests(unittest.TestCase):
    """The ATS detector reads binary Info.plist files too (line 0: no line numbers in binary)."""

    def test_binary_info_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "App"))
            with open(os.path.join(tmp, "App", "Info.plist"), "wb") as fh:
                fh.write(plistlib.dumps({"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}},
                                        fmt=plistlib.FMT_BINARY))
            with open(os.path.join(tmp, "App", "Evil.plist"), "w", encoding="utf-8") as fh:
                fh.write('<?xml version="1.0"?>\n<!DOCTYPE plist [<!ENTITY a "b">]>\n<plist><dict/></plist>')
            hits = helpers.scan_dir(tmp, {"IOS-001"})
            self.assertEqual([(h.location.path, h.location.line) for h in hits], [("App/Info.plist", 0)])

    def test_infoplist_key_in_xcconfig(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "App.xcconfig"), "w", encoding="utf-8") as fh:
                fh.write("GENERATE_INFOPLIST_FILE = YES\nINFOPLIST_KEY_NSAllowsArbitraryLoads = YES\n")
            with open(os.path.join(tmp, "AppDebug.xcconfig"), "w", encoding="utf-8") as fh:
                fh.write("GENERATE_INFOPLIST_FILE = YES\nINFOPLIST_KEY_NSAllowsArbitraryLoads = YES\n")
            hits = helpers.scan_dir(tmp, {"IOS-001"})
            self.assertEqual([(h.location.path, h.location.line) for h in hits], [("App.xcconfig", 2)])


if __name__ == "__main__":
    unittest.main()


PROJECT = """// !$*UTF8*$!
{
 archiveVersion = 1; objectVersion = 77;
 objects = {
  F1 = {isa = PBXFileReference; path = A.swift; sourceTree = "<group>"; };
  F2 = {isa = PBXFileReference; path = T.swift; sourceTree = "<group>"; };
  F3 = {isa = PBXFileReference; lastKnownFileType = folder; path = Bundled; sourceTree = "<group>"; };
  G1 = {isa = PBXGroup; children = (G2, G3, F3); sourceTree = "<group>"; };
  G2 = {isa = PBXGroup; children = (F1); path = App; sourceTree = "<group>"; };
  G3 = {isa = PBXGroup; children = (F2); path = Helpers; sourceTree = "<group>"; };
  B1 = {isa = PBXBuildFile; fileRef = F1; };
  B2 = {isa = PBXBuildFile; fileRef = F2; };
  B3 = {isa = PBXBuildFile; fileRef = F3; };
  P1 = {isa = PBXSourcesBuildPhase; files = (B1); };
  P2 = {isa = PBXSourcesBuildPhase; files = (B2); };
  P3 = {isa = PBXResourcesBuildPhase; files = (B3); };
  T1 = {isa = PBXNativeTarget; buildConfigurationList = L1; buildPhases = (P1, P3); name = App;
        productType = "com.apple.product-type.application"; };
  T2 = {isa = PBXNativeTarget; buildConfigurationList = L2; buildPhases = (P2); name = AppChecks;
        productType = "com.apple.product-type.bundle.unit-test"; };
  L1 = {isa = XCConfigurationList; buildConfigurations = (C1); };
  C1 = {isa = XCBuildConfiguration; buildSettings = {INFOPLIST_FILE = "$(SRCROOT)/App/Info.plist"; }; name = Release; };
  L2 = {isa = XCConfigurationList; buildConfigurations = (); };
  R = {isa = PBXProject; mainGroup = G1; targets = (T1, T2); };
 };
 rootObject = R;
}
"""


class TargetMembership(unittest.TestCase):
    """Which Apple sources and Info.plists a shipped Xcode target uses."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        files = {
            "App.xcodeproj/project.pbxproj": PROJECT,
            "App/A.swift": "", "App/Info.plist": "", "Helpers/T.swift": "", "App/Orphan.swift": "",
            "App/Old-Info.plist": "", "App/Config.plist": "", "Bundled/Script.swift": "",
            "Packages/Kit/Package.swift": "", "Packages/Kit/Sources/K.swift": "",
            "LocalPod/LocalPod.podspec": "", "LocalPod/Classes/P.swift": "",
            "sampleapps/BugReportSampleApp/BugReportSampleApp.xcodeproj/project.pbxproj": PROJECT,
            "sampleapps/BugReportSampleApp/App/A.swift": "",
        }
        for rel, text in files.items():
            path = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_scopes(self):
        from masaudit import engine, safety
        from masaudit.detectors import ios
        from masaudit.model import Project
        ctx = engine.Context(Project(root=self.tmp, platforms=["ios"], files=safety.walk(self.tmp)))
        expected = {
            "App/A.swift": "", "App/Info.plist": "", "Bundled/Script.swift": "",
            "Helpers/T.swift": "test",
            "App/Orphan.swift": "unshipped", "App/Old-Info.plist": "unshipped",
            "App/Config.plist": "",                              # may reach the app through a build script
            "Packages/Kit/Sources/K.swift": "", "LocalPod/Classes/P.swift": "",
            "sampleapps/BugReportSampleApp/App/A.swift": "unshipped",
            "sampleapps/BugReportSampleApp/BugReportSampleApp.xcodeproj/project.pbxproj": "unshipped",
        }
        for path, scope in expected.items():
            with self.subTest(path=path):
                self.assertEqual(ios.target_scope(ctx, path), scope)
        self.assertEqual(engine._shipped(ctx, "App/Orphan.swift", "main"), "unshipped")
        self.assertEqual(ios.target_scope(engine.Context(Project(root=self.tmp, platforms=["android"],
                                                                 files=safety.walk(self.tmp))), "App/Orphan.swift"), "")
