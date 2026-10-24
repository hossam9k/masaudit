# SPDX-License-Identifier: Apache-2.0
"""Detect which platforms a project contains, from file names alone."""

from __future__ import annotations

import re
from typing import List


def platforms(files: List[str]) -> List[str]:
    names = set(files)
    found: List[str] = []
    if any(f.endswith("AndroidManifest.xml") for f in names) or any(
        f.endswith(("build.gradle", "build.gradle.kts")) for f in names
    ):
        found.append("android")
    if any(".xcodeproj/" in f or f.endswith(("Info.plist", ".entitlements", "Package.swift", "Podfile"))
           for f in names) or any(f.endswith(".swift") for f in names):
        found.append("ios")
    if any("/commonMain/" in f or f.startswith("commonMain/") for f in names):
        found.append("kmp")
    if "pubspec.yaml" in names or any(f.endswith("/pubspec.yaml") for f in names):
        found.append("flutter")
    if any(f.endswith("package.json") for f in names) and any(
        f.endswith(("index.js", "App.tsx", "App.js")) for f in names
    ):
        found.append("react-native")
    if any(f.startswith(".github/workflows/") for f in names):
        found.append("ci")
    return found


# Folder names that mean test or tooling code. For Gradle paths they count only in the module path
# (before /src/), so a production package such as src/main/java/com/acme/testing/ stays main.
_TEST_DIRS = {
    "test", "tests", "androidtest", "testshared", "sharedtest", "testfixtures", "testutil", "testutils",
    "testsupport", "testing", "uitests", "fixtures", "mocks", "fakes", "benchmark", "benchmarkshared",
}
# Gradle and KMP source sets: test, androidTest, commonTest, jvmTest, testShared, testFixtures, benchmark...
_TEST_SOURCE_SET = re.compile(r"/src/(?:\w*test\w*|benchmark\w*)/", re.IGNORECASE)
# Xcode and SPM test or mock targets: SignalServiceKitTests/, WikipediaUnitTests/, WMFDataMocks/.
_TEST_TARGET = re.compile(r"(?:^|/)[\w-]*(?:Tests|UITests|Mocks)/")
# Case-sensitive file names: FooTest.kt, FooTests.swift, FooSpec.kt, FooIT.java, foo_test.dart. A lowercase
# letter or digit must come before "Test", so ABTest.kt, Latest.kt, and KeyAttest.kt stay main.
_TEST_FILE = re.compile(r"(?:[a-z0-9_](?:Test|Tests|Spec|IT)(?:_\w+)?\.(?:kt|java|swift|m|mm)|_test\.dart)$")
_DEBUG_DIRS = {"sample", "samples", "example", "examples", "demo", "demos", "catalog", "showcase",
               "preview content"}
_PREVIEW_FILE = re.compile(r"(?:Preview|Previews|PreviewParam\w*|PreviewProvider|StateProvider)\.kt$")
_TOOLING_TOP = {"build-logic", "buildsrc", "scripts", "tools", "fastlane"}


def scope_of(path: str) -> str:
    """Where in the project a file lives. Used to downgrade hits outside production code."""
    p = "/" + path
    low = p.lower()
    if "/.github/" in low:
        return "ci"
    base = p.rsplit("/", 1)[-1]
    module = low.split("/src/", 1)[0] if "/src/" in low else low.rsplit("/", 1)[0]
    if (_TEST_SOURCE_SET.search(p) or _TEST_TARGET.search(p) or _TEST_FILE.search(base)
            or any(seg in _TEST_DIRS for seg in module.split("/"))):
        return "test"
    if "/src/debug/" in low or "/src/mock/" in low or _PREVIEW_FILE.search(base):
        return "debug"
    # Sample, demo, and catalog modules count as debug code, but only as module directories: a package
    # such as src/main/java/com/example/... is production code.
    if any(seg in _DEBUG_DIRS for seg in module.split("/")):
        return "debug"
    top = low.lstrip("/").split("/", 1)[0]
    if top in _TOOLING_TOP or low.endswith((".gradle", ".gradle.kts", "podfile", "package.swift", ".toml")):
        return "build-script"
    return "main"
