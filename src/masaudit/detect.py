# SPDX-License-Identifier: Apache-2.0
"""Detect which platforms a project contains, from file names alone."""

from __future__ import annotations

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


def scope_of(path: str) -> str:
    """Where in the project a file lives. Used to downgrade hits outside production code."""
    p = "/" + path.lower()
    if "/.github/" in p:
        return "ci"
    if any(s in p for s in ("/src/test/", "/src/androidtest/", "/tests/", "/test/", "uitests/",
                            "tests.swift", "test.kt", "test.java", "/commontest/", "/fixtures/")):
        return "test"
    if any(s in p for s in ("/src/debug/", "/src/mock/")):
        return "debug"
    # Sample/demo modules count as debug code, but only as module directories: a package such as
    # src/main/java/com/example/... is production code.
    module = p.split("/src/", 1)[0] if "/src/" in p else p.rsplit("/", 1)[0]
    if any(seg in ("sample", "samples", "example", "examples", "demo", "demos")
           for seg in module.split("/")):
        return "debug"
    if p.endswith((".gradle", ".gradle.kts", "podfile", "package.swift", ".toml")):
        return "build-script"
    return "main"
