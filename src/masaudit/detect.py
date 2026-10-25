# SPDX-License-Identifier: Apache-2.0
"""Detect which platforms a project contains, from file names alone."""

from __future__ import annotations

import functools
import os
import re
from typing import List, Optional

# An Android import at the start of a line: `import android.os.Bundle`, `import androidx.webkit.*`.
_ANDROID_IMPORT = re.compile(rb"^[ \t]*import[ \t]+(?:static[ \t]+)?androidx?\.", re.MULTILINE)
_SNIFF_BYTES = 16384          # imports sit at the top of a file
_SNIFF_FILES = 2000


def _imports_android(root: str, files: List[str]) -> bool:
    """Does a Kotlin or Java production file import android.* or androidx.*? For a folder of sources with no
    manifest or Gradle file (a copied module, decompiled code). Reads only the head of each file."""
    checked = 0
    for f in files:
        if not f.endswith((".kt", ".java")) or scope_of(f) == "test":
            continue
        checked += 1
        if checked > _SNIFF_FILES:
            return False
        try:
            with open(os.path.join(root, f), "rb") as fh:
                head = fh.read(_SNIFF_BYTES)
        except OSError:
            continue
        if _ANDROID_IMPORT.search(head):
            return True
    return False


_PACKAGE_FILES = 200          # package.json files read, at most (a monorepo has one per package)
_DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")


def depends_on(package_json: Optional[str], *names: str) -> bool:
    """Whether a package.json text lists one of `names` in a dependency section. Only those sections count:
    `"react-native"` as a key under `jest`, `overrides`, or `resolutions` is not a dependency."""
    if not package_json:
        return False
    import json
    try:
        data = json.loads(package_json)
    except (ValueError, RecursionError):
        return False
    if not isinstance(data, dict):
        return False
    return any(isinstance(data.get(s), dict) and any(n in data[s] for n in names) for s in _DEPENDENCY_SECTIONS)


def _is_react_native(files: List[str], root: Optional[str]) -> bool:
    """A React Native app: a package.json that depends on react-native or expo. Without `root` (file names
    only), a package.json next to an RN entry file, which can also be a plain Node project."""
    packages = [f for f in files if f == "package.json" or f.endswith("/package.json")]
    if not packages:
        return False
    if root is None:
        return any(f.endswith(("index.js", "App.tsx", "App.js")) for f in files)
    from masaudit import safety          # detect is imported by safety's users; keep the import local
    for rel in packages[:_PACKAGE_FILES]:
        if depends_on(safety.read_text(root, rel), "react-native", "expo"):
            return True
    return False


_EXPO_CONFIGS = ("app.json", "app.config.json", "app.config.js", "app.config.ts", "app.config.mjs", "app.config.cjs")


def _managed_expo(files: List[str], root: Optional[str]) -> List[str]:
    """Platforms `expo prebuild` generates for a managed Expo app, which commits no android/ or ios/ folder: an app
    folder whose own package.json depends on expo and that holds an Expo config (app.json with an `expo` object,
    or app.config.*). A literal `expo.platforms` list limits them. Needs `root`; [] without it."""
    if root is None:
        return []
    import json
    from masaudit import safety
    names = set(files)
    configs = sorted((f for f in files if f.rpartition("/")[2] in _EXPO_CONFIGS and scope_of(f) == "main"),
                     key=lambda p: (p.count("/"), p))
    out: List[str] = []
    for f in configs[:_PACKAGE_FILES]:
        folder, _, base = f.rpartition("/")
        pkg = (folder + "/" if folder else "") + "package.json"
        if pkg not in names or not depends_on(safety.read_text(root, pkg), "expo"):
            continue
        wanted = ["android", "ios"]
        if base.endswith(".json"):
            try:
                data = json.loads(safety.read_text(root, f) or "")
            except (ValueError, RecursionError):
                continue
            expo = data.get("expo") if isinstance(data, dict) else None
            if not isinstance(expo, dict):
                continue
            if isinstance(expo.get("platforms"), list):
                wanted = [p for p in wanted if p in expo["platforms"]]
        out += [p for p in wanted if p not in out]
    return out


def platforms(files: List[str], root: Optional[str] = None) -> List[str]:
    """Platforms from file names; with `root`, also Android from the imports of Kotlin and Java files, React
    Native from package.json, and the platforms a managed Expo app generates at build time."""
    names = set(files)
    found: List[str] = []
    react_native = _is_react_native(files, root)
    expo = _managed_expo(files, root) if react_native else []
    if any(f.endswith("AndroidManifest.xml") for f in names) or any(
        f.endswith(("build.gradle", "build.gradle.kts")) for f in names
    ) or (root is not None and _imports_android(root, files)) or "android" in expo:
        found.append("android")
    if any(".xcodeproj/" in f or f.endswith(("Info.plist", ".entitlements", "Package.swift", "Podfile"))
           for f in names) or any(f.endswith(".swift") for f in names) or "ios" in expo:
        found.append("ios")
    if any("/commonMain/" in f or f.startswith("commonMain/") for f in names):
        found.append("kmp")
    if "pubspec.yaml" in names or any(f.endswith("/pubspec.yaml") for f in names):
        found.append("flutter")
    if react_native:
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
# A set named test..., or ...Test... in camel case: "latest" and "attestation" are not test sets.
_TEST_SOURCE_SET = re.compile(r"/src/(?:[Tt]est\w*|\w*Test\w*|(?i:android|integration|unit|instrumented|ui|screenshot|"
                              r"shared)test\w*|[Bb]enchmark\w*)/")
# Xcode and SPM test or mock targets: SignalServiceKitTests/, WikipediaUnitTests/, WMFDataMocks/.
_TEST_TARGET = re.compile(r"(?:^|/)[\w-]*(?:Tests|UITests|Mocks)/")
# Case-sensitive file names: FooTest.kt, FooTests.swift, FooSpec.kt, FooIT.java, foo_test.dart. A lowercase
# letter or digit must come before "Test", so ABTest.kt, Latest.kt, and KeyAttest.kt stay main.
_TEST_FILE = re.compile(r"(?:[a-z0-9_](?:Test|Spec|IT)(?:_\w+)?\.(?:kt|java|swift|m|mm)|[A-Za-z0-9_]Tests\.(?:kt|java|swift|m|mm)"
                        r"|_test\.dart)$")
_DEBUG_DIRS = {"sample", "samples", "example", "examples", "demo", "demos", "catalog", "showcase",
               "preview content"}
# Storybook's folders count as debug code for JavaScript-side files only. A folder named `stories` is often a
# shipping feature (in native or JS code); Storybook's own files are `*.stories.*`.
_JS_STORY_DIRS = {"storybook", ".storybook"}
# JavaScript and TypeScript tests: Jest's __tests__ and __mocks__ folders anywhere, Detox and Maestro e2e
# folders, and foo.test.ts / foo.spec.tsx files; jest.setup.js and setupTests.ts configure them.
# The folders count only for JavaScript-side files: a Kotlin package or Swift group named `e2e` or `jest` in
# the app's own native code is production code.
_JS_TEST_DIRS = {"__tests__", "__mocks__", "__fixtures__", "e2e", "detox", "jest", "maestro"}
_JS_TEST_DIR_FILES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".snap", ".yaml", ".yml")
_JS_TEST_FILE = re.compile(r"(?:\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs)|^(?:jest\.setup|setupTests|jest\.config)"
                           r"\.(?:js|ts|cjs|mjs))$")
_JS_STORY_FILE = re.compile(r"\.stories\.(?:js|jsx|ts|tsx)$")
# Build tooling for JavaScript apps: bundler, transpiler, and React Native CLI configuration.
_JS_BUILD_FILE = re.compile(r"^(?:metro|babel|react-native|webpack|rollup|vite|eslint|prettier)\.config\.(?:js|cjs|mjs|ts)$"
                            r"|^\.babelrc(?:\.js)?$")
_PREVIEW_FILE = re.compile(r"(?:Preview|Previews|PreviewParam\w*|PreviewProvider|StateProvider)\.kt$")
_TOOLING_TOP = {"build-logic", "buildsrc", "scripts", "tools", "fastlane"}


@functools.lru_cache(maxsize=65536)          # every rule asks about the same paths
def scope_of(path: str) -> str:
    """Where in the project a file lives. Used to downgrade hits outside production code."""
    p = "/" + path
    low = p.lower()
    if "/.github/" in low:
        return "ci"
    base = p.rsplit("/", 1)[-1]
    module = low.split("/src/", 1)[0] if "/src/" in low else low.rsplit("/", 1)[0]
    if (_TEST_SOURCE_SET.search(p) or _TEST_TARGET.search(p) or _TEST_FILE.search(base)
            or any(seg in _TEST_DIRS for seg in module.split("/"))
            or _JS_TEST_FILE.search(base)
            or (low.endswith(_JS_TEST_DIR_FILES) and any(seg in _JS_TEST_DIRS for seg in low.split("/")[:-1]))):
        return "test"
    if _JS_STORY_FILE.search(base) or (low.endswith(_JS_TEST_DIR_FILES)
                                       and any(seg in _JS_STORY_DIRS for seg in low.split("/")[:-1])):
        return "debug"
    if any(d in low for d in ("/src/debug/", "/src/mock/", "/src/internal/")) or _PREVIEW_FILE.search(base):
        return "debug"
    # Sample, demo, catalog, and internal-build modules (sync-internal, settings/internal) count as debug
    # code, but only as module directories: a package such as src/main/java/com/example/... is production.
    if any(seg in _DEBUG_DIRS or seg == "internal" or seg.endswith("-internal") for seg in module.split("/")):
        return "debug"
    top = low.lstrip("/").split("/", 1)[0]
    if (top in _TOOLING_TOP or low.endswith((".gradle", ".gradle.kts", "podfile", "package.swift", ".toml"))
            or _JS_BUILD_FILE.search(base)):
        return "build-script"
    return "main"
