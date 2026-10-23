# SPDX-License-Identifier: Apache-2.0
"""AndroidManifest.xml helpers on top of xmlsafe: components, intent filters, merge markers."""

from __future__ import annotations

from typing import Dict, Iterator, List, Optional

from masaudit.parsers import xmlsafe
from masaudit.parsers.xmlsafe import Element

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def parse(text: str) -> Optional[Element]:
    root = xmlsafe.parse(text)
    if root is None or root.tag != "manifest":
        return None
    return root


def is_placeholder(value: Optional[str]) -> bool:
    """`${applicationId}`-style manifest placeholders: the real value is decided at build time."""
    return bool(value) and "${" in value


def is_removed(el: Element) -> bool:
    """`tools:node="remove"` tells the manifest merger to drop this element."""
    return (el.get("tools:node") or "").strip() in ("remove", "removeAll")


def applications(root: Element) -> List[Element]:
    return [a for a in root.children if a.tag == "application" and not is_removed(a)]


def components(root: Element, tags=COMPONENT_TAGS) -> Iterator[Element]:
    for app in applications(root):
        for c in app.children:
            if c.tag in tags and not is_removed(c):
                yield c


def intent_filters(component: Element) -> List[Element]:
    return [f for f in component.children if f.tag == "intent-filter" and not is_removed(f)]


def names(parent: Element, tag: str) -> List[str]:
    return [c.get("android:name") or "" for c in parent.children if c.tag == tag and not is_removed(c)]


def data_attrs(intent_filter: Element) -> List[Dict[str, str]]:
    return [c.attrs for c in intent_filter.children if c.tag == "data" and not is_removed(c)]


def is_launcher(component: Element) -> bool:
    for f in intent_filters(component):
        if ("android.intent.action.MAIN" in names(f, "action")
                and "android.intent.category.LAUNCHER" in names(f, "category")):
            return True
    return False


def is_browsable_only(component: Element) -> bool:
    """Every intent filter is a web/deep-link filter (VIEW + BROWSABLE)."""
    filters = intent_filters(component)
    return bool(filters) and all(
        "android.intent.category.BROWSABLE" in names(f, "category") for f in filters
    )


def declared_permissions(root: Element) -> Dict[str, str]:
    """<permission> name -> protectionLevel ("normal" when absent, as Android defaults)."""
    out: Dict[str, str] = {}
    for p in root.children:
        if p.tag == "permission" and not is_removed(p):
            out[p.get("android:name") or ""] = (p.get("android:protectionLevel") or "normal").strip()
    return out


def uses_permissions(root: Element) -> Iterator[Element]:
    for p in root.children:
        if p.tag in ("uses-permission", "uses-permission-sdk-23") and not is_removed(p):
            yield p
