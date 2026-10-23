# SPDX-License-Identifier: Apache-2.0
"""What kind of app is this? The answer decides which advice applies.

Mapping from the book: MAS profiles (§3.2), pinning by application type (§8.8), and
assessment profiles by app (§23.1: a banking app is typically L2+P+R, a news app L1+P).
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from masaudit.model import Profile

# app type -> (MAS profiles, one-line description shown in the prompt)
APP_TYPES: Dict[str, Tuple[List[str], str]] = {
    "banking":         (["L1", "L2", "R", "P"], "Banking, payments, or trading"),
    "fintech":         (["L1", "L2", "R", "P"], "Wallets, lending, crypto, or other money movement"),
    "health":          (["L1", "L2", "P"],      "Health or medical data"),
    "ecommerce-cards": (["L1", "L2", "P"],      "Shopping app that handles card numbers itself"),
    "ecommerce":       (["L1", "P"],            "Shopping app that uses a payment provider's SDK"),
    "marketplace":     (["L1", "P"],            "Marketplace, ride-sharing, or delivery"),
    "social":          (["L1", "P"],            "Social, messaging, or community"),
    "content":         (["L1", "P"],            "News, media, reading, or other content"),
    "enterprise":      (["L1", "L2", "P"],      "Internal or enterprise app"),
    "game":            (["L1", "R", "P"],       "Game (cheating and tampering matter)"),
    "general":         (["L1"],                 "Something else / not sure (baseline checks only)"),
}

ALIASES = {
    "bank": "banking", "finance": "fintech", "payments": "banking", "trading": "banking",
    "medical": "health", "shop": "ecommerce", "shopping": "ecommerce", "retail": "ecommerce",
    "news": "content", "media": "content", "blog": "content", "reader": "content",
    "messaging": "social", "chat": "social", "ride-sharing": "marketplace", "delivery": "marketplace",
    "internal": "enterprise", "corporate": "enterprise", "games": "game", "other": "general",
}

# Code clues: they only suggest a type, stated in the report, never applied silently.
# (pattern, what was found, app types that may fit, or "no type ..." when the clue decides nothing)
CLUES: List[Tuple[str, str, str]] = [
    (r"com\.stripe|stripe-android|StripePaymentSheet|\bStripe\b", "a payment SDK (Stripe)", "ecommerce"),
    (r"braintree|adyen|checkout\.com|com\.checkout|paypal", "a payment SDK", "ecommerce"),
    (r"HealthKit|HKHealthStore|androidx\.health\.connect|health-connect", "a health data API", "health"),
    (r"BiometricPrompt|LAContext", "biometric authentication", "no type on its own; check biometric binding (Chapter 11)"),
    (r"cardNumber|card_number|\bpan\b|cvv|cvc2?", "card-number fields", "ecommerce-cards"),
    (r"PlayIntegrity|com\.google\.android\.play:integrity|DCAppAttestService", "app attestation", "no type on its own; check server verification (Chapters 9 and 10)"),
]


def normalize(app_type: str) -> str:
    key = app_type.strip().lower().replace("_", "-").replace(" ", "-")
    key = ALIASES.get(key, key)
    if key not in APP_TYPES:
        raise ValueError(
            f"Unknown app type '{app_type}'. Use one of: {', '.join(APP_TYPES)}"
        )
    return key


def make(app_type: str, source: str) -> Profile:
    key = normalize(app_type)
    return Profile(app_type=key, mas_profiles=list(APP_TYPES[key][0]), source=source)


def infer_clues(texts: Dict[str, str]) -> List[str]:
    """Return human-readable suggestions from code clues (path -> text)."""
    found: Dict[str, Tuple[str, str]] = {}
    for path, text in texts.items():
        for pattern, label, fits in CLUES:
            if label in found:
                continue
            if re.search(pattern, text):
                found[label] = (path, fits)
    return [f"Found {label} in {path} — {fits}" if fits.startswith("no type") else
            f"Found {label} in {path} — {fits} may fit"
            for label, (path, fits) in found.items()]


def describe(profile: Profile) -> str:
    profiles = "+".join(p for p in ["L1", "L2", "R", "P"] if p in profile.mas_profiles)
    source = {
        "flag": "from --app-type",
        "config": "from .masaudit.ini",
        "prompt": "from your answer",
        "default": "assumed (no app type given)",
    }.get(profile.source, profile.source)
    return f"{profile.app_type} ({APP_TYPES[profile.app_type][1]}); MAS-{profiles}; {source}"
