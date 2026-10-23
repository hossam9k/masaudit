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
# §3.2: L2 for high-risk data or sensitive functions; R for apps protecting their own logic or assets;
# P for every app that handles user-sensitive data. Pinning by type follows §8.8.
APP_TYPES: Dict[str, Tuple[List[str], str]] = {
    "banking":         (["L1", "L2", "R", "P"], "Banking, payments, wallets, crypto, lending, or insurance"),
    "identity":        (["L1", "L2", "R", "P"], "Digital ID, government, password manager, VPN, or carrier"),
    "health":          (["L1", "L2", "P"],      "Health, medical, or mental-health data"),
    "ecommerce-cards": (["L1", "L2", "P"],      "Shop where your own code handles card numbers"),
    "ecommerce":       (["L1", "P"],            "Shop, food ordering, or booking (payment SDK takes cards)"),
    "loyalty":         (["L1", "R", "P"],       "Loyalty points, coupons, gift cards, tickets (no cards)"),
    "marketplace":     (["L1", "P"],            "Marketplace, ride-hailing, delivery, jobs, or listings"),
    "social":          (["L1", "P"],            "Social, messaging, dating, or community"),
    "content":         (["L1", "P"],            "News, video, music, reading, or learning"),
    "device-control":  (["L1", "L2", "P"],      "Controls real things: smart locks, home devices, or cars"),
    "enterprise":      (["L1", "L2", "P"],      "Internal app for your company's own staff"),
    "game":            (["L1", "R", "P"],       "Game (cheating and tampering matter)"),
    "general":         (["L1", "P"],            "Something else: a tool, notes, photos, maps (or not sure)"),
}

ALIASES = {
    "bank": "banking", "payments": "banking", "trading": "banking", "fintech": "banking",
    "finance": "banking", "crypto": "banking", "lending": "banking",
    "insurance": "banking",
    "government": "identity", "eid": "identity", "id": "identity", "password-manager": "identity",
    "authenticator": "identity", "vpn": "identity", "telecom": "identity", "carrier": "identity",
    "medical": "health",
    "shop": "ecommerce", "shopping": "ecommerce", "retail": "ecommerce", "food": "ecommerce",
    "restaurant": "ecommerce", "ordering": "ecommerce", "travel": "ecommerce", "booking": "ecommerce",
    "rewards": "loyalty", "points": "loyalty", "coupons": "loyalty", "vouchers": "loyalty",
    "gift-cards": "loyalty", "tickets": "loyalty", "ticketing": "loyalty",
    "ride-sharing": "marketplace", "ride-hailing": "marketplace", "delivery": "marketplace",
    "jobs": "marketplace", "real-estate": "marketplace",
    "messaging": "social", "chat": "social", "dating": "social",
    "news": "content", "media": "content", "blog": "content", "reader": "content",
    "education": "content", "learning": "content", "streaming": "content", "music": "content",
    "video": "content",
    "iot": "device-control", "smart-home": "device-control", "automotive": "device-control",
    "car": "device-control",
    "internal": "enterprise", "corporate": "enterprise", "games": "game",
    "other": "general", "tool": "general", "utility": "general",
}

# Code clues: they only suggest a type, stated in the report, never applied silently.
# (pattern, what was found, app types that may fit, or "no type ..." when the clue decides nothing)
CLUES: List[Tuple[str, str, str]] = [
    (r"com\.stripe|stripe-android|StripePaymentSheet|\bStripe\b", "a payment SDK (Stripe)", "ecommerce or banking"),
    (r"braintree|adyen|checkout\.com|com\.checkout|paypal", "a payment SDK", "ecommerce or banking"),
    (r"HealthKit|HKHealthStore|androidx\.health\.connect|health-connect|HealthConnectClient",
     "a health data API", "health"),
    (r"cardNumber|card_number|primaryAccountNumber|\bcvv\b|\bcvc2?\b", "card-number fields", "ecommerce-cards"),
    (r"play-services-pay|PayClient|savePasses|pay\.google\.com/gp/v/save|PKAddPassesViewController|\.pkpass\b",
     "a wallet pass (Google or Apple Wallet)", "loyalty"),
    (r"(?i)\bloyalty|reward_?points|points_?balance|redeem_?(?:points|coupon|voucher)",
     "loyalty or points code", "loyalty"),
    (r"\bweb3j\b|\bbitcoinj\b|\bethers\b|WalletConnect|TrustWalletCore", "a crypto wallet library", "banking"),
    (r"NFCTagReaderSession|\bIsoDep\b|\bjmrtd\b|\beMRTD\b", "passport or ID-card NFC reading", "identity"),
    (r"HMHomeManager|androidx\.car\.app|\bCarPlay\b|chip\.devicecontroller",
     "a smart-home or car API", "device-control"),
    (r"BiometricPrompt|LAContext", "biometric authentication", "no type on its own; check biometric binding (Chapter 11)"),
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
