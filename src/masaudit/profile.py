# SPDX-License-Identifier: Apache-2.0
"""What kind of app is this? The answer decides which advice applies.

Mapping from the book: MAS profiles (§3.2), pinning by application type (§8.8), and
assessment profiles by app (§23.1: a banking app is typically L2+P+R, a news app L1+P).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from masaudit.model import AppTypeWarning, Profile
from masaudit.textscan import _NeedleIndex

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

# Code clues: evidence in the code that the app may be riskier than the type chosen. They never change
# the type silently: `check` turns them into a warning when the chosen type skips checks the suggested
# type needs. (pattern, what was found, the least risky type the evidence implies, or None for a
# clue that names no type, and a note for those.)
CLUES: List[Tuple[str, str, Optional[str], str]] = [
    # Payment SDKs, matched by package, import, pod, or Flutter/React Native package name, never by a
    # bare word: "paypal" in a list of website names or a URL scheme is not a payment SDK.
    (r"com\.stripe|stripe-(?:android|ios)|StripePaymentSheet|\bimport\s+Stripe\w*|flutter_stripe"
     r"|@stripe/stripe-react-native|pod\s+['\"]Stripe", "a payment SDK (Stripe)", "ecommerce", ""),
    (r"com\.braintreepayments|braintree_(?:ios|android)|\bimport\s+Braintree\w*|com\.adyen\.checkout"
     r"|adyen-(?:ios|android)|\bimport\s+Adyen\w*|com\.checkout\.(?:android|frames|risk)|frames-(?:ios|android)"
     r"|com\.paypal\.(?:android|checkout|messages)|paypal-ios|\bimport\s+PayPal\w*"
     r"|com\.squareup\.sdk\.(?:in-app-payments|reader)|com\.razorpay|\bimport\s+Razorpay|razorpay_flutter"
     r"|co\.paystack|flutter_paystack|com\.flutterwave|flutterwave_standard|com\.mercadopago|com\.payu\."
     r"|com\.paymob|com\.fawry|com\.oppwa|\bimport\s+OPPWAMobile|com\.klarna|\bimport\s+KlarnaMobileSDK"
     r"|com\.afterpay|pod\s+['\"](?:Braintree|Adyen|PayPal\w*|razorpay-pod|Klarna\w*)",
     "a payment SDK", "ecommerce", ""),
    (r"play-services-wallet|com\.google\.android\.gms\.wallet|IsReadyToPayRequest|PKPaymentRequest"
     r"|PKPaymentAuthorization(?:Controller|ViewController)", "Google Pay or Apple Pay", "ecommerce", ""),
    # Card fields: names that mean a card, never a bare "cvc" (Signal names a view controller `cvc`).
    (r"\bcardNumber\b|\bcard_number\b|primaryAccountNumber|\bcvv\b|\bcard(?:Cvc|Cvv|_cvc|_cvv)\b"
     r"|\bcardExpiry|\bcard_expiry", "card-number fields", "ecommerce-cards", ""),
    (r"com\.plaid\.link|\bimport\s+LinkKit\b|truelayer|com\.tink\.link|tink-link|yapily",
     "an open-banking SDK", "banking", ""),
    (r"\bweb3j\b|\bbitcoinj\b|\bethers\b|WalletConnect|TrustWalletCore|\breown\b",
     "a crypto wallet library", "banking", ""),
    (r"com\.onfido|\bimport\s+Onfido|com\.jumio|\bimport\s+Jumio|com\.veriff|\bimport\s+Veriff|com\.sumsub"
     r"|IdensicMobileSDK|de\.idnow|withpersona|\bimport\s+Persona\b",
     "an identity-verification (KYC) SDK", "identity", ""),
    (r"NFCTagReaderSession|\bIsoDep\b|\bjmrtd\b|\beMRTD\b", "passport or ID-card NFC reading", "identity", ""),
    (r"HealthKit|HKHealthStore|androidx\.health\.connect|health-connect|HealthConnectClient",
     "a health data API", "health", ""),
    # Controlling devices, not displaying on them: Android Auto and CarPlay apps are often media players.
    (r"HMHomeManager|chip\.devicecontroller|\bMatterSupport\b|com\.google\.home\.",
     "a smart-home API", "device-control", ""),
    (r"com\.microsoft\.intune\.mam|IntuneMAM|android\.content\.APP_RESTRICTIONS|com\.apple\.configuration\.managed",
     "managed-device (MDM) configuration", "enterprise", ""),
    (r"com\.unity3d|UnityPlayer|com\.epicgames\.(?:ue4|unreal)|org\.cocos2dx|org\.godotengine",
     "a game engine", "game", ""),
    # Issuing passes to Wallet, not showing a .pkpass someone sent (Signal, Thunderbird).
    (r"play-services-pay|com\.google\.android\.gms\.pay|savePasses|pay\.google\.com/gp/v/save",
     "a Google Wallet pass", "loyalty", ""),
    (r"(?i:\bloyalty|reward_?points|points_?balance|redeem_?(?:points|coupon|voucher))",
     "loyalty or points code", "loyalty", ""),
]


# Literal substrings that every match of a clue contains. A file without any of them is skipped with a
# fast substring search, so the regex (slow on large code bases) runs only on the rare candidates.
NEEDLES: Dict[str, Tuple[str, ...]] = {
    "a payment SDK (Stripe)": ("stripe", "Stripe"),
    "a payment SDK": ("raintree", "dyen", "com.checkout", "frames-", "aypal", "PayPal", "squareup", "azorpay",
                      "aystack", "lutterwave", "mercadopago", "com.payu", "paymob", "fawry", "oppwa", "OPPWA",
                      "lutterwave", "larna", "afterpay"),
    "Google Pay or Apple Pay": ("wallet", "IsReadyToPayRequest", "PKPayment"),
    "card-number fields": ("card", "cvv", "primaryAccountNumber"),
    "an open-banking SDK": ("plaid", "LinkKit", "truelayer", "tink.link", "tink-link", "yapily"),
    "a crypto wallet library": ("web3j", "bitcoinj", "ethers", "WalletConnect", "TrustWalletCore", "reown"),
    "an identity-verification (KYC) SDK": ("nfido", "umio", "eriff", "sumsub", "Idensic", "idnow", "ersona"),
    "passport or ID-card NFC reading": ("NFCTagReaderSession", "IsoDep", "jmrtd", "eMRTD"),
    "a health data API": ("HealthKit", "HKHealthStore", "ealth"),
    "a smart-home API": ("HMHomeManager", "devicecontroller", "MatterSupport", "google.home"),
    "managed-device (MDM) configuration": ("intune", "IntuneMAM", "APP_RESTRICTIONS", "configuration.managed"),
    "a game engine": ("unity3d", "UnityPlayer", "epicgames", "cocos2dx", "godotengine"),
    "a Google Wallet pass": ("play-services-pay", "gms.pay", "savePasses", "gp/v/save"),
    "loyalty or points code": ("oyalty", "OYALTY", "eward", "EWARD", "oints", "OINTS", "edeem", "EDEEM"),
}
_COMPILED = [(re.compile(pattern), label, app_type, note, NEEDLES[label])
             for pattern, label, app_type, note in CLUES]


@dataclass(frozen=True)
class Clue:
    label: str                 # what was found, e.g. "card-number fields"
    path: str                  # the first file it was found in
    app_type: Optional[str]    # the least risky type the evidence implies; None if it names no type
    note: str = ""

    def describe(self) -> str:
        if self.app_type is None:
            return f"Found {self.label} in {self.path} — {self.note}"
        return f"Found {self.label} in {self.path} — {self.app_type} may fit"


def find_clues(texts: Dict[str, str], strip: Optional[Callable[[str, str], str]] = None) -> List[Clue]:
    """Evidence about the app's type (path -> text). With `strip`, a raw match only counts if it
    survives strip(path, text), which removes comments; files without a raw match are never stripped."""
    found: Dict[str, Clue] = {}
    # One word index answers every clue's needles, instead of a pass over all the text per clue.
    index = _NeedleIndex(list(texts.values()))
    for k, (path, text) in enumerate(texts.items()):
        stripped: Optional[str] = None
        for regex, label, app_type, note, needles in _COMPILED:
            if label in found or k not in index.holding_any(needles) or not regex.search(text):
                continue
            if strip is not None:
                if stripped is None:
                    stripped = strip(path, text)
                if not regex.search(stripped):
                    continue
            found[label] = Clue(label, path, app_type, note)
        if len(found) == len(_COMPILED):
            break
    return list(found.values())


def infer_clues(texts: Dict[str, str]) -> List[str]:
    """Human-readable suggestions from code clues (path -> text)."""
    return [c.describe() for c in find_clues(texts)]


def _needed(app_type: str, rules) -> set:
    profiles = set(APP_TYPES[app_type][0])
    return {r.id for r in rules if not r.retired and set(r.profiles) & profiles
            and (r.app_types is None or app_type in r.app_types)}


def check(profile: Profile, clues: List[Clue], rules, findings=(), applies: Callable = lambda rule: True,
          reviewed: Sequence[str] = ()) -> List[AppTypeWarning]:
    """Warnings when the code suggests a riskier type than the one chosen.

    A clue warns only when its type runs checks the chosen type skips on this project's platforms
    (`applies`), so evidence that changes nothing (a payment SDK in a news app) stays a quiet clue.
    A warning that another one covers is dropped, the riskiest comes first, and types the team
    marked as reviewed (`app_type_reviewed` in .masaudit.ini) don't warn.
    """
    rules = [r for r in rules if applies(r)]
    chosen = _needed(profile.app_type, rules)
    titles = {r.id: r.title for r in rules}
    candidates = []
    for clue in clues:
        t = clue.app_type
        if t is None or t == profile.app_type or t in reviewed or any(c[0].app_type == t for c in candidates):
            continue
        skipped = _needed(t, rules) - chosen
        if skipped:
            candidates.append((clue, skipped))
    candidates.sort(key=lambda c: -len(c[1]))
    kept = [c for i, c in enumerate(candidates)
            if not any(c[1] <= other[1] for j, other in enumerate(candidates) if j < i)]
    warnings: List[AppTypeWarning] = []
    for clue, skipped in kept:
        hidden = sorted({f.rule.id for f in findings
                         if f.bucket == "not-needed" and f.status == "open" and f.rule.id in skipped})
        warnings.append(AppTypeWarning(
            chosen=profile.app_type, source=profile.source, suggested=clue.app_type or "", evidence=clue.label,
            path=clue.path, extra_checks=len(skipped), hidden=[(i, titles[i]) for i in hidden]))
    return warnings


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


def describe(profile: Profile) -> str:
    profiles = "+".join(p for p in ["L1", "L2", "R", "P"] if p in profile.mas_profiles)
    source = {
        "flag": "from --app-type",
        "config": "from .masaudit.ini",
        "prompt": "from your answer",
        "default": "assumed (no app type given)",
    }.get(profile.source, profile.source)
    return f"{profile.app_type} ({APP_TYPES[profile.app_type][1]}); MAS-{profiles}; {source}"
