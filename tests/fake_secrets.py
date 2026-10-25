# SPDX-License-Identifier: Apache-2.0
"""Fake secrets for fixtures, assembled at test time.

Fixture files contain placeholders such as {{FAKE_STRIPE_LIVE}} instead of realistic keys, so no
secret-looking string is ever committed (GitHub push protection and other secret scanners would
rightly flag one). None of these values are real credentials.
"""

FAKES = {
    "FAKE_AWS_KEY_ID": "AKIA" + "Q3VZ7TBN2KD5MF8H",
    "FAKE_OPENAI_KEY": "sk-" + "proj-" + "Zq8Lr2Vt6Yx1Nc4Bm7Ka9Wd3Fs5Gh0Jp",
    "FAKE_STRIPE_LIVE": "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "FAKE_GOOGLE_KEY": "AIza" + "SyB3x9Kq2Lm8Vn4Rt7Yw1Zc5Df6Gh0Jk2Pq",
    "FAKE_RN002_PASSWORD": "e7" + "4b1c9d03aa58f26e51",
    "FAKE_RN002_SECRET": "q9" + "Vr2Lx7Tn4Kd8Wm3Hz6Pb",
    "FAKE_RN002_SENTRY": "sntrys_" + "eyJpYXQiOjE3MDAwMDAwMDB9" + "_Qm9n5Tz2Lr8Vx4Kc7Wd1Ys",
    "FAKE_RN019_NPM": "npm_" + "Zq8Lr2Vt6Yx1Nc4Bm7Ka9Wd3Fs5Gh0Jp4Tx2",
}


def materialize(text):
    for name, value in FAKES.items():
        text = text.replace("{{" + name + "}}", value)
    return text
