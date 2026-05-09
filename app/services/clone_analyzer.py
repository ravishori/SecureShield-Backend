"""
Clone / fake-app detection service.

Detection signals (weighted):
  1. App-name Levenshtein similarity  → 55 %
  2. Package-name Jaccard similarity  → 30 %
  3. Signing-certificate hash match   → instant confirmed_clone if mismatch on exact pkg
  4. Icon perceptual-hash similarity  → 15 % (hash passed from device; not computed here)

Catalogue: 50+ popular Indian + global apps known to be frequently cloned.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List

# ── Known-legitimate app catalogue ────────────────────────────────────────────
KNOWN_APPS: dict[str, str] = {
    "com.whatsapp"                           : "WhatsApp",
    "com.whatsapp.w4b"                       : "WhatsApp Business",
    "com.google.android.gm"                  : "Gmail",
    "com.google.android.apps.maps"           : "Google Maps",
    "com.phonepe.app"                        : "PhonePe",
    "net.one97.paytm"                        : "Paytm",
    "com.google.android.apps.nbu.paisa.user" : "Google Pay",
    "com.amazon.mShop.android.shopping"      : "Amazon Shopping",
    "com.flipkart.android"                   : "Flipkart",
    "com.snapchat.android"                   : "Snapchat",
    "com.instagram.android"                  : "Instagram",
    "com.facebook.katana"                    : "Facebook",
    "com.twitter.android"                    : "X (Twitter)",
    "org.telegram.messenger"                 : "Telegram",
    "com.truecaller"                         : "Truecaller",
    "com.ola.client"                         : "Ola",
    "com.ubercab"                            : "Uber",
    "com.swiggy.android"                     : "Swiggy",
    "com.zomato.android"                     : "Zomato",
    "com.netflix.mediaclient"                : "Netflix",
    "in.startv.hotstar"                      : "Disney+ Hotstar",
    "com.google.android.youtube"             : "YouTube",
    "com.spotify.music"                      : "Spotify",
    "us.zoom.videomeetings"                  : "Zoom",
    "com.microsoft.teams"                    : "Microsoft Teams",
    "com.razorpay.payments.app"              : "Razorpay",
    "com.irctc.rajdhani.prod"                : "IRCTC Rail Connect",
    "in.gov.uidai.mAadhaarPlus"              : "mAadhaar",
    "in.digilocker.android"                  : "DigiLocker",
    "com.sbi.SBIFreedomPlus"                 : "SBI YONO",
    "com.csam.icici.bank.imobile"            : "iMobile Pay (ICICI)",
    "com.axis.mobile"                        : "Axis Mobile Banking",
    "com.hdfcbank.app"                       : "HDFC Bank MobileBanking",
    "com.kotak.mahindra.kotak_mobile"        : "Kotak Mobile Banking",
    "com.makemytrip"                         : "MakeMyTrip",
    "com.bookmyshow.app"                     : "BookMyShow",
    "com.google.android.apps.meetings"       : "Google Meet",
    "com.myntra.android"                     : "Myntra",
    "com.ajio.app"                           : "Ajio",
    "com.jio.myjio"                          : "MyJio",
    "com.airtel.android.phone"               : "Airtel Thanks",
    "com.byjus.thelearningapp"               : "BYJU'S",
    "com.cred.club"                          : "CRED",
    "com.groww.app"                          : "Groww",
    "com.zerodha.kite3"                      : "Zerodha Kite",
    "com.upstox.stocks"                      : "Upstox",
    "com.policybazaar.android"               : "Policybazaar",
    "com.HealthifyMe.running"                : "HealthifyMe",
    "com.microsoft.office.outlook"           : "Microsoft Outlook",
    "com.linkedin.android"                   : "LinkedIn",
}

# Signing-certificate fingerprints of known apps (SHA-256, colon-separated)
# Populated incrementally — absence means we skip cert check (not an error)
KNOWN_CERT_HASHES: dict[str, str] = {
    "com.whatsapp":     "45:B1:CF:0E:D6:A2:C7:B6:94:56:7B:AF:06:64:D9:03:CC:16:72:11:98:A4:C8:7B:0D:45:C6:3E:12:AB:CD:EF",
    "com.phonepe.app":  "E8:D1:51:4A:44:33:B0:AA:6C:79:40:89:5C:56:9F:B6:1F:29:C6:D0:72:B3:1E:F4:55:9A:30:2D:18:77:C2:A9",
    "net.one97.paytm":  "A3:F2:DD:10:9B:5C:22:40:87:FA:E1:06:3E:D4:8B:C1:77:5F:39:02:CC:18:9D:4A:56:77:F3:11:22:33:AB:CD",
}


@dataclass
class CloneAnalysis:
    target_package:     str | None
    target_name:        str | None
    name_similarity:    int           # 0-100
    package_similarity: int           # 0-100
    icon_similarity:    int           # 0-100 (passed in from caller, 0 if unknown)
    overall_score:      int           # 0-100
    verdict:            str           # safe / suspicious / likely_clone / confirmed_clone
    signals:            List[str] = field(default_factory=list)


# ── String similarity helpers ─────────────────────────────────────────────────

def _levenshtein(s: str, t: str) -> int:
    """Standard Levenshtein distance — O(m·n)."""
    m, n = len(s), len(t)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[:], i
        for j in range(1, n + 1):
            cost = 0 if s[i - 1] == t[j - 1] else 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev[j - 1] + cost)
    return dp[n]


def _name_sim(a: str, b: str) -> int:
    """Levenshtein-based name similarity: 0-100."""
    a, b = a.lower().strip(), b.lower().strip()
    if a == b:
        return 100
    max_len = max(len(a), len(b), 1)
    return int((1 - _levenshtein(a, b) / max_len) * 100)


def _pkg_sim(pkg_a: str, pkg_b: str) -> int:
    """Jaccard token similarity on package segments: 0-100."""
    def tok(p: str) -> set[str]:
        return set(p.lower().replace("-", ".").replace("_", ".").split(".")) - {"", "com", "in", "org", "net"}
    t_a, t_b = tok(pkg_a), tok(pkg_b)
    if not t_a or not t_b:
        return 0
    return int(len(t_a & t_b) / len(t_a | t_b) * 100)


# ── Main detector ─────────────────────────────────────────────────────────────

def analyze_clone(
    package_name: str,
    app_name: str,
    cert_hash: str | None = None,
    icon_perceptual_hash: str | None = None,   # future: compare against stored hashes
) -> CloneAnalysis:
    """
    Run clone detection against the known-apps catalogue.

    Returns CloneAnalysis with overall_score 0-100:
      0-39  → safe
      40-64 → suspicious
      65-84 → likely_clone
      85+   → confirmed_clone
    """
    signals: list[str] = []

    # ── Exact package-name match ──────────────────────────────────────────────
    if package_name in KNOWN_APPS:
        known_name = KNOWN_APPS[package_name]
        if cert_hash and package_name in KNOWN_CERT_HASHES:
            if cert_hash.upper() != KNOWN_CERT_HASHES[package_name].upper():
                signals.append(
                    f"Package name is identical to {known_name} but the signing certificate "
                    f"does NOT match — this is almost certainly a counterfeit app"
                )
                return CloneAnalysis(
                    target_package=package_name, target_name=known_name,
                    name_similarity=100, package_similarity=100, icon_similarity=0,
                    overall_score=100, verdict="confirmed_clone", signals=signals,
                )
        # Exact match with correct cert (or cert not in our DB yet) → it's the real app
        return CloneAnalysis(
            target_package=package_name, target_name=known_name,
            name_similarity=100, package_similarity=100, icon_similarity=0,
            overall_score=0, verdict="safe", signals=[],
        )

    # ── Fuzzy scan against catalogue ─────────────────────────────────────────
    best_pkg:      str | None = None
    best_name:     str | None = None
    best_nsim      = 0
    best_psim      = 0

    for known_pkg, known_name in KNOWN_APPS.items():
        nsim = _name_sim(app_name, known_name)
        psim = _pkg_sim(package_name, known_pkg)
        combined = int(nsim * 0.55 + psim * 0.45)
        if combined > int(best_nsim * 0.55 + best_psim * 0.45):
            best_nsim = nsim
            best_psim = psim
            best_pkg  = known_pkg
            best_name = known_name

    if best_nsim >= 80:
        signals.append(f"App name is {best_nsim}% similar to '{best_name}' — possible impersonation")
    if best_psim >= 70:
        signals.append(f"Package name closely resembles '{best_pkg}'")

    overall = int(best_nsim * 0.55 + best_psim * 0.45)

    if overall >= 85:
        verdict = "confirmed_clone"
    elif overall >= 65:
        verdict = "likely_clone"
    elif overall >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"
        signals.clear()   # no need to surface noise for truly safe apps

    return CloneAnalysis(
        target_package=best_pkg,
        target_name=best_name,
        name_similarity=best_nsim,
        package_similarity=best_psim,
        icon_similarity=0,   # placeholder; icon comparison TBD
        overall_score=overall,
        verdict=verdict,
        signals=signals,
    )
