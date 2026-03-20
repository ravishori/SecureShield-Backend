from typing import List, Tuple
import re


# High-risk permissions and their scores
PERMISSION_RISK_SCORES = {
    "android.permission.READ_CALL_LOG": 30,
    "android.permission.WRITE_CALL_LOG": 30,
    "android.permission.READ_SMS": 25,
    "android.permission.RECEIVE_SMS": 25,
    "android.permission.SEND_SMS": 25,
    "android.permission.CAMERA": 20,
    "android.permission.RECORD_AUDIO": 20,
    "android.permission.ACCESS_FINE_LOCATION": 15,
    "android.permission.ACCESS_COARSE_LOCATION": 10,
    "android.permission.READ_CONTACTS": 15,
    "android.permission.WRITE_CONTACTS": 15,
    "android.permission.GET_ACCOUNTS": 15,
    "android.permission.USE_BIOMETRIC": 10,
    "android.permission.USE_FINGERPRINT": 10,
    "android.permission.REQUEST_INSTALL_PACKAGES": 20,
    "android.permission.WRITE_EXTERNAL_STORAGE": 10,
    "android.permission.READ_EXTERNAL_STORAGE": 10,
    "android.permission.BLUETOOTH": 5,
    "android.permission.BLUETOOTH_ADMIN": 10,
    "android.permission.CHANGE_WIFI_STATE": 10,
    "android.permission.INTERNET": 5,
    "android.permission.SYSTEM_ALERT_WINDOW": 20,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 25,
    "android.permission.BIND_DEVICE_ADMIN": 30,
    "android.permission.PROCESS_OUTGOING_CALLS": 20,
    "android.permission.READ_PHONE_STATE": 15,
}

# Known malicious package name patterns
MALICIOUS_PATTERNS = [
    r".*spyware.*",
    r".*keylog.*",
    r".*trojan.*",
    r".*malware.*",
    r".*rat\d*\.",
    r".*hack.*tool.*",
]

# Phishing domain patterns
PHISHING_PATTERNS = [
    r".*paypa1\..*",
    r".*g00gle\..*",
    r".*amaz0n\..*",
    r".*facebok\..*",
    r".*netf1ix\..*",
    r".*app1e\..*",
    r".*secure-.*\.xyz",
    r".*login-.*\.tk",
    r".*verify-.*\.ml",
    r".*update-.*\.ga",
    r".*bit\.ly.*",
    r".*tinyurl\..*",
]

SCAM_DOMAINS = [
    "fakebank.com",
    "prizewinner.tk",
    "lotterywin.ml",
    "kycupdate.xyz",
    "aadhaarupdate.net",
    "sbicard-verify.com",
    "hdfc-reward.in",
    "icici-kyc.com",
]


def analyze_app_risk(package_name: str, permissions: List[str], is_system_app: bool) -> Tuple[float, str, bool, List[str]]:
    """
    Returns (risk_score, risk_level, is_malicious, threat_tags)
    """
    risk_score = 0.0
    threat_tags = []
    is_malicious = False

    if is_system_app:
        return 0.0, "safe", False, []

    # Check malicious package patterns
    for pattern in MALICIOUS_PATTERNS:
        if re.match(pattern, package_name.lower()):
            is_malicious = True
            threat_tags.append("known_malware_pattern")
            risk_score += 80
            break

    # Score based on permissions
    for perm in permissions:
        score = PERMISSION_RISK_SCORES.get(perm, 0)
        risk_score += score

    # Check for dangerous permission combos
    has_sms = any("SMS" in p for p in permissions)
    has_call_log = any("CALL_LOG" in p for p in permissions)
    has_contacts = any("CONTACTS" in p for p in permissions)
    has_camera = any("CAMERA" in p or "RECORD_AUDIO" in p for p in permissions)
    has_location = any("LOCATION" in p for p in permissions)
    has_accessibility = any("ACCESSIBILITY" in p for p in permissions)

    if has_sms and has_call_log and has_contacts:
        threat_tags.append("data_harvesting")
        risk_score += 20

    if has_sms and has_location:
        threat_tags.append("surveillance_risk")
        risk_score += 10

    if has_accessibility:
        threat_tags.append("accessibility_abuse_risk")
        risk_score += 15

    if has_camera and has_sms:
        threat_tags.append("potential_spyware")
        risk_score += 10

    # Cap at 100
    risk_score = min(risk_score, 100.0)

    # Determine risk level
    if risk_score >= 75:
        risk_level = "critical"
    elif risk_score >= 55:
        risk_level = "high"
    elif risk_score >= 35:
        risk_level = "medium"
    elif risk_score >= 15:
        risk_level = "low"
    else:
        risk_level = "safe"

    if not threat_tags and risk_score >= 15:
        threat_tags.append("elevated_permissions")

    return risk_score, risk_level, is_malicious, threat_tags


def analyze_url(url: str) -> Tuple[bool, bool, float, str]:
    """
    Returns (is_phishing, is_malicious, risk_score, threat_category)
    """
    url_lower = url.lower()
    risk_score = 0.0
    is_phishing = False
    is_malicious = False
    threat_category = None

    # Check against known scam domains
    for domain in SCAM_DOMAINS:
        if domain in url_lower:
            is_malicious = True
            risk_score = 90.0
            threat_category = "known_scam_domain"
            return is_phishing, is_malicious, risk_score, threat_category

    # Check phishing patterns
    for pattern in PHISHING_PATTERNS:
        if re.match(pattern, url_lower):
            is_phishing = True
            risk_score += 70
            threat_category = "phishing"
            break

    # Check for suspicious URL indicators
    if url_lower.startswith("http://"):
        risk_score += 15
        if not threat_category:
            threat_category = "insecure_http"

    if len(url) > 200:
        risk_score += 10

    suspicious_keywords = ["verify", "login", "secure", "update", "kyc", "otp", "bank", "reward", "prize", "winner"]
    for kw in suspicious_keywords:
        if kw in url_lower:
            risk_score += 5

    # Check for IP-based URLs (suspicious)
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
        risk_score += 30
        threat_category = "ip_based_url"
        is_suspicious = True

    # Multiple subdomains
    try:
        domain_part = url_lower.split("//")[-1].split("/")[0]
        subdomain_count = domain_part.count(".")
        if subdomain_count > 3:
            risk_score += 15
    except Exception:
        pass

    risk_score = min(risk_score, 100.0)

    if risk_score >= 60:
        is_malicious = True
    elif risk_score >= 40:
        is_phishing = True

    if not threat_category and risk_score > 0:
        threat_category = "suspicious_url"

    return is_phishing, is_malicious, risk_score, threat_category


def analyze_wifi(ssid: str | None, encryption_type: str | None, is_open: bool) -> Tuple[bool, str, list]:
    """
    Returns (is_suspicious, risk_level, risk_reasons)
    """
    risk_reasons = []
    risk_level = "safe"
    is_suspicious = False

    if is_open or not encryption_type or encryption_type.upper() in ["NONE", "OPEN", ""]:
        is_suspicious = True
        risk_level = "high"
        risk_reasons.append("Open network — no encryption")

    elif encryption_type.upper() in ["WEP", "WEP_OPEN", "WEP_SHARED"]:
        is_suspicious = True
        risk_level = "medium"
        risk_reasons.append("WEP encryption is outdated and easily cracked")

    elif encryption_type.upper() in ["WPA", "TKIP"]:
        risk_level = "low"
        risk_reasons.append("WPA/TKIP has known vulnerabilities")

    # Check for suspicious SSID patterns
    if ssid:
        ssid_lower = ssid.lower()
        suspicious_ssids = ["free wifi", "public wifi", "airport wifi", "hotel lobby", "starbucks"]
        for s in suspicious_ssids:
            if s in ssid_lower:
                if not is_suspicious:
                    risk_reasons.append(f"Common public hotspot name: {ssid}")
                    risk_level = "medium" if risk_level == "safe" else risk_level

        if "bank" in ssid_lower or "atm" in ssid_lower:
            is_suspicious = True
            risk_reasons.append("Suspicious SSID mimicking bank/ATM network")
            risk_level = "high"

    return is_suspicious, risk_level, risk_reasons


def analyze_scam_call(caller_number: str, duration_seconds: int, audio_features: dict | None) -> Tuple[float, str]:
    """
    Returns (risk_score, detection_reason)
    """
    risk_score = 0.0
    reasons = []

    # Short calls with unknown numbers
    if duration_seconds < 30:
        risk_score += 10
        reasons.append("Very short call duration")

    # Check for common scam number patterns
    if caller_number.startswith("+0") or caller_number.startswith("00"):
        risk_score += 20
        reasons.append("Suspicious international number format")

    if len(caller_number) > 15:
        risk_score += 10
        reasons.append("Unusually long phone number")

    # Audio features analysis
    if audio_features:
        if audio_features.get("is_robocall", False):
            risk_score += 50
            reasons.append("Detected robocall pattern")
        if audio_features.get("background_noise_level", 0) > 0.8:
            risk_score += 15
            reasons.append("High background noise — possible call center")
        if audio_features.get("speech_rate", 1.0) > 2.0:
            risk_score += 10
            reasons.append("Unusually fast speech rate")

    risk_score = min(risk_score, 100.0)
    detection_reason = "; ".join(reasons) if reasons else "No suspicious patterns detected"

    return risk_score, detection_reason
