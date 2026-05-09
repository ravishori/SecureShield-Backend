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

# Known malicious package name patterns (includes spyware patterns)
MALICIOUS_PATTERNS = [
    r".*spyware.*",
    r".*keylog.*",
    r".*trojan.*",
    r".*malware.*",
    r".*rat\d*\.",
    r".*hack.*tool.*",
    r".*spy\..*",
    r".*stalker.*",
    r".*monitor.*child.*",
    r".*track.*phone.*",
    r".*hidden.*camera.*",
    r".*stealth.*",
    r".*sms.*interceptor.*",
    r".*call.*recorder.*hidden.*",
]

# Known spyware package signatures
SPYWARE_PACKAGES = [
    "com.hoverwatch",
    "com.mspy",
    "com.flexispy",
    "com.spyzie",
    "com.highster",
    "com.spybubble",
    "com.ikeymonitor",
    "com.familytime",
    "com.umobix",
    "com.thetruthspy",
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

# Fake job offer keywords
FAKE_JOB_KEYWORDS = [
    "work from home earn", "guaranteed income", "no experience required earn",
    "daily payment", "weekly salary guaranteed", "upfront registration fee",
    "pay to apply", "training fee required", "part time earn lakhs",
    "data entry earn per day", "typing job earn", "earn from mobile",
    "whatsapp job", "telegram earning", "youtube subscriber job",
    "like and subscribe earn", "investment required job",
]

# Scam message patterns
SCAM_MESSAGE_PATTERNS = [
    r"congratulations.*won.*prize",
    r"your.*account.*blocked.*click",
    r"urgent.*kyc.*update.*link",
    r"otp.*share.*immediately",
    r"bank.*suspended.*verify.*now",
    r"free.*recharge.*click.*link",
    r"emi.*due.*pay.*now.*link",
    r"income.*tax.*notice.*call",
    r"reward.*points.*expire.*redeem",
    r"suspicious.*activity.*account.*verify",
    r"aadhar.*link.*bank.*required",
    r"pan.*kyc.*expired.*update",
    r"loan.*approved.*click.*here",
    r"electricity.*cut.*pay.*immediately",
]

# Cyberbullying indicator patterns
BULLYING_PATTERNS = [
    r"\byou.*stupid\b", r"\byou.*idiot\b", r"\bkill.*yourself\b",
    r"\bnobody.*likes.*you\b", r"\byou.*ugly\b", r"\byou.*loser\b",
    r"\bgo.*die\b", r"\bi.*hate.*you\b", r"\byou.*worthless\b",
    r"\bstupid.*kid\b", r"\bbig.*fat\b", r"\byou.*fat\b",
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

    # Check known spyware packages
    if package_name.lower() in SPYWARE_PACKAGES:
        is_malicious = True
        threat_tags.append("known_spyware")
        risk_score += 90

    # Check malicious package patterns
    if not is_malicious:
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
    has_device_admin = any("DEVICE_ADMIN" in p for p in permissions)
    has_install = any("INSTALL_PACKAGES" in p for p in permissions)

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

    if has_device_admin and has_sms:
        threat_tags.append("admin_sms_combo")
        risk_score += 25

    if has_install and has_accessibility:
        threat_tags.append("auto_install_risk")
        risk_score += 20

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


def get_removal_reason(risk_level: str, threat_tags: List[str], is_malicious: bool) -> str | None:
    """Returns a human-readable removal recommendation."""
    if is_malicious or "known_spyware" in threat_tags:
        return "This app is identified as spyware or malware. Uninstall immediately and run a device scan."
    if risk_level == "critical":
        return "Critically risky permissions detected. Strongly consider uninstalling this app."
    if "data_harvesting" in threat_tags:
        return "This app harvests SMS, call logs, and contacts together — a common data theft pattern."
    if "admin_sms_combo" in threat_tags:
        return "Device admin + SMS access is an extreme risk. Remove device admin rights and uninstall."
    if "accessibility_abuse_risk" in threat_tags:
        return "Accessibility service abuse can allow hidden screen reading. Review if this app needs this permission."
    if risk_level == "high":
        return "High-risk permissions detected. Only keep this app if you fully trust it."
    return None


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


def analyze_message_content(text: str) -> Tuple[float, str, List[str]]:
    """
    Analyzes SMS/message text for scam/phishing content.
    Returns (risk_score, threat_category, detected_patterns)
    """
    text_lower = text.lower()
    risk_score = 0.0
    detected_patterns = []
    threat_category = "safe"

    # Check scam message patterns
    for pattern in SCAM_MESSAGE_PATTERNS:
        if re.search(pattern, text_lower):
            risk_score += 25
            detected_patterns.append(pattern)

    # Check for fake job keywords
    for keyword in FAKE_JOB_KEYWORDS:
        if keyword in text_lower:
            risk_score += 20
            if "fake_job" not in detected_patterns:
                detected_patterns.append("fake_job_offer")

    # Check for suspicious links in message
    urls_in_text = re.findall(r'https?://\S+', text)
    for url in urls_in_text:
        _, is_malicious, url_score, _ = analyze_url(url)
        if is_malicious or url_score > 40:
            risk_score += 30
            detected_patterns.append("malicious_link_in_message")
            break

    # Urgency keywords
    urgency_words = ["urgent", "immediately", "now", "expire", "suspended", "blocked", "action required"]
    urgency_count = sum(1 for w in urgency_words if w in text_lower)
    if urgency_count >= 2:
        risk_score += urgency_count * 5
        detected_patterns.append("high_urgency_language")

    # Financial bait
    financial_bait = ["won", "prize", "reward", "cashback", "refund", "lottery", "lucky draw"]
    if any(w in text_lower for w in financial_bait):
        risk_score += 15
        detected_patterns.append("financial_bait")

    risk_score = min(risk_score, 100.0)

    if risk_score >= 70:
        threat_category = "high_risk_scam"
    elif risk_score >= 40:
        threat_category = "suspicious_message"
    elif risk_score >= 20:
        threat_category = "potentially_suspicious"
    else:
        threat_category = "safe"

    return risk_score, threat_category, detected_patterns


def analyze_job_offer(text: str) -> Tuple[float, bool, List[str]]:
    """
    Analyzes if a job offer text is fraudulent.
    Returns (risk_score, is_fake, red_flags)
    """
    text_lower = text.lower()
    risk_score = 0.0
    red_flags = []

    # Direct fake job indicators
    for keyword in FAKE_JOB_KEYWORDS:
        if keyword in text_lower:
            risk_score += 20
            red_flags.append(f"Suspicious phrase: '{keyword}'")

    # Fee-based red flags
    if any(w in text_lower for w in ["registration fee", "training fee", "deposit", "pay first", "advance payment"]):
        risk_score += 35
        red_flags.append("Legitimate jobs never ask for payment upfront")

    # Unrealistic income claims
    income_pattern = re.search(r"earn.*?(\d+[,\d]*)\s*(rs|rupees|₹|per day|daily)", text_lower)
    if income_pattern:
        risk_score += 20
        red_flags.append("Unrealistic income claim detected")

    # Contact via WhatsApp/Telegram (not professional)
    if any(w in text_lower for w in ["whatsapp", "telegram", "signal"]) and "apply" in text_lower:
        risk_score += 15
        red_flags.append("Legitimate companies use official email, not WhatsApp/Telegram for hiring")

    # No company name or vague employer
    if not any(w in text_lower for w in ["company", "organization", "pvt ltd", "limited", "inc", "llp"]):
        risk_score += 10
        red_flags.append("No company name mentioned")

    # Urgency in job posting
    if any(w in text_lower for w in ["urgent hiring", "immediate joining", "today only", "limited seats"]):
        risk_score += 15
        red_flags.append("Artificial urgency — common fake job tactic")

    risk_score = min(risk_score, 100.0)
    is_fake = risk_score >= 50

    return risk_score, is_fake, red_flags


def detect_cyberbullying(text: str) -> Tuple[float, bool, List[str]]:
    """
    Detects cyberbullying in message text.
    Returns (confidence_score, is_bullying, detected_indicators)
    """
    text_lower = text.lower()
    score = 0.0
    indicators = []

    for pattern in BULLYING_PATTERNS:
        if re.search(pattern, text_lower):
            score += 30
            indicators.append("Harmful language detected")

    # Threats
    if any(w in text_lower for w in ["i will hurt you", "i know where you live", "you'll regret", "watch your back"]):
        score += 40
        indicators.append("Threat detected")

    # Exclusion/isolation language
    if any(w in text_lower for w in ["nobody wants you", "everyone hates you", "you have no friends"]):
        score += 35
        indicators.append("Social exclusion language detected")

    # Repeated targeting
    if text_lower.count("you") > 5:
        score += 10
        indicators.append("Repeated targeting of individual")

    score = min(score, 100.0)
    is_bullying = score >= 40

    return score, is_bullying, indicators
