"""Email generation utilities for fraud complaints and security alerts."""
from typing import List, Optional
from datetime import datetime


def generate_daily_report_email(
    user_name: str,
    threats_detected: int,
    apps_scanned: int,
    links_scanned: int,
    overall_risk_score: float,
    recommendations: List[str],
) -> dict:
    """Generate a daily security report email."""
    date_str = datetime.utcnow().strftime("%B %d, %Y")
    risk_label = "LOW" if overall_risk_score < 30 else "MEDIUM" if overall_risk_score < 60 else "HIGH"

    body = f"""Dear {user_name},

Your Daily SecureShield Security Report — {date_str}

SECURITY SUMMARY
================
Overall Risk Level: {risk_label} ({overall_risk_score:.1f}/100)
Threats Detected: {threats_detected}
Apps Scanned: {apps_scanned}
Links Scanned: {links_scanned}

RECOMMENDATIONS
===============
"""
    for i, rec in enumerate(recommendations, 1):
        body += f"{i}. {rec}\n"

    body += """
Stay safe online. SecureShield AI is monitoring your device 24/7.

— SecureShield AI Team
"""

    return {
        "subject": f"SecureShield Daily Report — {date_str} — Risk: {risk_label}",
        "body": body,
    }


def generate_panic_alert_email(
    user_name: str,
    phone: str,
    latitude: Optional[float],
    longitude: Optional[float],
    message: str,
) -> dict:
    """Generate emergency panic alert email for family members."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    location_str = f"https://maps.google.com/?q={latitude},{longitude}" if latitude and longitude else "Location not available"

    body = f"""URGENT — PANIC ALERT

{user_name} has triggered an emergency panic button at {timestamp}.

Phone: {phone}
Location: {location_str}
Message: {message}

Please contact them immediately or alert emergency services.

— SecureShield AI Emergency System"""

    return {
        "subject": f"URGENT: Panic Alert from {user_name}",
        "body": body,
    }
