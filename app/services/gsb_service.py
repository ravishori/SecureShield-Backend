import os
import httpx
from typing import Optional, Dict, Any, List

GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

# Human-readable labels for GSB threat types
THREAT_LABELS: Dict[str, str] = {
    "MALWARE": "Malware",
    "SOCIAL_ENGINEERING": "Phishing / Social Engineering",
    "UNWANTED_SOFTWARE": "Unwanted Software",
    "POTENTIALLY_HARMFUL_APPLICATION": "Potentially Harmful App",
}


async def check_url_gsb(url: str) -> Optional[Dict[str, Any]]:
    """
    Calls Google Safe Browsing API v4 to check a URL against known threat databases.

    Returns:
        dict with keys: safe (bool), threats (list), provider (str)
        None  — if API key not configured or API is unavailable (caller should fall back to internal rules)
    """
    if not GSB_API_KEY:
        return None

    payload = {
        "client": {
            "clientId": "secureshield-ai",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{GSB_API_URL}?key={GSB_API_KEY}",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

            matches: List[Dict] = data.get("matches", [])
            if matches:
                threats = [
                    {
                        "threat_type": m.get("threatType"),
                        "threat_label": THREAT_LABELS.get(m.get("threatType", ""), m.get("threatType", "")),
                        "platform_type": m.get("platformType"),
                        "threat_entry_type": m.get("threatEntryType"),
                        "url": m.get("threat", {}).get("url"),
                    }
                    for m in matches
                ]
                return {
                    "safe": False,
                    "threats": threats,
                    "provider": "google_safe_browsing",
                }
            else:
                return {
                    "safe": True,
                    "threats": [],
                    "provider": "google_safe_browsing",
                }
    except httpx.HTTPStatusError:
        return None
    except httpx.RequestError:
        return None
    except Exception:
        return None
