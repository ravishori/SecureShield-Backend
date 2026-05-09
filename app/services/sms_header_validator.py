"""
SMS Sender Header Validator
Validates Indian SMS sender IDs against the TRAI registry.

Format: XY-HEADER
  X = TSP code (Telecom Service Provider / Originating Access Provider)
  Y = LSA code (License Service Area)
  HEADER = 6-char alphanum assigned to the Principal Entity (business/govt)

Source: TCCCPR 2018 regulations.
"""
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.sms_sender_registry import SmsSenderRegistry

# ── TSP codes (from TRAI PDF: Detail_Header_Prefixes_16062020_0.pdf) ──────────
TSP_CODES: Dict[str, str] = {
    "D": "Aircel Ltd / Dishnet Wireless Ltd",
    "A": "Bharti Airtel Ltd / Bharti Hexacom Ltd",
    "B": "Bharat Sanchar Nigam Ltd (BSNL)",
    "Q": "Quadrant Televentures Limited",
    "M": "Mahanagar Telephone Nigam Ltd (MTNL)",
    "R": "Reliance Communications Ltd",
    "J": "Reliance Jio Infocomm Ltd",
    "E": "Reliance Telecom Ltd",
    "T": "Tata Teleservices Ltd / Tata Teleservices (Maharashtra) Ltd",
    "V": "Vodafone Idea Ltd",
    "C": "V-CON Mobile & Infra Private Ltd",
}

# ── LSA codes (from TRAI PDF: Detail_Header_Prefixes_16062020_0.pdf) ──────────
LSA_CODES: Dict[str, str] = {
    "A": "Andhra Pradesh",
    "S": "Assam",
    "B": "Bihar",
    "D": "Delhi",
    "G": "Gujarat",
    "H": "Haryana",
    "I": "Himachal Pradesh",
    "J": "Jammu & Kashmir",
    "X": "Karnataka",
    "L": "Kerala",
    "K": "Kolkata",
    "Y": "Madhya Pradesh",
    "Z": "Maharashtra",
    "M": "Mumbai",
    "N": "North East",
    "O": "Orissa",
    "P": "Punjab",
    "R": "Rajasthan",
    "T": "Tamil Nadu (including Chennai)",
    "E": "UP-East",
    "W": "UP-West",
    "V": "West Bengal",
}


def parse_sender_id(sender: str) -> Dict[str, Optional[str]]:
    """
    Parse an Indian SMS sender ID into its components.

    Examples:
        'VK-SBIBNK' → {tsp_code: 'V', lsa_code: 'K', header: 'SBIBNK'}
        'JD-AIRTEL' → {tsp_code: 'J', lsa_code: 'D', header: 'AIRTEL'}
        'SBIBNK'   → {tsp_code: None, lsa_code: None, header: 'SBIBNK'}
        '+919876543210' → {tsp_code: None, lsa_code: None, header: '+919876543210'}
    """
    s = sender.strip().upper()
    if "-" in s:
        prefix, header = s.split("-", 1)
        tsp_code = prefix[0] if len(prefix) >= 1 else None
        lsa_code = prefix[1] if len(prefix) >= 2 else None
    else:
        header = s
        tsp_code = None
        lsa_code = None

    return {
        "tsp_code": tsp_code,
        "lsa_code": lsa_code,
        "header": header,
    }


def is_phone_number(sender: str) -> bool:
    """Returns True if the sender looks like a phone number rather than an alpha header."""
    cleaned = sender.strip().replace("+", "").replace(" ", "").replace("-", "")
    return cleaned.isdigit() and len(cleaned) >= 7


async def validate_sender(sender: str, db: AsyncSession) -> Dict[str, Any]:
    """
    Validate an SMS sender ID against the TRAI registry.

    Returns a dict with:
        is_registered   — found in TRAI database
        verdict         — REGISTERED | UNREGISTERED | PHONE_NUMBER | UNKNOWN
        principal_entity_name — company name if found
        tsp_name        — operator name (Vodafone Idea, Airtel, …)
        lsa_name        — service area (Delhi, Mumbai, …)
        verdict_detail  — human-readable explanation
    """
    if not sender or not sender.strip():
        return {
            "is_registered": None,
            "verdict": "UNKNOWN",
            "verdict_detail": "No sender ID provided.",
            "header": None,
            "sender_id": None,
            "principal_entity_name": None,
            "all_entity_names": [],
            "tsp_code": None,
            "tsp_name": None,
            "lsa_code": None,
            "lsa_name": None,
        }

    raw = sender.strip()

    # Phone numbers are not alpha headers — don't look them up
    if is_phone_number(raw):
        return {
            "is_registered": False,
            "verdict": "PHONE_NUMBER",
            "verdict_detail": (
                "This message was sent from a personal phone number, not a registered business sender ID. "
                "Legitimate banks, government bodies, and companies always use registered alpha sender IDs."
            ),
            "header": raw,
            "sender_id": raw,
            "principal_entity_name": None,
            "all_entity_names": [],
            "tsp_code": None,
            "tsp_name": None,
            "lsa_code": None,
            "lsa_name": None,
        }

    parsed = parse_sender_id(raw)
    header = parsed["header"]
    tsp_code = parsed["tsp_code"]
    lsa_code = parsed["lsa_code"]
    tsp_name = TSP_CODES.get(tsp_code) if tsp_code else None
    lsa_name = LSA_CODES.get(lsa_code) if lsa_code else None

    # DB lookup — case-insensitive
    result = await db.execute(
        select(SmsSenderRegistry)
        .where(func.upper(SmsSenderRegistry.header) == header.upper())
        .limit(10)
    )
    matches = result.scalars().all()

    if matches:
        entity_names: List[str] = list({m.principal_entity_name for m in matches})
        primary_name = entity_names[0]
        return {
            "is_registered": True,
            "verdict": "REGISTERED",
            "verdict_detail": (
                f"✅ Officially registered with TRAI for {primary_name}."
                + (f" Sent via {tsp_name}" if tsp_name else "")
                + (f" ({lsa_name} circle)" if lsa_name else "")
                + "."
            ),
            "header": header,
            "sender_id": raw.upper(),
            "principal_entity_name": primary_name,
            "all_entity_names": entity_names,
            "tsp_code": tsp_code,
            "tsp_name": tsp_name,
            "lsa_code": lsa_code,
            "lsa_name": lsa_name,
        }
    else:
        return {
            "is_registered": False,
            "verdict": "UNREGISTERED",
            "verdict_detail": (
                f"⚠️ Sender '{raw.upper()}' is NOT found in the TRAI registry. "
                "This could indicate a spoofed or fraudulent sender ID. "
                "Do not follow any instructions or links in this message."
            ),
            "header": header,
            "sender_id": raw.upper(),
            "principal_entity_name": None,
            "all_entity_names": [],
            "tsp_code": tsp_code,
            "tsp_name": tsp_name,
            "lsa_code": lsa_code,
            "lsa_name": lsa_name,
        }
