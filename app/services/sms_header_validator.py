"""
SMS Sender Header Validator
Validates Indian SMS sender IDs against the TRAI registry.

Format: XY-HEADER
  X = TSP code (Telecom Service Provider / Originating Access Provider)
  Y = LSA code (License Service Area)
  HEADER = 6-char alphanum assigned to the Principal Entity (business/govt)

Source: TCCCPR 2018 regulations.
"""

import asyncio
import logging
import re
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.sms_sender_registry import SmsSenderRegistry

logger = logging.getLogger(__name__)

# Seconds a registry lookup may take before the sender is reported as "not checked" (see validate_sender_safe).
REGISTRY_LOOKUP_TIMEOUT_SECONDS = 3.0

# Category suffix that the sender ID shown on the phone may carry after the header: ``VM-SBIBNK-S`` is the registered header
# ``SBIBNK`` sent as a Service message. Only the letters below are recognised, because they are the only ones the project has
# evidence for (the Stage 1.6C/1.6D-1 request names -S, -T and -P). The registry stores the BASE header, never a suffixed one.
# ``-G`` (government) is deliberately NOT recognised until it is verified; a ``-G`` sender is looked up unchanged.
SUPPORTED_SENDER_SUFFIXES = frozenset({"S", "T", "P"})
# ASCII only and exactly two prefix letters: a look-alike (Cyrillic) letter anywhere in prefix or suffix does not match.
_SUFFIXED_SENDER = re.compile(r"([A-Za-z]{2})-([A-Za-z0-9]+)-([STPstp])", re.ASCII)

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
    original = sender.strip()
    s = original.upper()
    suffixed = _SUFFIXED_SENDER.fullmatch(original)
    if suffixed:
        # XY-HEADER-S/T/P: the registry holds HEADER, so that is what is looked up; the suffix is reported, not discarded.
        prefix = suffixed.group(1).upper()
        return {
            "tsp_code": prefix[0],
            "lsa_code": prefix[1],
            "header": suffixed.group(2).upper(),
            "sender_suffix": suffixed.group(3).upper(),
        }
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
        "sender_suffix": None,
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
            "sender_suffix": None,
            "lookup_status": "not_applicable",
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
            "sender_suffix": None,
            "lookup_status": "not_applicable",
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
                + (
                    f" (category suffix -{parsed['sender_suffix']})"
                    if parsed["sender_suffix"]
                    else ""
                )
                + "."
            ),
            "header": header,
            "sender_id": raw.upper(),
            "principal_entity_name": primary_name,
            "all_entity_names": entity_names,
            "sender_suffix": parsed["sender_suffix"],
            "lookup_status": "ok",
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
            "sender_suffix": parsed["sender_suffix"],
            "lookup_status": "ok",
            "tsp_code": tsp_code,
            "tsp_name": tsp_name,
            "lsa_code": lsa_code,
            "lsa_name": lsa_name,
        }


def registry_unavailable_result(sender: Optional[str]) -> Dict[str, Any]:
    """Sender result when the registry could not be queried. It is UNKNOWN, never UNREGISTERED: not checking is not a finding."""
    raw = (sender or "").strip()
    return {
        "is_registered": None,
        "verdict": "UNKNOWN",
        "verdict_detail": (
            "The sender registry could not be checked right now, so this sender was not verified. "
            "This says nothing about whether the sender is genuine."
        ),
        "header": None,
        "sender_id": raw.upper() or None,
        "principal_entity_name": None,
        "all_entity_names": [],
        "tsp_code": None,
        "tsp_name": None,
        "lsa_code": None,
        "lsa_name": None,
        "sender_suffix": None,
        "lookup_status": "unavailable",
    }


async def validate_sender_safe(sender: str, db: AsyncSession) -> Dict[str, Any]:
    """``validate_sender`` that survives a registry failure.

    Any exception (database down, missing table, timeout, unexpected error) becomes ``registry_unavailable_result`` and the session
    is rolled back so the caller can keep using it. Only the exception CLASS is logged: no sender, message or connection detail.
    Cancellation (``CancelledError``) is not swallowed.
    """
    try:
        return await asyncio.wait_for(
            validate_sender(sender, db), timeout=REGISTRY_LOOKUP_TIMEOUT_SECONDS
        )
    except Exception as exc:  # noqa: BLE001 - deliberately broad; see docstring
        logger.warning("sender registry lookup unavailable (%s)", type(exc).__name__)
        try:
            await db.rollback()
        except Exception:  # noqa: BLE001
            logger.warning("rollback after registry failure also failed")
        return registry_unavailable_result(sender)
