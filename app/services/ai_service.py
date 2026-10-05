import logging
from typing import AsyncIterator, List, Optional

import anthropic
from app.config import settings

logger = logging.getLogger(__name__)

AI_TIMEOUT_SECONDS = 30.0


def get_client() -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


# Async client for streaming endpoints — keeps the event loop free while
# Claude generates text. Re-uses the same API key as the sync client.
_async_client_singleton: Optional[anthropic.AsyncAnthropic] = None


def get_async_client() -> anthropic.AsyncAnthropic:
    global _async_client_singleton
    if _async_client_singleton is None:
        _async_client_singleton = anthropic.AsyncAnthropic(
            api_key=settings.ANTHROPIC_API_KEY,
            timeout=AI_TIMEOUT_SECONDS,  # never hold a request open for the SDK default (10 min)
            max_retries=1,
        )
    return _async_client_singleton


async def _create_message(**kwargs):
    """Awaitable ``messages.create``. The previous code called the SYNCHRONOUS client inside
    ``async def`` handlers, blocking the whole event loop (every other request) for the full
    duration of each model call."""
    return await get_async_client().messages.create(**kwargs)


# ─── Language support ─────────────────────────────────────────────────────
# Maps ISO 639-1 language code → (English name, native script name).
# Used to instruct Claude to respond in the user's chosen language.
LANGUAGE_NAMES: dict[str, tuple[str, str]] = {
    "en": ("English", "English"),
    "hi": ("Hindi", "हिंदी"),
    "mr": ("Marathi", "मराठी"),
    "bn": ("Bengali", "বাংলা"),
    "ta": ("Tamil", "தமிழ்"),
    "te": ("Telugu", "తెలుగు"),
    "kn": ("Kannada", "ಕನ್ನಡ"),
    "gu": ("Gujarati", "ગુજરાતી"),
    "ml": ("Malayalam", "മലയാളം"),
    "pa": ("Punjabi", "ਪੰਜਾਬੀ"),
    "or": ("Odia", "ଓଡ଼ିଆ"),
    "ur": ("Urdu", "اردو"),
    "as": ("Assamese", "অসমীয়া"),
}


def _brief_language_instruction(language: Optional[str]) -> str:
    """
    Compact (1-2 sentence) language directive for SINGLE-SHOT endpoints
    like FIR drafting and complaint-email generation.

    Why: the full _language_instruction is ~600 tokens. For one-shot
    requests where context is given inline (no multi-turn mirroring risk),
    a short directive is just as effective and saves significant prefill
    latency — typically 1-3 seconds off the time-to-first-token.
    """
    if not language or language == "en":
        return ""
    entry = LANGUAGE_NAMES.get(language)
    if entry is None:
        return ""
    en_name, native_name = entry
    return (
        f"\n\nLanguage: Write the entire response in {en_name} ({native_name} "
        f"script). Keep these in English: technical terms (OTP, UPI, SMS, "
        f"app, URL, KYC, password), brand/proper nouns (bank/app names, IPC, "
        f"BNS, IT Act), section numbers, helpline codes (1930), phone "
        f"numbers, URLs, dates."
    )


def _language_instruction(language: Optional[str]) -> str:
    """
    Returns the system-prompt addendum that tells Claude what language to
    respond in. Empty string for English / unknown so the default behaviour
    (English) is preserved.

    The instruction is intentionally forceful: Claude's default behavior is
    to mirror the user's question language. We must explicitly override this
    because Indian users typically type in English (due to keyboard
    constraints) but want responses in their native script.
    """
    if not language or language == "en":
        return ""
    entry = LANGUAGE_NAMES.get(language)
    if entry is None:
        return ""
    en_name, native_name = entry
    return f"""

╔══════════════════════════════════════════════════════════════════╗
║  ⚠️  CRITICAL LANGUAGE OVERRIDE — READ CAREFULLY                  ║
╚══════════════════════════════════════════════════════════════════╝

The user has explicitly selected **{en_name} ({native_name})** as their
preferred response language in the app settings. This is a FIXED
preference that overrides any other language signal.

🔴 MANDATORY RULES — do not deviate:

1. **ALWAYS reply in {en_name} using the {native_name} script.**
   This applies to EVERY response in this conversation, no exceptions.

2. **Reply in {en_name} EVEN IF the user types in English.**
   Many Indian users type questions in English because typing
   {native_name} on a mobile keyboard is harder, but they explicitly
   want answers in {native_name}. DO NOT mirror their question
   language — respect their stated preference.

3. **All headings, bullets, bold text, lists → {native_name}.**
   Markdown structure (# ## ### - * **) is fine, but the actual
   words inside MUST be in {native_name}.

4. **Keep these in English** (transliteration confuses users):
   - Technical terms: OTP, UPI, KYC, OS, App, URL, SMS, password,
     phishing, malware, ransomware, VPN, browser, link, click, app store,
     2FA, biometric, fingerprint, Wi-Fi, Bluetooth
   - Brand / proper nouns: Gmail, WhatsApp, Google, Paytm, PhonePe,
     HDFC, SBI, ICICI, etc.
   - Numbers, helpline codes (1930, 112, 155260), IPC sections,
     URLs, email addresses

5. **Tone**: Warm, conversational, clear. Imagine explaining to a
   first-time smartphone user (often a senior citizen) who chose
   {en_name} because they're more comfortable reading it.

6. **The ONLY exception** to rule #1: if the user *explicitly* writes
   "please answer in English" or "इंग्लिश में जवाब दें", then switch.
   Otherwise, ALWAYS {en_name}.

If you respond in English when the user has chosen {en_name}, you are
breaking the user's explicit preference. Do not do this.

╔══════════════════════════════════════════════════════════════════╗
║  END OF LANGUAGE OVERRIDE                                        ║
╚══════════════════════════════════════════════════════════════════╝
"""


def _diagnose_ai_error(e: Exception) -> str:
    """User-safe description of an AI failure.

    Deliberately generic: operational details (quota exhausted, bad key, missing key, wrong
    model) are configuration facts for the OPERATOR and must not be shown to end users. They
    are logged server-side by exception type and HTTP status only (never the message text)."""
    msg = str(e).lower()
    if "rate" in msg and "limit" in msg:
        return "the AI service is busy, please try again in a minute"
    if "timeout" in msg or "timed out" in msg:
        return "the AI service timed out, please retry shortly"
    return "the AI service is temporarily unavailable"


def _log_ai_failure(where: str, e: Exception) -> None:
    logger.error(
        "[AI] %s failed: %s (status=%s)",
        where,
        type(e).__name__,
        getattr(e, "status_code", None),
    )


SYSTEM_PROMPT = """You are SecureShield AI Coach — an expert cybersecurity assistant specializing in digital safety for everyday users in India and worldwide. Your role is to:
- Educate users about online scams, phishing, OTP fraud, and cyber threats
- Provide clear, actionable advice in simple language
- Help users understand if apps, links, or calls might be dangerous
- Guide users through reporting cybercrime
- Support senior citizens with easy-to-understand explanations

Always be empathetic, clear, and supportive. Never use excessive jargon. If someone seems to be in danger, immediately advise them to call cybercrime helpline 1930 (India) or local emergency services.

Keep responses concise but thorough. Use bullet points for actionable steps."""


async def chat_with_coach(
    messages: List[dict],
    topic_category: Optional[str] = None,
    language: Optional[str] = "en",
) -> str:
    """Send messages to Claude and get a response.

    Args:
        messages: Conversation history.
        topic_category: Optional category tag for analytics.
        language: ISO 639-1 code (en/hi/mr/bn/ta/te/…). The assistant will
            reply in this language using its native script. Defaults to
            English when None / "en" / unknown.
    """
    try:
        system_prompt = SYSTEM_PROMPT + _language_instruction(language)

        # Inject a per-message reinforcement on the LAST user turn.
        # This is the strongest contextual signal because Claude pays
        # heaviest attention to the most recent user message. The system
        # prompt alone can be overridden by Claude's "mirror the user's
        # question language" default.
        api_messages = _inject_language_hint(messages, language)

        response = await _create_message(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system_prompt,
            messages=api_messages,
        )
        return response.content[0].text
    except Exception as e:
        reason = _diagnose_ai_error(e)
        _log_ai_failure("chat_with_coach", e)
        return _localised_fallback(language, reason)


def _inject_language_hint(
    messages: List[dict],
    language: Optional[str],
) -> List[dict]:
    """
    Add a small invisible-to-DB language reminder to the LAST user message
    before sending to Claude.

    Why this exists: Claude's default behaviour is to respond in whichever
    language the user typed in. Indian users often type in English (keyboard
    constraints) but want answers in their native script. The system prompt
    alone is sometimes ignored — appending a per-message hint right next to
    the user's question forces compliance.

    The hint is added ONLY to the API payload, not to the stored conversation
    history, so the DB stays clean.
    """
    if not language or language == "en" or not messages:
        return messages
    entry = LANGUAGE_NAMES.get(language)
    if entry is None:
        return messages
    en_name, native_name = entry

    # Bilingual hint so Claude understands even if it focused only on
    # one side.
    hint = (
        f"\n\n[System reminder: Respond in {en_name} ({native_name}) "
        f"as I have selected this language in app settings. "
        f"Use {native_name} script for all sentences. Keep technical terms "
        f"like OTP, UPI, password, app, URL in English. Do not reply in "
        f"English even though I typed in English.]"
    )

    # Mutate only the last user message; leave history untouched.
    api_messages = [dict(m) for m in messages]
    for i in range(len(api_messages) - 1, -1, -1):
        if api_messages[i].get("role") == "user":
            api_messages[i]["content"] = api_messages[i]["content"] + hint
            break
    return api_messages


def _localised_fallback(language: Optional[str], reason: str) -> str:
    """Return the AI-unavailable error message in the user's language."""
    msg = {
        "hi": f"AI Coach अभी उपलब्ध नहीं है — {reason}. कृपया थोड़ी देर बाद फिर कोशिश करें।",
        "mr": f"AI Coach सध्या उपलब्ध नाही — {reason}. कृपया थोड्या वेळाने पुन्हा प्रयत्न करा.",
        "bn": f"AI Coach এখন উপলব্ধ নয় — {reason}. দয়া করে কিছুক্ষণ পরে আবার চেষ্টা করুন।",
        "ta": f"AI Coach தற்போது கிடைக்கவில்லை — {reason}. சிறிது நேரம் கழித்து மீண்டும் முயற்சிக்கவும்.",
        "te": f"AI Coach ప్రస్తుతం అందుబాటులో లేదు — {reason}. దయచేసి కొంత సమయం తర్వాత మళ్లీ ప్రయత్నించండి.",
    }
    return msg.get(
        language or "en",
        f"AI Coach is unavailable right now — {reason}. Please try again shortly.",
    )


async def generate_complaint_email(
    incident_type: str,
    description: str,
    evidence_summary: Optional[str],
    suspect_info: Optional[str],
    user_name: str = "Victim",
    bank_name: Optional[str] = None,
    amount: Optional[str] = None,
    incident_date: Optional[str] = None,
    language: Optional[str] = "en",
) -> dict:
    """Generate a formal fraud complaint email. Optionally in [language]."""
    try:
        bank_line = f"Bank/Institution: {bank_name}" if bank_name else ""
        amount_line = f"Amount Lost: ₹{amount}" if amount else ""
        date_line = f"Incident Date: {incident_date}" if incident_date else ""
        extra = "\n".join(filter(None, [bank_line, amount_line, date_line]))

        prompt = f"""Generate a formal cybercrime complaint email for the following:

Incident Type: {incident_type}
Description: {description}
{extra}
Evidence: {evidence_summary or "None provided"}
Suspect Information: {suspect_info or "Unknown"}
Complainant: {user_name}

Generate a professional complaint email with:
1. Subject line
2. Full email body addressed to cybercrime authorities
3. All relevant details formatted properly
4. Request for immediate action
5. Contact details placeholder

Format your response as:
SUBJECT: <subject line>
BODY:
<full email body>
TO: <comma-separated list of recommended recipient emails>"""

        # NOTE: SUBJECT/BODY/TO marker keywords stay English because the
        # router parses them. The actual subject + body text will be in the
        # user's language, instructed via the system prompt.
        system_prompt = (
            "You are a formal-letter drafter for Indian cybercrime complaints. "
            "Always keep the markers 'SUBJECT:', 'BODY:' and 'TO:' in English "
            "(uppercase) so they can be parsed, but write the actual subject "
            "line and body in the user's chosen language."
            + _brief_language_instruction(language)
        )

        # Haiku 4.5 — 3× faster than Sonnet for short formal letters.
        response = await _create_message(
            model="claude-haiku-4-5",
            max_tokens=900,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text
        lines = text.strip().split("\n")

        subject = ""
        body_lines = []
        to_addresses = ["cybercrime@gov.in", "helpdesk@cybercrime.gov.in"]
        in_body = False

        for line in lines:
            if line.startswith("SUBJECT:"):
                subject = line.replace("SUBJECT:", "").strip()
            elif line.startswith("TO:"):
                to_raw = line.replace("TO:", "").strip()
                to_addresses = [a.strip() for a in to_raw.split(",") if a.strip()]
            elif line.startswith("BODY:"):
                in_body = True
            elif in_body:
                body_lines.append(line)

        body_text = "\n".join(body_lines).strip() or text
        return {
            "subject": subject or f"Cybercrime Complaint: {incident_type}",
            "body": body_text,
            "email": body_text,
            "to_addresses": to_addresses,
        }

    except Exception:
        fallback_body = (
            f"Dear Cybercrime Authority,\n\n"
            f"I am writing to report a cybercrime incident.\n\n"
            f"Incident Type: {incident_type}\n"
            f"Description: {description}\n\n"
            f"I request immediate investigation.\n\nThank you,\n{user_name}"
        )
        return {
            "subject": f"Cybercrime Complaint: {incident_type}",
            "body": fallback_body,
            "email": fallback_body,
            "to_addresses": ["cybercrime@gov.in"],
        }


async def explain_app_threat(
    app_name: str, risk_score: float, threat_tags: List[str], permissions: List[str]
) -> str:
    """Generate human-readable explanation of app threats."""
    try:
        prompt = f"""Explain in simple language why the app "{app_name}" is flagged as potentially risky:
Risk Score: {risk_score}/100
Threat Tags: {", ".join(threat_tags)}
Dangerous Permissions: {", ".join(permissions[:10])}

Provide:
1. What the risk means in plain English
2. What data could be at risk
3. Recommended action (keep/monitor/uninstall)
Keep it under 100 words and very clear."""

        response = await _create_message(
            model="claude-sonnet-4-6",
            max_tokens=256,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    except Exception:
        return f"This app has a risk score of {risk_score}/100 due to suspicious permissions. Review permissions carefully and consider uninstalling if you don't trust the app."


FIR_MODEL = "claude-haiku-4-5"
FIR_MAX_TOKENS = 1500


def _build_fir_prompts(
    *,
    incident_type: str,
    description: str,
    incident_date: str,
    incident_location: str,
    suspect_info: Optional[str],
    evidence_summary: Optional[str],
    complainant_name: str,
    complainant_phone: str,
    amount_lost: Optional[str],
    language: Optional[str],
) -> tuple[str, str]:
    """Build (system_prompt, user_prompt) for FIR generation.

    Shared by both the blocking [generate_fir_draft] and streaming
    [stream_fir_draft] helpers so they stay in lock-step on format rules.
    """
    amount_line = (
        f"Financial Loss: ₹{amount_lost}"
        if amount_lost
        else "Financial Loss: None reported"
    )

    user_prompt = f"""Draft a formal Indian FIR for this cybercrime.

Facts:
- Type: {incident_type}
- Date/time: {incident_date}
- Location: {incident_location}
- Description: {description}
- Suspect: {suspect_info or "Unknown"}
- Evidence: {evidence_summary or "None provided"}
- {amount_line}
- Complainant: {complainant_name}, {complainant_phone}

Output sections in order, using "## " markdown for each heading:
## To — addressed to "The Station House Officer, [station name placeholder], {incident_location}"
## Subject — one line
## 1. Complainant Details — name, phone, [Address as on ID]
## 2. Incident Details — date/time/location/loss in one formal paragraph
## 3. Description of the Incident — 2-3 paragraphs of formal chronological prose, no bullets
## 4. Suspect Information — bulleted if known, else "Suspect identity is unknown at this stage."
## 5. Evidence Submitted — bulleted; if none, "Evidence will be provided on request during investigation."
## 6. Applicable Sections of Law — bulleted, naming IT Act 66C/66D and BNS 318/319 as relevant (English verbatim)
## 7. Relief Sought — one short paragraph
## 8. Declaration — short truthfulness statement
## 9. Signature — block with Signature line, Name, Contact, Date [DD/MM/YYYY], Place

Be concise. Keep each section short."""

    system_prompt = (
        "You draft Indian FIRs. Output: ONLY plain markdown with '## ' "
        "headings, '-' bullets, '**bold**' sparingly. NO triple-backtick "
        "code fences. NO underscore/equals dividers. NO decorative emoji "
        "in headings. NO horizontal rules (---). Each section starts with "
        "## on a new line followed by a blank line. Be concise and formal."
        + _brief_language_instruction(language)
    )
    return system_prompt, user_prompt


async def generate_fir_draft(
    incident_type: str,
    description: str,
    incident_date: str,
    incident_location: str,
    suspect_info: Optional[str],
    evidence_summary: Optional[str],
    complainant_name: str,
    complainant_phone: str,
    amount_lost: Optional[str] = None,
    language: Optional[str] = "en",
) -> dict:
    """Generate a formal FIR (First Information Report) draft for cybercrime.

    Blocking variant — returns the full text once Claude finishes. For the
    streaming variant that yields incremental chunks see [stream_fir_draft].
    """
    try:
        system_prompt, user_prompt = _build_fir_prompts(
            incident_type=incident_type,
            description=description,
            incident_date=incident_date,
            incident_location=incident_location,
            suspect_info=suspect_info,
            evidence_summary=evidence_summary,
            complainant_name=complainant_name,
            complainant_phone=complainant_phone,
            amount_lost=amount_lost,
            language=language,
        )

        response = await _create_message(
            model=FIR_MODEL,
            max_tokens=FIR_MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        fir_text = response.content[0].text
        return {
            "fir_draft": fir_text,
            "incident_type": incident_type,
            "complainant_name": complainant_name,
            "generated_at": incident_date,
            "note": "This is a draft. Review with a legal expert before filing at police station.",
        }

    except Exception as e:
        reason = _diagnose_ai_error(e)
        _log_ai_failure("generate_fir_draft", e)
        amount_str = f"\nFinancial Loss: ₹{amount_lost}" if amount_lost else ""
        suspect_str = f"\nSuspect Details: {suspect_info}" if suspect_info else ""
        evidence_str = f"\nEvidence: {evidence_summary}" if evidence_summary else ""
        # Richer fallback so even without AI the user has a usable starting point.
        fallback = (
            f"FIRST INFORMATION REPORT (DRAFT)\n"
            f"{'=' * 50}\n\n"
            f"To,\n"
            f"The Station House Officer,\n"
            f"[Local Police Station Name]\n\n"
            f"Subject: Complaint regarding cybercrime incident — {incident_type}\n\n"
            f"Respected Sir/Madam,\n\n"
            f"I, {complainant_name} (mobile: {complainant_phone}), wish to report the\n"
            f"following cybercrime incident:\n\n"
            f"Date / Time of Incident : {incident_date}\n"
            f"Location of Incident    : {incident_location}\n"
            f"Type of Incident        : {incident_type}"
            f"{amount_str}\n\n"
            f"DESCRIPTION OF INCIDENT:\n"
            f"{description}\n"
            f"{suspect_str}"
            f"{evidence_str}\n\n"
            f"I request the police to register an FIR under the relevant sections\n"
            f"of the Indian Penal Code (IPC) and Information Technology Act, 2000\n"
            f"(e.g., Section 66C — identity theft, Section 66D — cheating by\n"
            f"impersonation using computer resource, Section 420 IPC — cheating),\n"
            f"investigate the matter, and take appropriate action.\n\n"
            f"I declare that the information provided above is true and correct\n"
            f"to the best of my knowledge.\n\n"
            f"Yours faithfully,\n\n"
            f"{complainant_name}\n"
            f"Mobile: {complainant_phone}\n"
            f"Date: {incident_date}\n\n"
            f"Also report online at: https://cybercrime.gov.in\n"
            f"Helpline: 1930"
        )
        return {
            "fir_draft": fallback,
            "incident_type": incident_type,
            "complainant_name": complainant_name,
            "generated_at": incident_date,
            "note": f"{reason}. A complete template was generated locally — please review and add any missing details before submitting.",
        }


async def stream_fir_draft(
    *,
    incident_type: str,
    description: str,
    incident_date: str,
    incident_location: str,
    suspect_info: Optional[str],
    evidence_summary: Optional[str],
    complainant_name: str,
    complainant_phone: str,
    amount_lost: Optional[str] = None,
    language: Optional[str] = "en",
) -> AsyncIterator[dict]:
    """Stream a FIR draft chunk-by-chunk from Claude.

    Yields a sequence of dicts that the SSE endpoint serialises straight to
    the wire:

      • `{"delta": "...text..."}` — incremental text chunks (many of these)
      • `{"done": True, "fir_draft": "...full..."}` — terminal event
      • `{"error": "..."}` — fatal failure (fallback FIR served instead)

    The caller is responsible for translating these into `data: <json>\\n\\n`
    SSE frames; this function purely produces structured events.
    """
    try:
        client = get_async_client()
        system_prompt, user_prompt = _build_fir_prompts(
            incident_type=incident_type,
            description=description,
            incident_date=incident_date,
            incident_location=incident_location,
            suspect_info=suspect_info,
            evidence_summary=evidence_summary,
            complainant_name=complainant_name,
            complainant_phone=complainant_phone,
            amount_lost=amount_lost,
            language=language,
        )

        accumulated: list[str] = []
        async with client.messages.stream(
            model=FIR_MODEL,
            max_tokens=FIR_MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        ) as stream:
            async for chunk in stream.text_stream:
                if not chunk:
                    continue
                accumulated.append(chunk)
                yield {"delta": chunk}

        full_text = "".join(accumulated)
        yield {
            "done": True,
            "fir_draft": full_text,
            "incident_type": incident_type,
            "complainant_name": complainant_name,
            "generated_at": incident_date,
            "note": "This is a draft. Review with a legal expert before "
            "filing at police station.",
        }

    except Exception as e:
        reason = _diagnose_ai_error(e)
        _log_ai_failure("stream_fir_draft", e)
        # Mirror the blocking fallback so the client gets a usable document
        # even when the stream fails before any token arrives.
        amount_str = f"\nFinancial Loss: ₹{amount_lost}" if amount_lost else ""
        suspect_str = f"\nSuspect Details: {suspect_info}" if suspect_info else ""
        evidence_str = f"\nEvidence: {evidence_summary}" if evidence_summary else ""
        fallback = (
            f"FIRST INFORMATION REPORT (DRAFT)\n"
            f"{'=' * 50}\n\n"
            f"To,\nThe Station House Officer,\n[Local Police Station Name]\n\n"
            f"Subject: Complaint regarding cybercrime incident — {incident_type}\n\n"
            f"Respected Sir/Madam,\n\n"
            f"I, {complainant_name} (mobile: {complainant_phone}), wish to report "
            f"the following cybercrime incident:\n\n"
            f"Date / Time of Incident : {incident_date}\n"
            f"Location of Incident    : {incident_location}\n"
            f"Type of Incident        : {incident_type}"
            f"{amount_str}\n\n"
            f"DESCRIPTION OF INCIDENT:\n{description}\n"
            f"{suspect_str}{evidence_str}\n\n"
            f"I request the police to register an FIR under the relevant "
            f"sections of the IT Act, 2000 and BNS, investigate the matter, "
            f"and take appropriate action.\n\n"
            f"I declare that the information provided above is true and "
            f"correct to the best of my knowledge.\n\n"
            f"Yours faithfully,\n\n{complainant_name}\n"
            f"Mobile: {complainant_phone}\nDate: {incident_date}\n\n"
            f"Also report online at: https://cybercrime.gov.in\nHelpline: 1930"
        )
        yield {
            "done": True,
            "fir_draft": fallback,
            "incident_type": incident_type,
            "complainant_name": complainant_name,
            "generated_at": incident_date,
            "note": f"{reason}. A complete template was generated locally — "
            f"please review and add any missing details before "
            f"submitting.",
            "error": reason,
        }


async def analyze_message_safety(message_text: str) -> dict:
    """AI-powered analysis of whether a message is safe or a scam."""
    try:
        prompt = f"""Analyze this message/SMS for scam, phishing, or fraud indicators:

Message: "{message_text}"

Provide a JSON-style analysis with:
1. is_safe: true/false
2. risk_level: safe/low/medium/high/critical
3. scam_type: (fake_job/phishing/otp_fraud/lottery/banking_fraud/none)
4. explanation: brief plain-English explanation (max 80 words)
5. action: what the user should do
6. red_flags: list of specific red flags found (empty list if none)

Respond ONLY in this exact format:
SAFE: yes/no
RISK: safe/low/medium/high/critical
SCAM_TYPE: type
EXPLANATION: explanation here
ACTION: action here
RED_FLAGS: flag1 | flag2 | flag3"""

        response = await _create_message(
            model="claude-sonnet-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text
        lines = text.strip().split("\n")

        result = {
            "is_safe": True,
            "risk_level": "safe",
            "scam_type": "none",
            "explanation": "",
            "action": "No action needed.",
            "red_flags": [],
        }

        for line in lines:
            if line.startswith("SAFE:"):
                result["is_safe"] = "yes" in line.lower()
            elif line.startswith("RISK:"):
                result["risk_level"] = line.replace("RISK:", "").strip()
            elif line.startswith("SCAM_TYPE:"):
                result["scam_type"] = line.replace("SCAM_TYPE:", "").strip()
            elif line.startswith("EXPLANATION:"):
                result["explanation"] = line.replace("EXPLANATION:", "").strip()
            elif line.startswith("ACTION:"):
                result["action"] = line.replace("ACTION:", "").strip()
            elif line.startswith("RED_FLAGS:"):
                flags_raw = line.replace("RED_FLAGS:", "").strip()
                result["red_flags"] = [
                    f.strip() for f in flags_raw.split("|") if f.strip()
                ]

        return result

    except Exception:
        return {
            "is_safe": None,
            "risk_level": "unknown",
            "scam_type": "unknown",
            "explanation": "AI analysis unavailable. Be cautious with unknown messages.",
            "action": "Do not click any links or share personal information.",
            "red_flags": [],
        }


async def analyze_job_offer_ai(job_text: str) -> dict:
    """AI-powered fake job offer detection."""
    try:
        prompt = f"""Analyze this job offer/advertisement for fraud indicators:

Job Offer Text: "{job_text}"

Respond in this exact format:
IS_FAKE: yes/no
CONFIDENCE: 0-100
RED_FLAGS: flag1 | flag2 | flag3
EXPLANATION: brief explanation (max 100 words)
ACTION: recommended action for the user"""

        response = await _create_message(
            model="claude-sonnet-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text
        lines = text.strip().split("\n")

        result = {
            "is_fake": False,
            "confidence": 0,
            "red_flags": [],
            "explanation": "",
            "action": "Verify the company before applying.",
        }

        for line in lines:
            if line.startswith("IS_FAKE:"):
                result["is_fake"] = "yes" in line.lower()
            elif line.startswith("CONFIDENCE:"):
                try:
                    result["confidence"] = int(line.replace("CONFIDENCE:", "").strip())
                except Exception:
                    pass
            elif line.startswith("RED_FLAGS:"):
                flags_raw = line.replace("RED_FLAGS:", "").strip()
                result["red_flags"] = [
                    f.strip() for f in flags_raw.split("|") if f.strip()
                ]
            elif line.startswith("EXPLANATION:"):
                result["explanation"] = line.replace("EXPLANATION:", "").strip()
            elif line.startswith("ACTION:"):
                result["action"] = line.replace("ACTION:", "").strip()

        return result

    except Exception:
        return {
            "is_fake": None,
            "confidence": 0,
            "red_flags": [],
            "explanation": "AI analysis unavailable. Verify job offer independently.",
            "action": "Research the company online and never pay any registration fee.",
        }


async def generate_ai_security_tips(
    threats_detected: int,
    risk_score: float,
    top_threat_types: List[str],
    risky_behaviors: List[str],
) -> List[str]:
    """Generate personalized AI security improvement tips based on user's security data."""
    try:
        behaviors_text = (
            ", ".join(risky_behaviors) if risky_behaviors else "none recorded"
        )
        threats_text = (
            ", ".join(top_threat_types) if top_threat_types else "no specific threats"
        )

        prompt = f"""Generate 5 personalized cybersecurity improvement tips for a user with:
- Risk Score: {risk_score}/100
- Threats Detected Today: {threats_detected}
- Main Threat Types: {threats_text}
- Risky Behaviors: {behaviors_text}

Rules:
- Tips must be specific to their situation, not generic
- Each tip should be 1 actionable sentence
- Use simple Indian English
- No bullet points or numbering in response
- Separate each tip with a pipe character |

Example format: Tip 1 here | Tip 2 here | Tip 3 here | Tip 4 here | Tip 5 here"""

        response = await _create_message(
            model="claude-sonnet-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )

        tips_text = response.content[0].text.strip()
        tips = [t.strip() for t in tips_text.split("|") if t.strip()]
        return tips[:5] if tips else _default_tips()

    except Exception:
        return _default_tips()


def _default_tips() -> List[str]:
    return [
        "Enable two-factor authentication on all your bank and email accounts",
        "Avoid clicking unknown links from SMS or WhatsApp messages",
        "Never share OTPs with anyone, including people claiming to be from your bank",
        "Use strong unique passwords for each account and store them in a password manager",
        "Keep your apps updated to receive the latest security patches",
    ]
