import anthropic
from app.config import settings
from typing import List, Optional


def get_client() -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


SYSTEM_PROMPT = """You are SecureShield AI Coach — an expert cybersecurity assistant specializing in digital safety for everyday users in India and worldwide. Your role is to:
- Educate users about online scams, phishing, OTP fraud, and cyber threats
- Provide clear, actionable advice in simple language
- Help users understand if apps, links, or calls might be dangerous
- Guide users through reporting cybercrime
- Support senior citizens with easy-to-understand explanations

Always be empathetic, clear, and supportive. Never use excessive jargon. If someone seems to be in danger, immediately advise them to call cybercrime helpline 1930 (India) or local emergency services.

Keep responses concise but thorough. Use bullet points for actionable steps."""


async def chat_with_coach(messages: List[dict], topic_category: Optional[str] = None) -> str:
    """Send messages to Claude and get a response."""
    try:
        client = get_client()
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
        return response.content[0].text
    except Exception as e:
        return f"AI service temporarily unavailable. Please try again later. Error: {str(e)}"


async def generate_complaint_email(
    incident_type: str,
    description: str,
    evidence_summary: Optional[str],
    suspect_info: Optional[str],
    user_name: str = "Victim",
    bank_name: Optional[str] = None,
    amount: Optional[str] = None,
    incident_date: Optional[str] = None,
) -> dict:
    """Generate a formal fraud complaint email."""
    try:
        client = get_client()

        bank_line   = f"Bank/Institution: {bank_name}" if bank_name else ""
        amount_line = f"Amount Lost: ₹{amount}" if amount else ""
        date_line   = f"Incident Date: {incident_date}" if incident_date else ""
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

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
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

    except Exception as e:
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


async def explain_app_threat(app_name: str, risk_score: float, threat_tags: List[str], permissions: List[str]) -> str:
    """Generate human-readable explanation of app threats."""
    try:
        client = get_client()

        prompt = f"""Explain in simple language why the app "{app_name}" is flagged as potentially risky:
Risk Score: {risk_score}/100
Threat Tags: {', '.join(threat_tags)}
Dangerous Permissions: {', '.join(permissions[:10])}

Provide:
1. What the risk means in plain English
2. What data could be at risk
3. Recommended action (keep/monitor/uninstall)
Keep it under 100 words and very clear."""

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=256,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    except Exception:
        return f"This app has a risk score of {risk_score}/100 due to suspicious permissions. Review permissions carefully and consider uninstalling if you don't trust the app."


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
) -> dict:
    """Generate a formal FIR (First Information Report) draft for cybercrime."""
    try:
        client = get_client()

        amount_line = f"Financial Loss: ₹{amount_lost}" if amount_lost else "Financial Loss: None reported"

        prompt = f"""Generate a formal First Information Report (FIR) draft for a cybercrime incident in India.

Incident Details:
- Type: {incident_type}
- Date/Time: {incident_date}
- Location: {incident_location}
- Description: {description}
- Suspect Information: {suspect_info or "Unknown"}
- Evidence: {evidence_summary or "None provided"}
- {amount_line}

Complainant:
- Name: {complainant_name}
- Contact: {complainant_phone}

Generate a complete FIR draft with:
1. FIR Header (police station placeholder, date, FIR number placeholder)
2. Complainant details section
3. Detailed incident description in formal language
4. Evidence list
5. Suspect description (if any)
6. Relief sought
7. Declaration statement
8. Relevant IPC/IT Act sections that apply

Format as a proper legal document ready to submit at a police station."""

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
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
        fallback = (
            f"FIR DRAFT\n\n"
            f"Date: {incident_date}\n"
            f"Incident Type: {incident_type}\n"
            f"Description: {description}\n"
            f"Complainant: {complainant_name} ({complainant_phone})\n\n"
            f"I hereby report the above cybercrime incident and request immediate police action.\n\n"
            f"Signature: {complainant_name}"
        )
        return {
            "fir_draft": fallback,
            "incident_type": incident_type,
            "complainant_name": complainant_name,
            "generated_at": incident_date,
            "note": "AI unavailable — basic draft generated. Please add full details.",
        }


async def analyze_message_safety(message_text: str) -> dict:
    """AI-powered analysis of whether a message is safe or a scam."""
    try:
        client = get_client()

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

        response = client.messages.create(
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
                result["red_flags"] = [f.strip() for f in flags_raw.split("|") if f.strip()]

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
        client = get_client()

        prompt = f"""Analyze this job offer/advertisement for fraud indicators:

Job Offer Text: "{job_text}"

Respond in this exact format:
IS_FAKE: yes/no
CONFIDENCE: 0-100
RED_FLAGS: flag1 | flag2 | flag3
EXPLANATION: brief explanation (max 100 words)
ACTION: recommended action for the user"""

        response = client.messages.create(
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
                result["red_flags"] = [f.strip() for f in flags_raw.split("|") if f.strip()]
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
        client = get_client()

        behaviors_text = ", ".join(risky_behaviors) if risky_behaviors else "none recorded"
        threats_text = ", ".join(top_threat_types) if top_threat_types else "no specific threats"

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

        response = client.messages.create(
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
