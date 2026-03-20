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
) -> dict:
    """Generate a formal fraud complaint email."""
    try:
        client = get_client()

        prompt = f"""Generate a formal cybercrime complaint email for the following:

Incident Type: {incident_type}
Description: {description}
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

        return {
            "subject": subject or f"Cybercrime Complaint: {incident_type}",
            "body": "\n".join(body_lines).strip() or text,
            "to_addresses": to_addresses,
        }

    except Exception as e:
        return {
            "subject": f"Cybercrime Complaint: {incident_type}",
            "body": f"Dear Cybercrime Authority,\n\nI am writing to report a cybercrime incident.\n\nIncident Type: {incident_type}\nDescription: {description}\n\nI request immediate investigation.\n\nThank you,\n{user_name}",
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
