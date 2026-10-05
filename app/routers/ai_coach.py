import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.database import get_db
from app.models.user import User
from app.models.ai_conversation import AiConversation, ConversationRole
from app.schemas.ai_conversation import (
    ChatRequest, ChatResponse,
    ConversationMessageResponse,
    ComplaintEmailRequest, ComplaintEmailResponse,
)
from app.config import settings
from app.middleware.rate_limiter import rate_limiter
from app.routers.auth import get_current_user
from app.services.ai_service import chat_with_coach, generate_complaint_email

router = APIRouter(prefix="/ai", tags=["ai"])

HISTORY_TURNS = 20


def _check_ai_rate(user: User) -> None:
    """Per-user cap on model calls (cost + event-loop protection)."""
    if not rate_limiter.is_allowed(f"ai:{user.id}", max_hits=settings.AI_REQUESTS_PER_MINUTE, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many AI requests. Please wait a minute and try again.",
            headers={"Retry-After": "60"},
        )


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _check_ai_rate(current_user)
    session_id = request.session_id or uuid.uuid4()

    # History for context: ONLY this user's turns of this session (a session id alone must never
    # grant access to someone else's conversation), and the LATEST turns, not the oldest.
    history_result = await db.execute(
        select(AiConversation)
        .where(
            AiConversation.session_id == session_id,
            AiConversation.user_id == current_user.id,
        )
        .order_by(AiConversation.created_at.desc())
        .limit(HISTORY_TURNS)
    )
    history = list(reversed(history_result.scalars().all()))

    messages = [{"role": msg.role.value, "content": msg.content} for msg in history]
    messages.append({"role": "user", "content": request.message})

    reply = await chat_with_coach(
        messages,
        request.topic_category,
        language=request.language or "en",
    )

    # Save user message
    user_msg = AiConversation(
        user_id=current_user.id,
        session_id=session_id,
        role=ConversationRole.user,
        content=request.message,
        topic_category=request.topic_category,
    )
    db.add(user_msg)

    # Save assistant reply
    ai_msg = AiConversation(
        user_id=current_user.id,
        session_id=session_id,
        role=ConversationRole.assistant,
        content=reply,
        topic_category=request.topic_category,
    )
    db.add(ai_msg)
    await db.commit()

    return ChatResponse(
        session_id=session_id,
        reply=reply,
        topic_category=request.topic_category,
        language=request.language or "en",
    )


@router.get("/history/{session_id}", response_model=List[ConversationMessageResponse])
async def get_history(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    result = await db.execute(
        select(AiConversation)
        .where(
            AiConversation.session_id == session_uuid,
            AiConversation.user_id == current_user.id,
        )
        .order_by(AiConversation.created_at.asc())
    )
    return result.scalars().all()


@router.post("/generate-complaint-email", response_model=ComplaintEmailResponse)
async def generate_email(
    request: ComplaintEmailRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _check_ai_rate(current_user)
    user_name = current_user.full_name or current_user.phone
    result = await generate_complaint_email(
        incident_type=request.incident_type,
        description=request.description,
        evidence_summary=request.evidence_summary,
        suspect_info=request.suspect_info,
        user_name=user_name,
        bank_name=request.bank_name,
        amount=request.amount,
        incident_date=request.incident_date,
        language=request.language or "en",
    )
    return ComplaintEmailResponse(**result)
