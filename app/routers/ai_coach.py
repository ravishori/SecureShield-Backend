import uuid
from fastapi import APIRouter, Depends
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
from app.routers.auth import get_current_user
from app.services.ai_service import chat_with_coach, generate_complaint_email

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session_id = request.session_id or uuid.uuid4()

    # Fetch conversation history for context
    history_result = await db.execute(
        select(AiConversation)
        .where(AiConversation.session_id == session_id)
        .order_by(AiConversation.created_at.asc())
        .limit(20)
    )
    history = history_result.scalars().all()

    messages = [{"role": msg.role.value, "content": msg.content} for msg in history]
    messages.append({"role": "user", "content": request.message})

    reply = await chat_with_coach(messages, request.topic_category)

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
    )


@router.get("/history/{session_id}", response_model=List[ConversationMessageResponse])
async def get_history(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AiConversation)
        .where(
            AiConversation.session_id == uuid.UUID(session_id),
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
    user_name = current_user.full_name or current_user.phone
    result = await generate_complaint_email(
        incident_type=request.incident_type,
        description=request.description,
        evidence_summary=request.evidence_summary,
        suspect_info=request.suspect_info,
        user_name=user_name,
    )
    return ComplaintEmailResponse(**result)
