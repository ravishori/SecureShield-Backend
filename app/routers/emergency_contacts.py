import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.database import get_db
from app.models.user import User
from app.models.emergency_contact import EmergencyContact
from app.schemas.emergency_contact import (
    EmergencyContactCreate,
    EmergencyContactUpdate,
    EmergencyContactResponse,
)
from app.routers.auth import get_current_user

router = APIRouter(prefix="/emergency-contacts", tags=["emergency-contacts"])


@router.get("", response_model=List[EmergencyContactResponse])
async def list_contacts(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(EmergencyContact).where(EmergencyContact.user_id == current_user.id)
    )
    return result.scalars().all()


@router.post("", response_model=EmergencyContactResponse)
async def add_contact(
    data: EmergencyContactCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    contact = EmergencyContact(
        user_id=current_user.id,
        name=data.name,
        relationship=data.relationship,
        phone=data.phone,
        email=data.email,
    )
    db.add(contact)
    await db.commit()
    await db.refresh(contact)
    return contact


@router.patch("/{contact_id}", response_model=EmergencyContactResponse)
async def update_contact(
    contact_id: str,
    data: EmergencyContactUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partial update — only fields present in the body are modified."""
    try:
        contact_uuid = uuid.UUID(contact_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid contact id")

    result = await db.execute(
        select(EmergencyContact).where(
            EmergencyContact.id == contact_uuid,
            EmergencyContact.user_id == current_user.id,
        )
    )
    contact = result.scalar_one_or_none()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    # Apply only the fields the client actually sent (model_dump exclude_unset)
    updates = data.model_dump(exclude_unset=True)
    for field, value in updates.items():
        # Treat empty strings as "clear this field"
        setattr(contact, field, value if value != "" else None)

    # Require at least one of phone/email to remain set after update
    if not (contact.phone or contact.email):
        raise HTTPException(
            status_code=400,
            detail="At least one of phone or email is required",
        )
    if not (contact.name and contact.name.strip()):
        raise HTTPException(status_code=400, detail="Name is required")

    await db.commit()
    await db.refresh(contact)
    return contact


@router.delete("/{contact_id}")
async def delete_contact(
    contact_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        contact_uuid = uuid.UUID(contact_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid contact id")

    result = await db.execute(
        select(EmergencyContact).where(
            EmergencyContact.id == contact_uuid,
            EmergencyContact.user_id == current_user.id,
        )
    )
    contact = result.scalar_one_or_none()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    await db.delete(contact)
    await db.commit()
    return {"message": "Contact removed", "id": contact_id}
