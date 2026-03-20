from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.user import User
from app.models.device import Device
from app.schemas.device import DeviceRegisterRequest, DeviceResponse, DeviceUpdateRequest
from app.routers.auth import get_current_user
from typing import List

router = APIRouter(prefix="/devices", tags=["devices"])


@router.post("/register", response_model=DeviceResponse)
async def register_device(
    request: DeviceRegisterRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Check if device already exists
    result = await db.execute(select(Device).where(Device.device_token == request.device_token))
    device = result.scalar_one_or_none()

    if device:
        device.last_seen = datetime.utcnow()
        device.is_active = True
        if request.os_version:
            device.os_version = request.os_version
        if request.app_version:
            device.app_version = request.app_version
    else:
        device = Device(
            user_id=current_user.id,
            device_token=request.device_token,
            device_name=request.device_name,
            platform=request.platform,
            os_version=request.os_version,
            app_version=request.app_version,
            last_seen=datetime.utcnow(),
        )
        db.add(device)

    await db.commit()
    await db.refresh(device)
    return device


@router.get("/", response_model=List[DeviceResponse])
async def list_devices(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Device).where(Device.user_id == current_user.id, Device.is_active == True)
    )
    return result.scalars().all()


@router.patch("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: str,
    request: DeviceUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    import uuid
    result = await db.execute(
        select(Device).where(Device.id == uuid.UUID(device_id), Device.user_id == current_user.id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if request.device_name is not None:
        device.device_name = request.device_name
    if request.os_version is not None:
        device.os_version = request.os_version
    if request.app_version is not None:
        device.app_version = request.app_version
    device.last_seen = datetime.utcnow()

    await db.commit()
    await db.refresh(device)
    return device
