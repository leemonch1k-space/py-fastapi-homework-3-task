from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.token_manager import JWTAuthManager
from security.passwords import verify_password
from security.interfaces import JWTAuthManagerInterface

from schemas import accounts

from exceptions.security import TokenExpiredError, InvalidTokenError

router = APIRouter()


@router.post("/register/", response_model=accounts.UserReadSchema, status_code=201)
async def create_user(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_data: accounts.UserRegistrationRequestSchema
):
    user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    result = user.scalar_one_or_none()
    if result:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        group_query = await db.execute(select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        ))
        default_group = group_query.scalar_one_or_none()

        if not default_group:
            raise HTTPException(status_code=500, detail="Default user group not found.")

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=default_group.id
        )
        db.add(new_user)

        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=200)
async def activate_user(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_data: accounts.UserActivationSchema
):
    query = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == user_data.email)
    )
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    token_record = db_user.activation_token

    if not token_record or token_record.token != user_data.token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    db_user.is_active = True

    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=200)
async def request_password_reset(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_data: accounts.PasswordResetSchema
):
    success_message = {
        "message": "If you are registered, you will receive an email with instructions."
    }

    query = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == str(user_data.email))
    )
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.is_active:
        return success_message

    try:
        if db_user.password_reset_token:
            await db.delete(db_user.password_reset_token)
            await db.flush()

        new_reset_token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(new_reset_token)

        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        return success_message

    return success_message


@router.post("/reset-password/complete/", status_code=200)
async def reset_password_complete(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_data: accounts.PasswordResetCompleteSchema
):
    query = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == str(user_data.email))
    )
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_record = db_user.password_reset_token

    is_token_invalid = not token_record or token_record.token != user_data.token
    is_token_expired = False

    if token_record:
        expires_at = token_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            is_token_expired = True

    if is_token_invalid or is_token_expired:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        db_user.password = user_data.password

        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=accounts.TokenResponseSchema, status_code=201)
async def login_user(
        user_data: accounts.UserLoginSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
        settings: Annotated[BaseAppSettings, Depends(get_settings)]
):
    result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(user_data.password, user._hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token(data={"sub": str(user.id)})
        refresh_token = jwt_manager.create_refresh_token(data={"sub": str(user.id)})

        new_refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )

        db.add(new_refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=accounts.RefreshTokenResponseSchema, status_code=200)
async def refresh_access_token(
        token_data: accounts.RefreshTokenRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)]
):
    try:
        jwt_manager.decode_refresh_token(token=token_data.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )

    query = (
        select(RefreshTokenModel)
        .options(joinedload(RefreshTokenModel.user))
        .where(RefreshTokenModel.token == token_data.refresh_token)
    )
    token_result = await db.execute(query)
    token_db = token_result.scalar_one_or_none()

    if not token_db:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    user = token_db.user

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(data={"sub": str(user.id)})

    return {"access_token": new_access_token}
