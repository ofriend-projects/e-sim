import os
import uuid
from typing import Optional
from dotenv import load_dotenv
from httpx_oauth.clients.google import GoogleOAuth2
from fastapi_users import FastAPIUsers, BaseUserManager, schemas
from fastapi_users.authentication import JWTStrategy, AuthenticationBackend, BearerTransport
from fastapi import Depends, Request
from .models import User, get_user_db
import logging

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__) 

# UserManager
class UserManager(BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = "SECRET"
    verification_token_secret = "SECRET"

    async def on_after_register(self, user: User, request: Optional[Request] = None):
        logger.info(f"✨ NEW USER REGISTERED: {user.email} (ID: {user.id})")
        logger.info(f"   Is active: {user.is_active}, Is verified: {user.is_verified}")
        logger.info(f"   OAuth accounts: {len(user.oauth_accounts)}")

    async def on_after_forgot_password(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        logger.info(f"🔑 Password reset requested for user {user.id}. Reset token: {token}")

    async def on_after_request_verify(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        logger.info(f"✉️ Verification requested for user {user.id}. Verification token: {token}")
    
    def parse_id(self, value: str) -> uuid.UUID:
        """Parse string ID to UUID"""
        logger.debug(f"🔍 Parsing user ID from token: {value}")
        return uuid.UUID(value)

async def get_user_manager(user_db=Depends(get_user_db)):
    yield UserManager(user_db)

# User Schemas
class UserRead(schemas.BaseUser[uuid.UUID]):
    pass

class UserCreate(schemas.BaseUserCreate):
    pass

class UserUpdate(schemas.BaseUserUpdate):
    pass

# 1. Define the Google Client
google_oauth_client = GoogleOAuth2(
    os.getenv("GOOGLE_CLIENT_ID", "YOUR_CLIENT_ID"),
    os.getenv("GOOGLE_CLIENT_SECRET", "YOUR_CLIENT_SECRET"),
    scopes=["openid", "email", "profile"]
)

# 2. Define Authentication Strategy (JWT)
SECRET = os.getenv("SECRET_KEY", "YOUR_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION")

def get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(secret=SECRET, lifetime_seconds=72000)

auth_backend = AuthenticationBackend(
    name="jwt",
    transport=BearerTransport(tokenUrl="auth/jwt/login"),
    get_strategy=get_jwt_strategy,
)

# 3. Initialize FastAPI Users
fastapi_users = FastAPIUsers[User, uuid.UUID](
    get_user_manager,
    [auth_backend],
)