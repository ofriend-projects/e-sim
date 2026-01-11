from fastapi_users.db import SQLAlchemyBaseUserTableUUID, SQLAlchemyBaseOAuthAccountTableUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, relationship
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from fastapi import Depends
from fastapi_users.db import SQLAlchemyUserDatabase

# 1. Define Base
class Base(DeclarativeBase):
    pass

# 2. Define OAuth Account Model
class OAuthAccount(SQLAlchemyBaseOAuthAccountTableUUID, Base):
    pass

# 3. Define User Model with relationship to OAuthAccount
class User(SQLAlchemyBaseUserTableUUID, Base):
    oauth_accounts: Mapped[list[OAuthAccount]] = relationship(
        "OAuthAccount", lazy="joined"
    )

# 4. Database Setup (Standard SQLAlchemy)
DATABASE_URL = "sqlite+aiosqlite:///./test.db"
engine = create_async_engine(DATABASE_URL)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

async def get_async_session():
    async with async_session_maker() as session:
        yield session

async def get_user_db(session: AsyncSession = Depends(get_async_session)):
    yield SQLAlchemyUserDatabase(session, User, OAuthAccount)