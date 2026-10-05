from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings

# hide_parameters: SQLAlchemy otherwise appends "[parameters: (...)]" to DB errors, which
# would put bound values (submitted OTP codes, emails, phone numbers) into exception text,
# tracebacks, error_logs rows and alert e-mails.
engine = create_async_engine(settings.DATABASE_URL, echo=False, hide_parameters=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
