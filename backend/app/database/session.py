from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

engine = create_engine(settings.database_url, future=True, echo=False)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_session() -> sessionmaker[Session]:
    """Return the configured SQLAlchemy session factory."""

    return SessionLocal


def get_db_session() -> Generator[Session, None, None]:
    """Yield one request-scoped session without owning its transaction outcome."""

    with SessionLocal() as session:
        yield session
