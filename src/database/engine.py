"""Database engine configuration and session management for SecOps Log Analyzer."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from ..utils.config import get_settings
from .models import Base

logger = logging.getLogger(__name__)

_engine: Optional[Engine] = None
_SessionFactory: Optional[sessionmaker[Session]] = None


def get_engine(database_url: Optional[str] = None) -> Engine:
    """
    Get or create the SQLAlchemy engine singleton.

    Args:
        database_url: Optional database URL override; defaults to settings.database_url.

    Returns:
        SQLAlchemy Engine instance.
    """
    global _engine, _SessionFactory
    if database_url is not None:
        connect_args = {}
        if database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        return create_engine(database_url, connect_args=connect_args, future=True)

    if _engine is None:
        settings = get_settings()
        url = settings.database_url
        connect_args = {}
        if url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        _engine = create_engine(url, connect_args=connect_args, future=True)
        _SessionFactory = sessionmaker(bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False)
        logger.info(f"Database engine initialized for URL: {url}")

    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Get the global sessionmaker factory."""
    global _SessionFactory
    if _SessionFactory is None:
        get_engine()
    assert _SessionFactory is not None
    return _SessionFactory


@contextmanager
def get_session(engine: Optional[Engine] = None) -> Generator[Session, None, None]:
    """
    Provide a transactional scope around a series of operations.

    Args:
        engine: Optional Engine override.

    Yields:
        Active SQLAlchemy Session.
    """
    if engine is not None:
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
        session = factory()
    else:
        factory = get_session_factory()
        session = factory()

    try:
        yield session
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.exception("Database session rolled back due to error")
        raise exc
    finally:
        session.close()


def init_db(engine: Optional[Engine] = None) -> None:
    """
    Create all tables defined in metadata if they do not exist.

    Args:
        engine: Optional Engine override.
    """
    eng = engine or get_engine()
    Base.metadata.create_all(bind=eng)
    logger.info("Database tables verified/initialized successfully.")


def close_engine() -> None:
    """Dispose of the database engine (useful in test teardowns)."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _SessionFactory = None
