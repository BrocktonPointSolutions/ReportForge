from __future__ import annotations
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import NullPool
from reportforge.utils import get_db_path

def _make_url() -> str:
    return "sqlite:///" + str(get_db_path())

engine = create_engine(
    _make_url(),
    connect_args={"check_same_thread": False},
    poolclass=NullPool,
)

@event.listens_for(engine, "connect")
def _set_sqlite_pragma(conn, _):
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

class Base(DeclarativeBase):
    pass
