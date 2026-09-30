"""Persistence: PostgreSQL in the Docker stack, SQLite when DATABASE_URL is unset (local dev/tests)."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

DATA_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).resolve().parents[3] / "data"))
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DATA_DIR / 'analyzer.db'}")

engine = create_engine(DATABASE_URL, pool_pre_ping=True,
                       connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    provenance: Mapped[str] = mapped_column(String(64))  # synthetic | real-public | user-upload
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|done|failed
    stage: Mapped[str] = mapped_column(String(64), default="queued")
    error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    has_keys: Mapped[int] = mapped_column(Integer, default=0)
    tunnels: Mapped[list["TunnelRow"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class TunnelRow(Base):
    __tablename__ = "tunnels"
    pk: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    tunnel_id: Mapped[str] = mapped_column(String(64), index=True)
    risk: Mapped[float] = mapped_column(Float, index=True)
    band: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict] = mapped_column(JSON)  # tunnel + findings + risk + anomaly
    analysis: Mapped[Analysis] = relationship(back_populates="tunnels")


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(engine)
