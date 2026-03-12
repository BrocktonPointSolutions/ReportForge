from __future__ import annotations
__version__ = "1.2.3"
import datetime as dt
from typing import Optional
from sqlalchemy import String, Text, DateTime, Float
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

_now = lambda: dt.datetime.now(
    dt.timezone.utc).replace(tzinfo=None)

class Report(Base):
    __tablename__ = 'reports'
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True)
    title: Mapped[str] = mapped_column(
        String(300), default='Untitled Report')
    org: Mapped[str] = mapped_column(
        String(300), default='')
    report_type: Mapped[str] = mapped_column(
        String(120), default='Security Assessment')
    classification: Mapped[str] = mapped_column(
        String(60), default='Confidential')
    assessment_date: Mapped[str] = mapped_column(
        String(20), default='')
    authors: Mapped[str] = mapped_column(
        String(300), default='')
    status: Mapped[str] = mapped_column(
        String(40), default='draft')
    data_json: Mapped[str] = mapped_column(
        Text, default='{}')
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=_now, onupdate=_now)

class Template(Base):
    __tablename__ = 'templates'
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(
        Text, default='')
    template_json: Mapped[str] = mapped_column(
        Text, default='{}')
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=_now, onupdate=_now)

class Finding(Base):
    __tablename__ = 'findings'
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True)
    report_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True)
    title: Mapped[str] = mapped_column(
        String(300), default='')
    severity: Mapped[str] = mapped_column(
        String(40), default='Medium')
    status: Mapped[str] = mapped_column(
        String(40), default='open')
    description: Mapped[str] = mapped_column(
        Text, default='')
    discussion: Mapped[str] = mapped_column(
        Text, default='')
    recommendation: Mapped[str] = mapped_column(
        Text, default='')
    refs: Mapped[str] = mapped_column(
        Text, default='')
    cvss: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=_now, onupdate=_now)
