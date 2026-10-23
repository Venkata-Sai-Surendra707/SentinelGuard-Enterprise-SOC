from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

def utcnow():
    return datetime.now(timezone.utc)

class SecurityEvent(Base):
    __tablename__ = 'events'
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    principal: Mapped[str] = mapped_column(String(120), index=True)
    src_ip: Mapped[str] = mapped_column(String(48), index=True)
    hostname: Mapped[str] = mapped_column(String(120))
    outcome: Mapped[str] = mapped_column(String(30))
    details: Mapped[dict] = mapped_column(JSON, default=dict)

class Incident(Base):
    __tablename__ = 'incidents'
    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(240))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(24), default='open', index=True)
    assignee: Mapped[str] = mapped_column(String(120), default='unassigned')
    entity: Mapped[str] = mapped_column(String(180), index=True)
    technique: Mapped[str] = mapped_column(String(40))
    rationale: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    notes: Mapped[list] = mapped_column(JSON, default=list)
