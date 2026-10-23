from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict

class EventIn(BaseModel):
    event_id: str = Field(min_length=3, max_length=80)
    ts: datetime
    source: str = Field(min_length=2, max_length=40)
    event_type: str = Field(min_length=2, max_length=80)
    principal: str = Field(max_length=120)
    src_ip: str = Field(max_length=48)
    hostname: str = Field(max_length=120)
    outcome: str = Field(max_length=30)
    details: dict = Field(default_factory=dict)

class EventOut(EventIn):
    model_config = ConfigDict(from_attributes=True)
    id: int

class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_id: str
    title: str
    severity: str
    status: str
    assignee: str
    entity: str
    technique: str
    rationale: str
    first_seen: datetime
    last_seen: datetime
    evidence: list
    notes: list

class IncidentUpdate(BaseModel):
    status: Literal['open','investigating','contained','closed'] | None = None
    assignee: str | None = Field(default=None, max_length=120)
    note: str | None = Field(default=None, max_length=1000)
