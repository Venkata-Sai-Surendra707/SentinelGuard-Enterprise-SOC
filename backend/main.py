import os
from collections import Counter
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Header, Query
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .db import initialize, session_scope
from .models import SecurityEvent, Incident, utcnow
from .schemas import EventIn, EventOut, IncidentOut, IncidentUpdate
from .simulation import generate
from .detections import run_detection, RULES

@asynccontextmanager
async def lifespan(app):
    initialize()
    yield

app = FastAPI(title='SentinelGuard SOC API',version='1.0.0',lifespan=lifespan)

def guard(x_api_key: str | None = Header(None)):
    expected=os.getenv('SENTINELGUARD_API_KEY')
    if not expected or x_api_key != expected:
        raise HTTPException(401,'Valid API key required (set SENTINELGUARD_API_KEY)')

def db_session():
    db=session_scope()
    try:
        yield db
    finally:
        db.close()

@app.get('/health')
def health():
    return {'status':'ok','service':'sentinelguard'}

@app.get('/rules',dependencies=[Depends(guard)])
def rules():
    return RULES

@app.post('/simulate',dependencies=[Depends(guard)])
def simulate(count: int=Query(500,ge=0,le=10000), seed: int=42, db:Session=Depends(db_session)):
    added=0
    for ev in generate(count,seed):
        if db.scalar(select(SecurityEvent.id).where(SecurityEvent.event_id==ev.event_id)) is None:
            db.add(SecurityEvent(**ev.model_dump()))
            added+=1
    db.commit()
    return {'inserted':added,'synthetic':True}

@app.post('/events',dependencies=[Depends(guard)],response_model=EventOut,status_code=201)
def ingest(event:EventIn,db:Session=Depends(db_session)):
    if db.scalar(select(SecurityEvent.id).where(SecurityEvent.event_id==event.event_id)):
        raise HTTPException(409,'Duplicate event_id')
    row=SecurityEvent(**event.model_dump())
    db.add(row)
    db.commit(); db.refresh(row)
    return row

@app.get('/events',dependencies=[Depends(guard)],response_model=list[EventOut])
def events(limit:int=Query(100,ge=1,le=1000),db:Session=Depends(db_session)):
    return db.scalars(select(SecurityEvent).order_by(SecurityEvent.ts.desc()).limit(limit)).all()

@app.post('/detect',dependencies=[Depends(guard)])
def detect(db:Session=Depends(db_session)):
    return run_detection(db)

@app.get('/incidents',dependencies=[Depends(guard)],response_model=list[IncidentOut])
def incidents(status:str|None=None,limit:int=Query(100,ge=1,le=1000),db:Session=Depends(db_session)):
    stmt=select(Incident)
    if status: stmt=stmt.where(Incident.status==status)
    return db.scalars(stmt.order_by(Incident.last_seen.desc()).limit(limit)).all()

@app.patch('/incidents/{incident_id}',dependencies=[Depends(guard)],response_model=IncidentOut)
def update_incident(incident_id:int,change:IncidentUpdate,db:Session=Depends(db_session)):
    row=db.get(Incident,incident_id)
    if row is None: raise HTTPException(404,'Incident not found')
    if change.status is not None: row.status=change.status
    if change.assignee is not None: row.assignee=change.assignee
    if change.note:
        row.notes=[*row.notes,{'at':utcnow().isoformat(),'author':change.assignee or row.assignee,'text':change.note}]
    row.updated_at=utcnow()
    db.commit();db.refresh(row)
    return row

@app.get('/incidents/{incident_id}/analysis',dependencies=[Depends(guard)])
def explain(incident_id:int,db:Session=Depends(db_session)):
    row=db.get(Incident,incident_id)
    if row is None: raise HTTPException(404,'Incident not found')
    return {'incident_id':row.id,'mode':'deterministic_explainable_assistant','finding':row.rationale,
            'confidence':'rule-match, not confirmed compromise','technique':row.technique,
            'evidence_ids':row.evidence,
            'recommended_actions':['Validate affected identity or asset ownership','Correlate with relevant authentication, endpoint and network logs','Check for authorized administrative activity','Document disposition and escalate based on evidence'],
            'disclaimer':'Synthetic lab analytics; human verification required.'}

@app.get('/metrics',dependencies=[Depends(guard)])
def metrics(db:Session=Depends(db_session)):
    items=db.scalars(select(Incident)).all()
    return {'events':db.scalar(select(func.count()).select_from(SecurityEvent)),
            'incidents':len(items),'by_severity':dict(Counter(i.severity for i in items)),
            'by_status':dict(Counter(i.status for i in items)),
            'by_rule':dict(Counter(i.rule_id for i in items))}
