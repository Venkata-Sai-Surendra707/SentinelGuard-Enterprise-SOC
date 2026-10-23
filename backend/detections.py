"""Deterministic defensive analytics over synthetic or authorized logs only."""
import hashlib
from collections import defaultdict
from datetime import timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import SecurityEvent, Incident

RULES = {
    'SG-001': {'title':'Repeated authentication failures','severity':'high','technique':'T1110'},
    'SG-002': {'title':'Successful authentication after repeated failures','severity':'critical','technique':'T1110'},
    'SG-003': {'title':'Suspicious privileged role change','severity':'high','technique':'T1098'},
    'SG-004': {'title':'Endpoint security control disabled','severity':'critical','technique':'T1562.001'},
    'SG-005': {'title':'Unusual outbound data transfer','severity':'high','technique':'T1041'},
}

def _emit(rule_id, entity, events, rationale):
    ordered = sorted(events, key=lambda e: e.ts)
    unique_key = rule_id + '|' + entity + '|' + '|'.join(sorted(e.event_id for e in events))
    fingerprint = hashlib.sha256(unique_key.encode()).hexdigest()
    return dict(fingerprint=fingerprint, rule_id=rule_id, title=RULES[rule_id]['title'],
                severity=RULES[rule_id]['severity'], technique=RULES[rule_id]['technique'],
                entity=entity, rationale=rationale, first_seen=ordered[0].ts,
                last_seen=ordered[-1].ts, evidence=[e.event_id for e in ordered])

def analyze(events):
    events = sorted(events, key=lambda e: e.ts)
    findings = []
    auth = defaultdict(list)
    for e in events:
        if e.event_type == 'authentication':
            auth[(e.principal, e.src_ip)].append(e)
        if e.event_type == 'role_change' and e.details.get('privileged') is True:
            findings.append(_emit('SG-003',e.principal,[e],f"Privileged role changed on {e.hostname}; review authorization and change ticket."))
        if e.event_type == 'security_control' and e.details.get('action') == 'disabled':
            findings.append(_emit('SG-004',e.hostname,[e],f"Endpoint protection was disabled on {e.hostname}; validate maintenance authorization."))
        if e.event_type == 'network_transfer' and int(e.details.get('bytes_out',0)) >= 100_000_000:
            findings.append(_emit('SG-005',e.hostname,[e],f"Outbound transfer exceeded 100 MB from {e.hostname}; investigate destination and business context."))
    for (principal, ip), group in auth.items():
        failures = [e for e in group if e.outcome == 'failure']
        bucket = []
        for e in failures:
            if bucket and e.ts - bucket[0].ts > timedelta(minutes=10):
                if len(bucket) >= 5:
                    findings.append(_emit('SG-001',f'{principal}@{ip}',bucket,f'{len(bucket)} failed logins in <=10 minutes for {principal} from {ip}.'))
                bucket = []
            bucket.append(e)
        if len(bucket) >= 5:
            findings.append(_emit('SG-001',f'{principal}@{ip}',bucket,f'{len(bucket)} failed logins in <=10 minutes for {principal} from {ip}.'))
        for success in (e for e in group if e.outcome == 'success'):
            preceding = [e for e in failures if timedelta(0) <= success.ts-e.ts <= timedelta(minutes=10)]
            if len(preceding) >= 5:
                findings.append(_emit('SG-002',f'{principal}@{ip}',preceding+[success],f'Successful login followed {len(preceding)} failures from {ip}; verify account owner and MFA logs.'))
    return findings

def run_detection(db: Session):
    events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.ts)).all()
    findings = analyze(events)
    created = 0
    for result in findings:
        if db.scalar(select(Incident.id).where(Incident.fingerprint == result['fingerprint'])) is None:
            db.add(Incident(**result))
            created += 1
    db.commit()
    return {'evaluated_events':len(events),'findings':len(findings),'new_incidents':created}
