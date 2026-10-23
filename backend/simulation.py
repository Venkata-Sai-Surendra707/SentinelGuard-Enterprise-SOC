"""Reproducible synthetic logs: RFC 5737 test-net IPs, no network probes."""
from datetime import datetime, timedelta, timezone
from random import Random
from .schemas import EventIn

def generate(count=500, seed=42):
    rng = Random(seed)
    base = datetime(2026,10,20,12,0,tzinfo=timezone.utc)
    events = []
    for n in range(count):
        user = rng.choice(['alex','jamie','priya','morgan','sam'])
        events.append(EventIn(event_id=f'sim-{seed}-normal-{n}',ts=base+timedelta(seconds=n*45),source='identity',event_type='authentication',principal=user,src_ip=f'192.0.2.{rng.randint(1,250)}',hostname='idp-lab',outcome='success',details={'mfa':'passed','synthetic':True}))
    attack_start = base+timedelta(hours=8)
    for n in range(8):
        events.append(EventIn(event_id=f'sim-{seed}-burst-{n}',ts=attack_start+timedelta(seconds=n*25),source='identity',event_type='authentication',principal='alex',src_ip='198.51.100.17',hostname='idp-lab',outcome='failure',details={'synthetic':True}))
    events.append(EventIn(event_id=f'sim-{seed}-burst-success',ts=attack_start+timedelta(minutes=4),source='identity',event_type='authentication',principal='alex',src_ip='198.51.100.17',hostname='idp-lab',outcome='success',details={'mfa':'unknown','synthetic':True}))
    for kind, details, source, hostname in [
        ('role_change',{'privileged':True,'role':'global_admin','synthetic':True},'cloud','tenant-lab'),
        ('security_control',{'action':'disabled','product':'lab-edr','synthetic':True},'endpoint','lab-workstation-7'),
        ('network_transfer',{'bytes_out':180_000_000,'destination':'203.0.113.55','synthetic':True},'network','lab-workstation-7')]:
        idx=len(events)
        events.append(EventIn(event_id=f'sim-{seed}-scenario-{idx}',ts=attack_start+timedelta(minutes=6+idx%7),source=source,event_type=kind,principal='alex',src_ip='203.0.113.5',hostname=hostname,outcome='observed',details=details))
    return events
