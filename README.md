# SentinelGuard — Enterprise SOC Detection & Case Management

Defensive SOC platform with synthetic security telemetry, API-based ingestion, correlation rules, incident triage, MITRE ATT&CK references and an analyst dashboard.

**Security scope:** Simulation only; no scanning, exploitation or unauthorized log collection. ATT&CK labels are mappings, not proof of compromise.

## Run

1. Copy `.env.example` to `.env` and replace the example passwords with strong distinct secrets.
2. Run `docker compose up --build -d`.
3. Open http://localhost:8501 and provide your API key.
4. Generate synthetic events, run detections, and triage incidents.
5. API docs: http://localhost:8000/docs

Do not expose these development services publicly without HTTPS, RBAC and audit logging.

## Detection rules

- SG-001: five or more failed authentications from one source in ten minutes — T1110
- SG-002: successful authentication after repeated failures — T1110
- SG-003: privileged role change — T1098
- SG-004: endpoint protection disabled — T1562.001
- SG-005: outbound transfer over 100MB — T1041

## Development

```bash
pip install -r requirements.txt
python -m pytest -q
```

Educational prototype; not production-hardened.
