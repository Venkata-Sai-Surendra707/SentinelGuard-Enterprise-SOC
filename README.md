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


## Deployment configuration and verification

Compose runs PostgreSQL, the API, and the dashboard. It builds the database URL
from separate credentials (including passwords containing URL characters), waits
for database readiness, and waits for API `/ready` before starting the dashboard.
`/health` checks the process; `/ready` runs `SELECT 1` and returns 503 if the
connection fails. Enter the backend's API key in the dashboard sidebar.

The Render Blueprint manages **only the API and PostgreSQL**. Deploy
`frontend/app.py` separately on Streamlit, with `requirements.txt` at the repository
root. Set `API_URL` in that dashboard's environment to the actual HTTPS backend
URL, then enter the same `SENTINELGUARD_API_KEY` that is configured on the API.
The existing default URL remains a convenience; an explicit `API_URL` takes
precedence. For direct local runs, export environment variables before starting
Python; copying `.env` alone only configures Docker Compose.

Run `python -m pytest -q` for unit tests and a real HTTP/Streamlit flow backed by a
temporary SQLite file. To exercise PostgreSQL, set `TEST_DATABASE_URL` to a
**disposable test database** before running the same command. The test creates
and removes a unique schema, exercises dashboard generation/detection/triage,
checks authentication and deduplication, restarts the API, and verifies persisted
incident notes and counts. CI runs this flow against PostgreSQL 16 and builds the
Docker image. This does not establish that a hosted deployment has the correct
secrets or that its dashboard is reachable.

For final hosted acceptance, use a unique simulation seed with `/simulate`, run
`/detect`, triage an incident in the dashboard, restart the API, and confirm the
status, assignee, notes, and event counts remain. Repeating the same simulation
and detection must create no duplicates. In a disposable stack, stop PostgreSQL
and verify `/ready` returns 503; restart it and confirm `/ready` recovers. Never
remove the database volume when testing persistence.
