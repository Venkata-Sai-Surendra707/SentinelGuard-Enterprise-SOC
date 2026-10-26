"""Real HTTP + Streamlit flow. TEST_DATABASE_URL enables isolated PostgreSQL coverage."""
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
import requests
from sqlalchemy import create_engine, text
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def service(tmp_path):
    database = os.getenv('TEST_DATABASE_URL')
    schema = 'sg_test_' + uuid.uuid4().hex
    admin = None
    env = dict(os.environ, SENTINELGUARD_API_KEY='integration-key')
    if database:
        database = database.replace('postgresql://', 'postgresql+psycopg://', 1)
        admin = create_engine(database)
        with admin.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA {schema}'))
        env['PGOPTIONS'] = f'-c search_path={schema}'
    else:
        database = f'sqlite:///{tmp_path / "integration.db"}'
    env['DATABASE_URL'] = database
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    process = None
    log = (tmp_path / 'api.log').open('w+')
    def stop():
        nonlocal process
        if process:
            process.terminate()
            process.wait(timeout=10)
            process = None
    def start():
        nonlocal process
        process = subprocess.Popen(
            [sys.executable, '-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', str(port)],
            cwd=ROOT, env=env, stdout=log, stderr=log,
        )
        for _ in range(100):
            try:
                if requests.get(url + '/ready', timeout=1).status_code == 200:
                    return
            except requests.RequestException:
                pass
            if process.poll() is not None:
                break
            time.sleep(.1)
        log.flush(); log.seek(0)
        pytest.fail('API failed to become ready:\n' + log.read())
    try:
        start()
        yield url, stop, start
    finally:
        stop(); log.close()
        if admin:
            with admin.begin() as conn:
                conn.execute(text(f'DROP SCHEMA {schema} CASCADE'))
            admin.dispose()


def test_dashboard_api_persistence(service, monkeypatch):
    url, stop, start = service
    headers = {'X-API-Key': 'integration-key'}
    assert requests.get(url + '/metrics', timeout=5).status_code == 401
    assert requests.get(url + '/metrics', headers={'X-API-Key': 'wrong'}, timeout=5).status_code == 401
    monkeypatch.setenv('API_URL', url)
    monkeypatch.delenv('SENTINELGUARD_API_KEY', raising=False)
    at = AppTest.from_file(str(ROOT / 'frontend/app.py')).run()
    at.sidebar.text_input[1].set_value('integration-key').run()
    at.button[0].click().run()
    assert not at.exception and not at.error
    assert requests.get(url + '/metrics', headers=headers, timeout=5).json()['events'] == 512
    at.button[1].click().run()
    assert not at.exception and not at.error
    incidents = requests.get(url + '/incidents', headers=headers, timeout=5).json()
    assert {i['rule_id'] for i in incidents} == {'SG-001','SG-002','SG-003','SG-004','SG-005'}
    selected = at.selectbox[0].value
    assert requests.get(url + f'/incidents/{selected}/analysis', headers=headers, timeout=5).json()['evidence_ids']
    at.selectbox[1].set_value('investigating')
    next(v for v in at.text_input if v.label == 'Assignee').set_value('analyst1')
    at.text_area[0].set_value('Persistence check')
    next(b for b in at.button if b.label == 'Save investigation').click().run()
    assert not at.exception and not at.error
    assert requests.post(url + '/simulate?count=500&seed=42', headers=headers, timeout=5).json()['inserted'] == 0
    assert requests.post(url + '/detect', headers=headers, timeout=5).json()['new_incidents'] == 0
    stop(); start()
    rows = requests.get(url + '/incidents', headers=headers, timeout=5).json()
    row = next(i for i in rows if i['id'] == selected)
    assert row['status'] == 'investigating' and row['assignee'] == 'analyst1'
    assert row['notes'][0]['text'] == 'Persistence check'
    assert requests.get(url + '/metrics', headers=headers, timeout=5).json()['events'] == 512
    at.run()
    assert not at.exception and not at.error
    assert at.get('download_button')
