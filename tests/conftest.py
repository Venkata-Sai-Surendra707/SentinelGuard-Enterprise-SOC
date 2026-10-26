import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from backend.db import Base
from backend.main import app, db_session

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('SENTINELGUARD_API_KEY','test-secret')
    monkeypatch.setattr('backend.main.initialize', lambda: None)
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    local=sessionmaker(bind=engine,expire_on_commit=False)
    def override():
        with local() as db: yield db
    app.dependency_overrides[db_session]=override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    engine.dispose()

