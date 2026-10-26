from sqlalchemy.exc import OperationalError
from backend.main import app, db_session


def test_readiness_checks_database(client):
    assert client.get('/ready').status_code == 200
    class Unavailable:
        def execute(self, statement):
            raise OperationalError('SELECT 1', {}, Exception('offline'))
    def offline():
        yield Unavailable()
    app.dependency_overrides[db_session] = offline
    assert client.get('/ready').status_code == 503
    assert client.get('/health').status_code == 200
