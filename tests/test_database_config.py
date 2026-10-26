import os
import subprocess
import sys


def test_separate_credentials_preserve_reserved_characters():
    env = dict(os.environ, POSTGRES_HOST='db', POSTGRES_PASSWORD='p@ss:/?#%word', POSTGRES_USER='sentinelguard')
    env.pop('DATABASE_URL', None)
    subprocess.run([sys.executable, '-c', "from backend.db import engine; assert engine.url.password == 'p@ss:/?#%word'; assert engine.url.host == 'db'; assert engine.url.drivername == 'postgresql+psycopg'"], env=env, check=True)
