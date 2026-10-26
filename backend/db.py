import os
from sqlalchemy import create_engine, URL
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL and os.getenv('POSTGRES_HOST'):
    DATABASE_URL = URL.create(
        'postgresql+psycopg', username=os.getenv('POSTGRES_USER', 'sentinelguard'),
        password=os.environ['POSTGRES_PASSWORD'], host=os.environ['POSTGRES_HOST'],
        port=int(os.getenv('POSTGRES_PORT', '5432')),
        database=os.getenv('POSTGRES_DB', 'sentinelguard'),
    )
DATABASE_URL = DATABASE_URL or 'sqlite:///./sentinelguard.db'
# Render supplies a postgresql:// URL; select the installed psycopg v3 driver.
if isinstance(DATABASE_URL, str) and DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if str(DATABASE_URL).startswith('sqlite') else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

def initialize():
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)

def session_scope():
    return SessionLocal()

