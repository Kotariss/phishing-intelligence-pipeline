from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

try:
    from ..config import get_settings
except (ImportError, ValueError):
    from config import get_settings

DATABASE_URL = get_settings().DATABASE_URL

# If PostgreSQL connection string uses postgres:// or postgresql://, ensure psycopg2 driver for SQLAlchemy
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    # timeout: parallel evaluation workers (separate processes) wait for the write lock instead of failing
    connect_args = {"check_same_thread": False, "timeout": 60}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _add_missing_columns():
    """Lightweight forward migration: adds columns introduced after a table was created."""
    insp = inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            col_type = column.type.compile(dialect=engine.dialect)
            with engine.begin() as conn:
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {column.name} {col_type}'))


def init_db():
    # Import models so they are registered on Base.metadata before create_all.
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()
    _retire_legacy_signatures()


def _retire_legacy_signatures():
    """Rules produced by pre-1.1 versions (no all_of/any_of predicates, never regression-tested)
    must not be shipped: they are kept for history with status LEGACY_UNVERIFIED."""
    from .models import LSignatureModel
    db = SessionLocal()
    try:
        changed = 0
        for sig in db.query(LSignatureModel).filter(LSignatureModel.status == "ACTIVE_VERIFIED").all():
            preds = (sig.rule_json or {}).get("predicates") or {}
            if "all_of" not in preds and "any_of" not in preds:
                sig.status = "LEGACY_UNVERIFIED"
                changed += 1
        if changed:
            db.commit()
    finally:
        db.close()
