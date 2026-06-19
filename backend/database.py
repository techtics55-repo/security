from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import settings

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    import backend.models
    Base.metadata.create_all(bind=engine)
    try:
        from sqlalchemy import inspect, text as sa_text
        inspector = inspect(engine)
        columns = [c["name"] for c in inspector.get_columns("users")]
        if "google_id" not in columns:
            with engine.connect() as conn:
                conn.execute(sa_text("ALTER TABLE users ADD COLUMN google_id VARCHAR"))
                conn.commit()
    except Exception:
        pass
