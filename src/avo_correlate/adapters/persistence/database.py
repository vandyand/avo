"""Database initialization, SQLite hardening, and transaction factory."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

_IMMUTABLE_TRIGGER_SQL = (
    """
    CREATE TRIGGER IF NOT EXISTS events_no_update
    BEFORE UPDATE ON events
    BEGIN
      SELECT RAISE(ABORT, 'events are immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS events_no_delete
    BEFORE DELETE ON events
    BEGIN
      SELECT RAISE(ABORT, 'events are immutable');
    END
    """,
)


class Database:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.engine = create_engine(f"sqlite:///{path.as_posix()}", future=True)
        event.listen(self.engine, "connect", self._configure_sqlite)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @staticmethod
    def _configure_sqlite(dbapi_connection: sqlite3.Connection, _: object) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    def initialize(self) -> None:
        with self.engine.begin() as connection:
            configuration = Config()
            configuration.set_main_option(
                "script_location", str(Path(__file__).parent / "migrations")
            )
            configuration.set_main_option("sqlalchemy.url", str(self.engine.url))
            configuration.attributes["connection"] = connection
            command.upgrade(configuration, "head")
            for statement in _IMMUTABLE_TRIGGER_SQL:
                connection.execute(text(statement))

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        with self._sessions.begin() as session:
            yield session

    def dispose(self) -> None:
        self.engine.dispose()


def sqlite_foreign_keys_enabled(engine: Engine) -> bool:
    with engine.connect() as connection:
        return bool(connection.execute(text("PRAGMA foreign_keys")).scalar_one())
