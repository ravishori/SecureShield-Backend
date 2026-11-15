"""Unit-test guard: unit tests never open a database connection - not even a failing one.

Every entry point that can reach a database server is replaced by a function that (a) records the attempt and (b) raises
``DatabaseConnectionBlocked`` immediately. The autouse fixture then FAILS the test at teardown if any attempt was recorded, so a
test cannot pass by swallowing the error (the error logger and several routers catch ``Exception``).

Blocked entry points: ``asyncpg.connect`` / ``asyncpg.connection.connect`` / ``asyncpg.create_pool`` (which is also what
SQLAlchemy's asyncpg dialect calls), ``socket.socket.connect``/``connect_ex`` and the asyncio ``create_connection`` /
``sock_connect`` for the well-known PostgreSQL ports (5432, 5433, 6543), and the one production helper that connects on purpose,
``app.db_identity.verify_connected_database``. Tests that need a "database" use the ``no_database`` fixture (an in-memory fake).
Loopback connections to other ports (a test's own throw-away HTTP server) are unaffected.
"""

import asyncio
import os
import socket

import pytest

DB_PORTS = frozenset({5432, 5433, 6543})
SESSION_ATTEMPTS: list[
    tuple[str, str]
] = []  # (test id, entry point) for every blocked attempt in the whole run
SELF_TESTS = "test_final_corrections.py::TestUnitConnectionGuard"  # the guard's own tests attempt on purpose, then clear


def pytest_terminal_summary(terminalreporter):
    outside = [a for a in SESSION_ATTEMPTS if SELF_TESTS not in a[0]]
    terminalreporter.write_line(
        f"DATABASE CONNECTION ATTEMPTS by tests other than the guard's own self-tests: {len(outside)}"
        f" (self-tests deliberately provoked and cleared: {len(SESSION_ATTEMPTS) - len(outside)})"
    )
    for test_id, kind in outside:
        terminalreporter.write_line(f"  ATTEMPT {kind} <- {test_id}")


class DatabaseConnectionBlocked(AssertionError):
    """A unit test tried to open a database connection."""


@pytest.fixture(autouse=True)
def _no_database_connections(monkeypatch):
    attempts: list[str] = []

    def blocked(kind: str):
        attempts.append(kind)
        SESSION_ATTEMPTS.append((os.environ.get("PYTEST_CURRENT_TEST", "?"), kind))
        raise DatabaseConnectionBlocked(
            f"unit tests must not connect to a database ({kind}); use the no_database fixture or mock the call"
        )

    async def refuse(*args, **kwargs):
        blocked("app.db_identity.verify_connected_database")

    async def refuse_connect(*args, **kwargs):
        blocked("asyncpg.connect")

    async def refuse_pool(*args, **kwargs):
        blocked("asyncpg.create_pool")

    import asyncpg
    import asyncpg.connection

    # Run every unit test on the standard asyncio loop. An earlier test can leave a different loop policy installed process-wide
    # (a real uvicorn server on Linux installs uvloop's), and the loop-level patches below cannot patch uvloop's compiled loop:
    # the guard would then silently not apply. Whatever was installed is put back afterwards.
    previous_policy = asyncio.get_event_loop_policy()
    asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())

    monkeypatch.setattr("app.db_identity.verify_connected_database", refuse)
    monkeypatch.setattr(asyncpg, "connect", refuse_connect)
    monkeypatch.setattr(asyncpg.connection, "connect", refuse_connect)
    monkeypatch.setattr(asyncpg, "create_pool", refuse_pool)

    def _port(addr):
        try:
            return int(addr[1])
        except Exception:  # noqa: BLE001
            return None

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def connect(self, addr):
        if _port(addr) in DB_PORTS:
            blocked(f"socket.connect:{_port(addr)}")
        return original_connect(self, addr)

    def connect_ex(self, addr):
        if _port(addr) in DB_PORTS:
            blocked(f"socket.connect_ex:{_port(addr)}")
        return original_connect_ex(self, addr)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)

    original_create_connection = asyncio.BaseEventLoop.create_connection
    original_sock_connect = asyncio.BaseEventLoop.sock_connect

    async def create_connection(self, protocol_factory, host=None, port=None, **kw):
        if port is not None and _port((host, port)) in DB_PORTS:
            blocked(f"loop.create_connection:{port}")
        return await original_create_connection(
            self, protocol_factory, host, port, **kw
        )

    async def sock_connect(self, sock, address):
        if _port(address) in DB_PORTS:
            blocked(f"loop.sock_connect:{_port(address)}")
        return await original_sock_connect(self, sock, address)

    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", create_connection)
    monkeypatch.setattr(asyncio.BaseEventLoop, "sock_connect", sock_connect)

    try:
        yield attempts
    finally:
        asyncio.set_event_loop_policy(previous_policy)
    assert not attempts, f"database connection attempts during a unit test: {attempts}"


class _EmptyResult:
    """What every query returns from the in-memory fake: nothing."""

    rowcount = 0

    def scalar_one_or_none(self):
        return None

    def scalar_one(self):
        raise LookupError("no rows (in-memory fake)")

    def scalar(self):
        return None

    def first(self):
        return None

    def one_or_none(self):
        return None

    def all(self):
        return []

    def fetchall(self):
        return []

    def scalars(self):
        return self

    def mappings(self):
        return self

    def __iter__(self):
        return iter(())


class NoDbSession:
    """An in-memory stand-in for ``AsyncSession``: every query finds nothing and nothing is stored."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, *a, **k):
        return _EmptyResult()

    async def get(self, *a, **k):
        return None

    async def commit(self):
        return None

    async def rollback(self):
        return None

    async def close(self):
        return None

    async def flush(self):
        return None

    async def refresh(self, *a, **k):
        return None

    def add(self, *a, **k):
        return None

    def add_all(self, *a, **k):
        return None


@pytest.fixture
def no_database(monkeypatch):
    """Route every database access of the real app (dependency injection AND the sessions the services open themselves) to an
    in-memory fake, so a test can serve real requests without any database server."""
    from app import database
    from app.main import app

    async def fake_get_db():
        yield NoDbSession()

    app.dependency_overrides[database.get_db] = fake_get_db
    monkeypatch.setattr(database, "AsyncSessionLocal", lambda: NoDbSession())
    yield
    app.dependency_overrides.pop(database.get_db, None)
