"""Persistent replay & idempotency state store alias (`from swarmwire.state import SqliteStateStore`)."""

from agentwire.state import SqliteStateStore, StateStore

__all__ = ["SqliteStateStore", "StateStore"]
