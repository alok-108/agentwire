"""Drop-in middleware adapters for popular multi-agent frameworks."""

from agentwire.adapters.crewai import CrewAIWire
from agentwire.adapters.langgraph import LangGraphWire

__all__ = ["CrewAIWire", "LangGraphWire"]
