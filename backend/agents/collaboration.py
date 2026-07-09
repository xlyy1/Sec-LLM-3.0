"""Agent collaboration via shared blackboard for multi-agent orchestration."""
from datetime import datetime, timezone
from typing import Any, Dict, List


class Blackboard:
    """Thread-safe shared memory for agent collaboration.

    ReconAgent publishes discoveries; ExploitAgent reads and chains them;
    ReportAgent aggregates everything.
    """

    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._history: List[Dict[str, Any]] = []

    def publish(self, key: str, value: Any, source: str = "") -> None:
        """Publish a discovery to the blackboard."""
        self._data[key] = value
        self._history.append({
            "key": key,
            "value": value,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def get_all(self) -> Dict[str, Any]:
        return dict(self._data)

    def get_by_source(self, source: str) -> Dict[str, Any]:
        return {k: v for k, v in self._data.items()
                if any(h["source"] == source and h["key"] == k for h in self._history)}

    def list_keys(self) -> List[str]:
        return sorted(self._data.keys())

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    def clear(self) -> None:
        self._data.clear()
        self._history.clear()
