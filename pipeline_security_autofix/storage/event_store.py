from __future__ import annotations

import json
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass
class StoredEvent:
    event_id: str
    received_at: str
    payload: dict[str, Any]
    raw_body: str
    console_text: str
    local_repo_path: str | None = None
    analysis: dict[str, Any] | None = None
    proposal: dict[str, Any] | None = None
    apply_result: dict[str, Any] | None = None


class EventStore:
    def __init__(self, events_file: Path, max_events: int = 200) -> None:
        self.events_file = events_file
        self.max_events = max_events
        self._lock = Lock()
        self._events: deque[StoredEvent] = deque(maxlen=max_events)
        self._load()

    def _load(self) -> None:
        self.events_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.events_file.exists():
            self.events_file.touch()
            return
        with self.events_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                self._events.append(StoredEvent(**record))

    def _persist(self) -> None:
        with self.events_file.open("w", encoding="utf-8") as handle:
            for event in self._events:
                handle.write(json.dumps(asdict(event), ensure_ascii=False))
                handle.write("\n")

    def add(self, event: StoredEvent) -> None:
        with self._lock:
            self._events.append(event)
            self._persist()

    def save(self, event: StoredEvent) -> None:
        with self._lock:
            for index, existing in enumerate(self._events):
                if existing.event_id == event.event_id:
                    self._events[index] = event
                    self._persist()
                    return
            self._events.append(event)
            self._persist()

    def list_events(self) -> list[StoredEvent]:
        with self._lock:
            events = list(self._events)
        events.reverse()
        return events

    def get(self, event_id: str) -> StoredEvent | None:
        with self._lock:
            for event in reversed(self._events):
                if event.event_id == event_id:
                    return event
        return None

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._persist()
