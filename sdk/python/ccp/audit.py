"""A local, private audit log (§16, §26.1).

Events are kept in memory and, optionally, appended to a JSON-lines file.
The log is local by default and never uploaded.
"""

import json
import threading
from datetime import datetime, timezone


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditLog:
    def __init__(self, path=None):
        self._events = []
        self._lock = threading.Lock()
        self._path = path

    def append(self, event):
        record = dict(event)
        record.setdefault("at", utcnow())
        with self._lock:
            self._events.append(record)
            if self._path:
                with open(self._path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False,
                                            sort_keys=True) + "\n")
        return record

    def events(self):
        with self._lock:
            return list(self._events)

    def __len__(self):
        with self._lock:
            return len(self._events)
