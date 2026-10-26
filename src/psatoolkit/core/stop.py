"""Emergency-stop token shared by the engine, checks and subprocesses."""

from __future__ import annotations

import threading


class StopRequested(Exception):
    """Raised inside a check when the operator pressed Stop."""


class StopToken:
    def __init__(self) -> None:
        self._event = threading.Event()
        self.reason = ""

    def stop(self, reason: str = "Operator requested emergency stop") -> None:
        if not self._event.is_set():
            self.reason = reason
            self._event.set()

    @property
    def stopped(self) -> bool:
        return self._event.is_set()

    def raise_if_stopped(self) -> None:
        if self._event.is_set():
            raise StopRequested(self.reason)

    def wait(self, timeout: float) -> bool:
        """Sleep up to ``timeout`` seconds; returns True if stop was requested."""
        return self._event.wait(timeout)
