"""
LiveHub: fan-out of sanitized pipeline events to live subscribers (WS /ws/live).

One-way and non-blocking. The runtime publishes after a pipeline step has been
persisted; subscribers only receive. publish() never awaits and never raises:
each subscriber has a bounded queue, and when it is full the oldest message is
dropped, so a slow or stalled client can never delay or alter the security
pipeline. Nothing a subscriber sends reaches this hub.

Messages follow the LiveMessage contract (frontend/src/types/api.ts): a type, an
ISO timestamp and a payload built from the public read schemas only.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class LiveMessageType(StrEnum):
    TELEMETRY = "telemetry"
    DETECTION_EVENT = "detection_event"
    THREAT_SCORE = "threat_score"
    DEFENSE_STATE_CHANGE = "defense_state_change"
    RESPONSE_ACTION = "response_action"


class SubscriberLimitError(RuntimeError):
    """The configured number of live subscribers is already connected."""


# Queued to every subscriber when the hub closes (the runtime stopped or was
# replaced by a demo reset): the stream ends and the client reconnects.
CLOSED: None = None

LiveQueue = asyncio.Queue[dict[str, Any] | None]


class LiveHub:
    def __init__(self, *, max_subscribers: int, queue_size: int) -> None:
        self._max = max_subscribers
        self._queue_size = queue_size
        self._subscribers: set[LiveQueue] = set()
        self._closed = False
        self.published = 0
        self.dropped = 0

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def closed(self) -> bool:
        return self._closed

    def publish(self, kind: LiveMessageType, payload: dict[str, Any]) -> None:
        """Queue one message for every subscriber. Never blocks, never raises."""
        if self._closed:
            return
        message = {
            "type": kind.value,
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": payload,
        }
        self.published += 1
        for queue in tuple(self._subscribers):
            self._put(queue, message)

    def close(self) -> None:
        """End every subscription. Later publishes and subscribes are refused."""
        self._closed = True
        for queue in tuple(self._subscribers):
            self._put(queue, CLOSED)

    def _put(self, queue: LiveQueue, item: dict[str, Any] | None) -> None:
        if queue.full():
            queue.get_nowait()
            self.dropped += 1
        queue.put_nowait(item)

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[LiveQueue]:
        if self._closed:
            raise SubscriberLimitError("live hub is closed")
        if len(self._subscribers) >= self._max:
            raise SubscriberLimitError("live subscriber limit reached")
        queue: LiveQueue = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers.add(queue)
        logger.info("Live: subscriber connected (%d active)", len(self._subscribers))
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)
            logger.info("Live: subscriber disconnected (%d active)", len(self._subscribers))
