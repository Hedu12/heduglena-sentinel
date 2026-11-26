"""
WS /ws/live: a one-way stream of sanitized pipeline events (master spec §13.3).

Clients only receive LiveMessage objects built from the public read models.
Anything a client sends is read and discarded; it never reaches the hub or the
pipeline. A browser Origin other than the configured frontend origin is refused
(cross-site WebSocket hijacking); non-browser clients send no Origin. A
disconnect ends only that client's subscription, and a client may reconnect at
any time. HTTP polling of /api/v1 remains the fallback (P-04).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.config import settings
from core.live import CLOSED, SubscriberLimitError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["live"])

# RFC 6455 close codes.
_POLICY_VIOLATION = 1008
_SERVICE_RESTART = 1012
_TRY_AGAIN_LATER = 1013


async def _discard_incoming(websocket: WebSocket) -> None:
    """Read and drop client messages until the client disconnects."""
    with contextlib.suppress(WebSocketDisconnect):
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                return


async def _stream(websocket: WebSocket, queue: asyncio.Queue[dict[str, Any] | None]) -> bool:
    """Forward messages until the client leaves (False) or the hub closes (True)."""
    receiver = asyncio.create_task(_discard_incoming(websocket))
    try:
        while True:
            getter = asyncio.create_task(queue.get())
            done, _ = await asyncio.wait({getter, receiver}, return_when=asyncio.FIRST_COMPLETED)
            if getter not in done:
                getter.cancel()
                return False
            message = getter.result()
            if message is CLOSED:
                return True
            await websocket.send_json(message)
    except (WebSocketDisconnect, RuntimeError) as exc:
        # The client went away mid-send; ending its subscription is the whole handling.
        logger.debug("Live: client disconnected during send (%s)", type(exc).__name__)
        return False
    finally:
        receiver.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await receiver


@router.websocket("/ws/live")
async def live(websocket: WebSocket) -> None:
    origin = websocket.headers.get("origin")
    if origin is not None and origin != settings.frontend_origin:
        await websocket.close(code=_POLICY_VIOLATION)
        return
    runtime = getattr(websocket.app.state, "runtime", None)
    if runtime is None:
        await websocket.close(code=_TRY_AGAIN_LATER)
        return
    try:
        async with runtime.live.subscribe() as queue:
            await websocket.accept()
            hub_closed = await _stream(websocket, queue)
    except SubscriberLimitError:
        await websocket.close(code=_TRY_AGAIN_LATER)
        return
    if hub_closed:
        # The runtime stopped or a demo reset replaced it: tell the client to reconnect.
        with contextlib.suppress(WebSocketDisconnect, RuntimeError):
            await websocket.close(code=_SERVICE_RESTART)
