"""Webhook channel implementation for generic HTTP POST callbacks."""

import hashlib
import hmac
import json
from typing import Any, Optional

from aiohttp import web
from loguru import logger
from pydantic import Field

from nanobot.bus.events import OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels.base import BaseChannel
from nanobot.config.schema import Base


class WebhookConfig(Base):
    """Webhook channel configuration."""

    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 18791
    path: str = "/webhook"
    secret: Optional[str] = None
    allow_from: list[str] = Field(default_factory=lambda: ["*"])
    max_payload_size: int = 1024 * 1024  # 1MB


class WebhookChannel(BaseChannel):
    """
    HTTP/HTTPS Webhook channel.
    Receives generic POST requests and forwards them to the LLM.
    """

    name = "webhook"
    display_name = "Webhook"

    @classmethod
    def default_config(cls) -> dict[str, Any]:
        return WebhookConfig().model_dump(by_alias=True)

    def __init__(self, config: Any, bus: MessageBus):
        if isinstance(config, dict):
            config = WebhookConfig.model_validate(config)
        super().__init__(config, bus)
        self.config: WebhookConfig = config
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None

    async def start(self) -> None:
        """Start the aiohttp server to listen for webhooks."""
        self._running = True
        self._app = web.Application(client_max_size=self.config.max_payload_size)
        self._app.router.add_post(self.config.path, self._handle_post)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        try:
            site = web.TCPSite(self._runner, self.config.host, self.config.port)
            await site.start()
            logger.info(
                "Webhook channel listening on http://{}:{}{}",
                self.config.host,
                self.config.port,
                self.config.path,
            )
        except Exception as e:
            logger.error("Failed to start Webhook server: {}", e)
            self._running = False
            raise

    async def stop(self) -> None:
        """Stop the Webhook server."""
        self._running = False
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self._app = None

    async def send(self, msg: OutboundMessage) -> None:
        """
        Webhooks are primarily inbound. Outbound is logged.
        In a more advanced implementation, this could support a response callback URL.
        """
        logger.info("Webhook [outbound to {}]: {}", msg.chat_id, msg.content)

    async def _handle_post(self, request: web.Request) -> web.Response:
        """Handle incoming HTTP POST request."""
        # 1. DoS mitigation: client_max_size is already handled by aiohttp if configured in Application

        # 2. Authenticate signature if secret is configured
        body = await request.read()
        if self.config.secret:
            signature = request.headers.get("X-Webhook-Signature")
            if not signature:
                logger.warning("Webhook: Missing X-Webhook-Signature header")
                return web.Response(status=401, text="Missing signature")

            # HMAC-SHA256 verification
            mac = hmac.new(
                self.config.secret.encode("utf-8"),
                body,
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(mac, signature):
                logger.warning("Webhook: Invalid signature")
                return web.Response(status=401, text="Invalid signature")

        # 3. Parse JSON body
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            logger.warning("Webhook: Received non-JSON payload")
            return web.Response(status=400, text="Invalid JSON")

        if not isinstance(data, dict):
            logger.warning("Webhook: Received JSON is not a dictionary")
            return web.Response(status=400, text="Invalid payload format")

        # 4. Extract fields with standard fallback logic
        # Supported fields: sender_id, chat_id, content/text
        sender_id = str(data.get("sender_id") or data.get("sender") or "webhook_user")
        chat_id = str(data.get("chat_id") or data.get("chat") or sender_id)
        content = str(data.get("content") or data.get("text") or "")

        if not content:
            logger.warning("Webhook: Empty content in payload from {}", sender_id)
            # We still accept it if there's metadata, but LLM usually needs text

        # 5. Forward to Nanobot message bus
        await self._handle_message(
            sender_id=sender_id,
            chat_id=chat_id,
            content=content,
            metadata={
                "webhook_headers": dict(request.headers),
                "webhook_payload": data
            }
        )

        return web.Response(status=200, text="OK")
