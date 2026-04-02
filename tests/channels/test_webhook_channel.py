import hashlib
import hmac
import json
import pytest
import aiohttp
from nanobot.bus.queue import MessageBus
from nanobot.channels.webhook import WebhookChannel, WebhookConfig

@pytest.mark.asyncio
async def test_webhook_inbound_success():
    bus = MessageBus()
    config = WebhookConfig(
        enabled=True,
        port=18792,
        path="/test-webhook",
        allow_from=["*"]
    )
    channel = WebhookChannel(config, bus)
    
    await channel.start()
    
    try:
        async with aiohttp.ClientSession() as session:
            payload = {
                "sender_id": "test_user",
                "content": "Hello Nanobot"
            }
            async with session.post(
                "http://127.0.0.1:18792/test-webhook",
                json=payload
            ) as resp:
                assert resp.status == 200
                assert await resp.text() == "OK"
        
        # Verify message reached the bus
        msg = await bus.consume_inbound()
        assert msg.sender_id == "test_user"
        assert msg.content == "Hello Nanobot"
        assert msg.channel == "webhook"
        
    finally:
        await channel.stop()

@pytest.mark.asyncio
async def test_webhook_signature_verification():
    bus = MessageBus()
    secret = "super-secret"
    config = WebhookConfig(
        enabled=True,
        port=18793,
        secret=secret,
        allow_from=["*"]
    )
    channel = WebhookChannel(config, bus)
    
    await channel.start()
    
    try:
        async with aiohttp.ClientSession() as session:
            payload = {"content": "Secret message"}
            body = json.dumps(payload).encode()
            
            # 1. No signature -> 401
            async with session.post(
                "http://127.0.0.1:18793/webhook",
                data=body
            ) as resp:
                assert resp.status == 401
            
            # 2. Wrong signature -> 401
            async with session.post(
                "http://127.0.0.1:18793/webhook",
                data=body,
                headers={"X-Webhook-Signature": "wrong"}
            ) as resp:
                assert resp.status == 401
            
            # 3. Correct signature -> 200
            signature = hmac.new(
                secret.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            async with session.post(
                "http://127.0.0.1:18793/webhook",
                data=body,
                headers={"X-Webhook-Signature": signature}
            ) as resp:
                assert resp.status == 200
        
    finally:
        await channel.stop()

@pytest.mark.asyncio
async def test_webhook_invalid_json():
    bus = MessageBus()
    config = WebhookConfig(
        enabled=True,
        port=18794,
        allow_from=["*"]
    )
    channel = WebhookChannel(config, bus)
    await channel.start()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://127.0.0.1:18794/webhook",
                data="not a json"
            ) as resp:
                assert resp.status == 400
    finally:
        await channel.stop()

@pytest.mark.asyncio
async def test_webhook_max_payload():
    bus = MessageBus()
    config = WebhookConfig(
        enabled=True,
        port=18795,
        max_payload_size=10,  # 10 bytes
        allow_from=["*"]
    )
    channel = WebhookChannel(config, bus)
    await channel.start()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://127.0.0.1:18795/webhook",
                json={"too_long": "this is more than 10 bytes"}
            ) as resp:
                assert resp.status == 413
    finally:
        await channel.stop()
