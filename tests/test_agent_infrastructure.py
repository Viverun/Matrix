import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from backend.agents.base_agent import BaseSecurityAgent
from backend.core.request_cache import RequestCache
from backend.agents.auth_agent import AuthenticationAgent
from models.vulnerability import Severity, VulnerabilityType

@pytest.fixture
def mock_http_client():
    client = MagicMock()
    # Mock the stream context manager
    client.stream = MagicMock()
    
    async def mock_aiter_bytes():
        yield b'{"status": "success", "message": "logged in", "user": {"id": 1, "username": "admin"}}'

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = httpx.Headers({"Content-Type": "application/json"})
    mock_response.aiter_bytes = mock_aiter_bytes
    mock_response.url = httpx.URL("http://example.com/login")
    mock_response.is_error = False

    class MockContextManager:
        async def __aenter__(self):
            return mock_response
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    client.stream.return_value = MockContextManager()
    return client

class MockAgent(BaseSecurityAgent):
    def __init__(self, http_client, **kwargs):
        super().__init__(**kwargs)
        self.http_client = http_client
        self.agent_name = "MockAgent"
    
    async def scan(self, target_url, endpoints, **kwargs):
        return []

@pytest.mark.asyncio
async def test_base_agent_json_request(mock_http_client):
    """Verify that BaseSecurityAgent correctly passes JSON payloads to the HTTP client."""
    agent = MockAgent(http_client=mock_http_client)
    url = "http://example.com/api"
    payload = {"key": "value"}
    
    await agent.make_request(url, method="POST", json=payload)
    
    # Check if stream was called with json parameter
    call_args = mock_http_client.stream.call_args
    assert call_args is not None
    assert call_args.kwargs["json"] == payload
    assert call_args.kwargs["data"] is None

@pytest.mark.asyncio
async def test_request_cache_with_json():
    """Verify that RequestCache distinguishes between different JSON payloads."""
    cache = RequestCache()
    url = "http://example.com/api"
    
    payload1 = {"id": 1}
    payload2 = {"id": 2}
    
    await cache.set(url, "POST", "resp1", 200, {}, json=payload1)
    await cache.set(url, "POST", "resp2", 200, {}, json=payload2)
    
    res1 = await cache.get(url, "POST", json=payload1)
    res2 = await cache.get(url, "POST", json=payload2)
    
    assert res1.response_text == "resp1"
    assert res2.response_text == "resp2"

@pytest.mark.asyncio
async def test_auth_agent_json_login(mock_http_client):
    """Verify that AuthenticationAgent tries JSON login if form fails."""
    # First call returns 415 (Unsupported Media Type) for form data
    # Second call returns 200 for JSON data
    
    async def mock_aiter_bytes_415():
        yield b'Use JSON'
        
    async def mock_aiter_bytes_200():
        yield b'{"status": "success", "token": "jwt123", "user": "admin"}'

    resp_415 = MagicMock()
    resp_415.status_code = 415
    resp_415.headers = httpx.Headers({})
    resp_415.aiter_bytes = mock_aiter_bytes_415
    resp_415.url = httpx.URL("http://example.com/login")
    resp_415.is_error = True

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.headers = httpx.Headers({
        "Content-Type": "application/json",
        "Set-Cookie": "session=xyz789"
    })
    
    # Text must contain success indicators: status 200 (given), welcome, dashboard, set-cookie (given)
    success_text = '{"status": "success", "token": "jwt123", "user": "admin", "welcome": "back", "dashboard": "home"}'
    
    async def mock_aiter_bytes_200():
        yield success_text.encode()

    resp_200.aiter_bytes = mock_aiter_bytes_200
    resp_200.url = httpx.URL("http://example.com/login")
    resp_200.is_error = False

    class MockContextManager:
        def __init__(self, resp): self.resp = resp
        async def __aenter__(self): return self.resp
        async def __aexit__(self, *args): pass

    mock_http_client.stream.side_effect = [
        MockContextManager(resp_415),
        MockContextManager(resp_200)
    ]

    from backend.core.request_cache import reset_cache
    reset_cache()

    agent = AuthenticationAgent()
    print(f"DEBUG: AuthenticationAgent imported from: {AuthenticationAgent.__module__}")
    import sys
    print(f"DEBUG: AuthenticationAgent source file: {sys.modules[AuthenticationAgent.__module__].__file__}")
    agent.http_client = mock_http_client
    
    endpoint = {"url": "http://example.com/login"}
    try:
        results = await agent._test_default_credentials(endpoint, [("admin", "admin")])
        print(f"DEBUG: Results: {results}")
    except Exception as e:
        print(f"DEBUG: EXCEPTION IN AGENT: {e}")
        import traceback
        traceback.print_exc()
        raise e
    
    assert results is not None
    assert results.is_vulnerable == True
    assert "json={'username': 'admin', 'password': 'admin'}" in str(mock_http_client.stream.call_args_list[1])
    # Check if second call was JSON
    assert mock_http_client.stream.call_args_list[1].kwargs["json"] == {"username": "admin", "password": "admin"}
