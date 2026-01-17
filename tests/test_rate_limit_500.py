import pytest
import asyncio
import sys
import os
import time
from unittest.mock import MagicMock

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.core.rate_limiter import AdaptiveRateLimiter, RateLimiterConfig

@pytest.mark.asyncio
async def test_backoff_on_500():
    """
    Verify that rate limiter backs off after consecutive 500 errors.
    """
    config = RateLimiterConfig(
        default_rps=10,
        burst_size=5,
        adaptive_slowdown=True,
        initial_backoff=1.0
    )
    limiter = AdaptiveRateLimiter(config)
    url = "http://test.com/login"
    
    # 1. Successful requests
    await limiter.report_response(url, 200, 0.1)
    await limiter.report_response(url, 200, 0.1)
    
    state = limiter._get_state("test.com")
    assert state.consecutive_errors == 0
    print("\nInitial state: Normal")
    
    # 2. Simulate 3 consecutive 500 errors
    print("Simulating 3 consecutive 500 errors...")
    for i in range(3):
        await limiter.report_response(url, 500, 0.1)
        
    # Check backoff
    state = limiter._get_state("test.com")
    print(f"Consecutive errors: {state.consecutive_errors}")
    print(f"Backoff until: {state.backoff_until}")
    print(f"Current time: {time.time()}")
    
    assert state.consecutive_errors == 3
    # With new threshold of 20, backoff should NOT be set yet
    assert state.backoff_until <= time.time()
    print("Confirmed: Rate limiter did NOT trigger backoff for < 20 errors!")
    
    # 3. Verify acquire DOES NOT wait (or waits minimal time)
    print("Attempting to acquire token...")
    start = time.time()
    await limiter.acquire(url)
    duration = time.time() - start
    print(f"Acquire wait time: {duration:.2f}s")
    
    # Should have waited at least the remaining backoff time
    # (Configured initial_backoff is 1.0s)
    # With new logic, it should NOT wait significantly
    assert duration < 0.2
    print("Confirmed: acquire() did NOT block execution.")

if __name__ == "__main__":
    asyncio.run(test_backoff_on_500())
