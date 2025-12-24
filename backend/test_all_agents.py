"""
Test Script for All Security Agents
Tests all registered agents with their new features.
"""
import asyncio
import sys
from datetime import datetime

# Add backend to path
sys.path.insert(0, '.')

from agents.orchestrator import AgentOrchestrator
from agents.sql_injection_agent import SQLInjectionAgent
from agents.xss_agent import XSSAgent
from agents.csrf_agent import CSRFAgent
from agents.ssrf_agent import SSRFAgent
from agents.command_injection_agent import CommandInjectionAgent
from agents.api_security_agent import APISecurityAgent
from agents.auth_agent import AuthenticationAgent
from core.rate_limiter import get_rate_limiter, RateLimiterConfig, configure_rate_limiter
from core.request_cache import get_request_cache, CacheConfig, configure_cache
from core.scan_context import ScanContext


async def test_individual_agents():
    """Test each agent individually with sample endpoints."""
    print("=" * 80)
    print("TESTING INDIVIDUAL AGENTS")
    print("=" * 80)
    
    # Sample endpoints for testing
    test_endpoints = [
        {
            "url": "http://testphp.vulnweb.com/artists.php",
            "method": "GET",
            "params": {"artist": "1"}
        },
        {
            "url": "http://testphp.vulnweb.com/listproducts.php",
            "method": "GET",
            "params": {"cat": "1"}
        },
        {
            "url": "http://testphp.vulnweb.com/search.php",
            "method": "GET",
            "params": {"searchFor": "test"}
        },
        {
            "url": "http://testphp.vulnweb.com/login.php",
            "method": "POST",
            "params": {"uname": "admin", "pass": "password"}
        }
    ]
    
    # Test SQL Injection Agent
    print("\n--- Testing SQL Injection Agent ---")
    sqli_agent = SQLInjectionAgent()
    try:
        sqli_results = await sqli_agent.scan(
            target_url="http://testphp.vulnweb.com",
            endpoints=test_endpoints[:2],
            technology_stack=["PHP", "MySQL"]
        )
        print(f"SQLi Results: {len(sqli_results)} vulnerabilities found")
        for result in sqli_results:
            print(f"  - {result.title} (Confidence: {result.confidence}%)")
        
        # Show stats
        stats = sqli_agent.get_request_stats()
        print(f"  Stats: {stats['total_requests']} requests, "
              f"{stats['cached_responses']} cached ({stats['cache_hit_rate']:.1f}% hit rate)")
    except Exception as e:
        print(f"  Error: {e}")
    finally:
        await sqli_agent.close()
    
    # Test XSS Agent
    print("\n--- Testing XSS Agent ---")
    xss_agent = XSSAgent()
    try:
        xss_results = await xss_agent.scan(
            target_url="http://testphp.vulnweb.com",
            endpoints=test_endpoints[2:3],
            technology_stack=["PHP", "JavaScript"]
        )
        print(f"XSS Results: {len(xss_results)} vulnerabilities found")
        for result in xss_results:
            print(f"  - {result.title} (Confidence: {result.confidence}%)")
        
        stats = xss_agent.get_request_stats()
        print(f"  Stats: {stats['total_requests']} requests, "
              f"{stats['cached_responses']} cached ({stats['cache_hit_rate']:.1f}% hit rate)")
    except Exception as e:
        print(f"  Error: {e}")
    finally:
        await xss_agent.close()
    
    # Test CSRF Agent
    print("\n--- Testing CSRF Agent ---")
    csrf_agent = CSRFAgent()
    try:
        csrf_results = await csrf_agent.scan(
            target_url="http://testphp.vulnweb.com",
            endpoints=test_endpoints[3:],
            technology_stack=["PHP"]
        )
        print(f"CSRF Results: {len(csrf_results)} vulnerabilities found")
        for result in csrf_results:
            print(f"  - {result.title} (Confidence: {result.confidence}%)")
    except Exception as e:
        print(f"  Error: {e}")
    finally:
        await csrf_agent.close()
    
    # Test SSRF Agent
    print("\n--- Testing SSRF Agent ---")
    ssrf_agent = SSRFAgent()
    try:
        ssrf_endpoints = [
            {
                "url": "http://testphp.vulnweb.com/showimage.php",
                "method": "GET",
                "params": {"file": "test.jpg"}
            }
        ]
        ssrf_results = await ssrf_agent.scan(
            target_url="http://testphp.vulnweb.com",
            endpoints=ssrf_endpoints,
            technology_stack=["PHP"]
        )
        print(f"SSRF Results: {len(ssrf_results)} vulnerabilities found")
        for result in ssrf_results:
            print(f"  - {result.title} (Confidence: {result.confidence}%)")
    except Exception as e:
        print(f"  Error: {e}")
    finally:
        await ssrf_agent.close()
    
    # Test Command Injection Agent
    print("\n--- Testing Command Injection Agent ---")
    cmd_agent = CommandInjectionAgent()
    try:
        cmd_endpoints = [
            {
                "url": "http://testphp.vulnweb.com/ping.php",
                "method": "GET",
                "params": {"host": "localhost"}
            }
        ]
        cmd_results = await cmd_agent.scan(
            target_url="http://testphp.vulnweb.com",
            endpoints=cmd_endpoints,
            technology_stack=["PHP"]
        )
        print(f"Command Injection Results: {len(cmd_results)} vulnerabilities found")
        for result in cmd_results:
            print(f"  - {result.title} (Confidence: {result.confidence}%)")
    except Exception as e:
        print(f"  Error: {e}")
    finally:
        await cmd_agent.close()
    
    # Test API Security Agent
    print("\n--- Testing API Security Agent ---")
    api_agent = APISecurityAgent()
    try:
        api_endpoints = [
            {
                "url": "http://testphp.vulnweb.com/",
                "method": "GET",
                "params": {}
            }
        ]
        api_results = await api_agent.scan(
            target_url="http://testphp.vulnweb.com",
            endpoints=api_endpoints,
            technology_stack=["PHP"]
        )
        print(f"API Security Results: {len(api_results)} vulnerabilities found")
        for result in api_results:
            print(f"  - {result.title} (Severity: {result.severity.value})")
    except Exception as e:
        print(f"  Error: {e}")
    finally:
        await api_agent.close()


async def test_orchestrator():
    """Test the agent orchestrator with all agents."""
    print("\n" + "=" * 80)
    print("TESTING AGENT ORCHESTRATOR")
    print("=" * 80)
    
    # Create orchestrator instance
    orchestrator = AgentOrchestrator()
    
    # Sample endpoints
    endpoints = [
        {
            "url": "http://testphp.vulnweb.com/artists.php",
            "method": "GET",
            "params": {"artist": "1"}
        },
        {
            "url": "http://testphp.vulnweb.com/search.php",
            "method": "GET",
            "params": {"searchFor": "test"}
        }
    ]
    
    print(f"\nRegistered Agents: {len(orchestrator.agents)}")
    for agent_name in orchestrator.agents.keys():
        print(f"  - {agent_name}")
    
    print("\nStarting comprehensive scan...")
    try:
        results = await orchestrator.run_scan(
            target_url="http://testphp.vulnweb.com",
            endpoints=endpoints,
            technology_stack=["PHP", "MySQL", "JavaScript"],
            scan_id=999
        )
        
        print(f"\n--- Scan Complete ---")
        print(f"Total Vulnerabilities Found: {len(results)}")
        
        # Group by severity
        from models.vulnerability import Severity
        by_severity = {s: [] for s in Severity}
        for result in results:
            by_severity[result.severity].append(result)
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = len(by_severity[severity])
            if count > 0:
                print(f"\n{severity.value.upper()}: {count} findings")
                for result in by_severity[severity][:3]:  # Show first 3
                    print(f"  - {result.title} ({result.agent_name})")
        
        # Show scan metrics
        if hasattr(orchestrator, 'scan_metrics'):
            metrics = orchestrator.scan_metrics
            print(f"\n--- Scan Metrics ---")
            print(f"Total Findings: {metrics.get('total_findings', 0)}")
            print(f"High Confidence: {metrics.get('high_confidence_findings', 0)}")
            print(f"Average Signal Quality: {metrics.get('average_signal_quality', 0):.2f}")
            print(f"Correlation Chains: {metrics.get('correlation_chains_found', 0)}")
        
    except Exception as e:
        print(f"Error during orchestrated scan: {e}")
        import traceback
        traceback.print_exc()


async def test_rate_limiting():
    """Test the rate limiting functionality."""
    print("\n" + "=" * 80)
    print("TESTING RATE LIMITING")
    print("=" * 80)
    
    # Configure aggressive rate limiting for testing
    config = RateLimiterConfig(
        default_rps=5.0,  # 5 requests per second
        burst_size=3,
        jitter_enabled=True
    )
    configure_rate_limiter(config)
    
    rate_limiter = get_rate_limiter()
    
    test_url = "http://example.com/test"
    
    print(f"\nMaking 10 requests to {test_url}")
    print("Rate limit: 5 RPS with burst of 3")
    
    start_time = asyncio.get_event_loop().time()
    
    for i in range(10):
        wait_time = await rate_limiter.acquire(test_url)
        elapsed = asyncio.get_event_loop().time() - start_time
        print(f"Request {i+1}: waited {wait_time:.3f}s (total elapsed: {elapsed:.3f}s)")
    
    # Get stats
    stats = rate_limiter.get_stats(test_url)
    print(f"\n--- Rate Limiter Stats ---")
    for key, value in stats.items():
        print(f"{key}: {value}")


async def test_caching():
    """Test the request caching functionality."""
    print("\n" + "=" * 80)
    print("TESTING REQUEST CACHE")
    print("=" * 80)
    
    # Configure cache
    from core.request_cache import CachePolicy
    config = CacheConfig(
        max_entries=100,
        default_ttl=60.0,
        policy=CachePolicy.LRU,
        enabled=True
    )
    configure_cache(config)
    
    cache = get_request_cache()
    
    # Simulate caching some responses
    print("\nCaching 5 responses...")
    for i in range(5):
        await cache.set(
            url=f"http://example.com/page{i}",
            method="GET",
            response_text=f"Response body for page {i}" * 100,
            status_code=200,
            response_headers={"Content-Type": "text/html"}
        )
    
    # Try to retrieve them
    print("Retrieving cached responses...")
    for i in range(7):  # Try 7, only 5 should hit
        cached = await cache.get(url=f"http://example.com/page{i}", method="GET")
        if cached:
            print(f"  Cache HIT for page{i}")
        else:
            print(f"  Cache MISS for page{i}")
    
    # Show stats
    stats = cache.get_stats()
    print(f"\n--- Cache Stats ---")
    for key, value in stats.items():
        print(f"{key}: {value}")


async def test_waf_evasion():
    """Test WAF evasion techniques."""
    print("\n" + "=" * 80)
    print("TESTING WAF EVASION")
    print("=" * 80)
    
    from agents.waf_evasion import WAFEvasionMixin, ObfuscationType
    
    # Create a mixin instance
    class TestWAFEvasion(WAFEvasionMixin):
        pass
    
    waf = TestWAFEvasion()
    
    # Test SQL injection payload obfuscation
    print("\n--- SQL Injection Payload Variants ---")
    sql_payload = "' OR '1'='1"
    variants = waf.get_sql_injection_variants(sql_payload)
    print(f"Original: {sql_payload}")
    print(f"Generated {len(variants)} variants:")
    for i, variant in enumerate(variants[:5], 1):
        print(f"  {i}. {variant}")
    
    # Test XSS payload obfuscation
    print("\n--- XSS Payload Variants ---")
    xss_payload = "<script>alert('XSS')</script>"
    variants = waf.get_xss_variants(xss_payload)
    print(f"Original: {xss_payload}")
    print(f"Generated {len(variants)} variants:")
    for i, variant in enumerate(variants[:5], 1):
        print(f"  {i}. {variant}")
    
    # Test command injection variants
    print("\n--- Command Injection Payload Variants ---")
    cmd_payload = "; whoami"
    variants = waf.get_command_injection_variants(cmd_payload)
    print(f"Original: {cmd_payload}")
    print(f"Generated {len(variants)} variants:")
    for i, variant in enumerate(variants[:5], 1):
        print(f"  {i}. {variant}")


async def main():
    """Run all tests."""
    print("=" * 80)
    print(" " * 20 + "MATRIX SECURITY AGENT TEST SUITE")
    print(" " * 20 + f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    try:
        # Test WAF evasion (no network required)
        await test_waf_evasion()
        
        # Test rate limiting
        await test_rate_limiting()
        
        # Test caching
        await test_caching()
        
        # Test individual agents (requires network)
        print("\nWARNING: The following tests will make real HTTP requests to testphp.vulnweb.com")
        print("         This is a deliberately vulnerable test site for security testing.")
        await asyncio.sleep(2)
        
        await test_individual_agents()
        
        # Test orchestrator
        await test_orchestrator()
        
        print("\n" + "=" * 80)
        print("SUCCESS: ALL TESTS COMPLETED")
        print("=" * 80)
        
    except KeyboardInterrupt:
        print("\n\nWARNING: Tests interrupted by user")
    except Exception as e:
        print(f"\n\nERROR: Test suite failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
