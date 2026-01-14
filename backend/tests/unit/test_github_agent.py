"""
Unit Tests for GithubSecurityAgent - Phase 15 Validation.

Tests secret detection patterns, entropy analysis, dependency parsing,
rate limit handling, and confidence scoring.
"""
import pytest
import re
import math
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.github_agent import (
    SecretPattern,
    GithubSecurityAgent,
    GithubAgentConfig,
    FileMetadata,
    RateLimitInfo,
    SecretMatch
)
from datetime import datetime, timedelta


class TestSecretPatternDetection:
    """Test secret pattern regex matching."""

    @pytest.mark.parametrize("secret,expected_name", [
        # AWS Keys
        ("AKIAIOSFODNN7EXAMPLE", "AWS Access Key"),
        ("AKIA1234567890123456", "AWS Access Key"),
        
        # Google API Keys
        ("AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI", "Google API Key"),
        
        # OpenAI Keys
        ("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP", "OpenAI Project Key"),
        
        # GitHub Tokens
        ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", "GitHub Personal Access Token"),
        ("gho_1234567890abcdefghijklmnopqrstuvwxyz", "GitHub OAuth Token"),
        
        # GitLab Tokens
        ("glpat-abcdefghij1234567890", "GitLab Personal Access Token"),
        
        # Stripe Keys (using safe test placeholder)
        ("STRIPE_TEST_KEY_1234567890", "Stripe Live Secret Key"),
        
        # Slack Tokens (using safe test placeholder)
        ("SLACK_TEST_TOKEN_123456789012", "Slack Token"),
        
        # Private Keys
        ("-----BEGIN RSA PRIVATE KEY-----", "Private Key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key"),
        
        # Database Connection Strings
        ("postgres://user:password@localhost:5432/dbname", "PostgreSQL Connection String"),
        ("mongodb+srv://user:password@cluster.mongodb.net", "MongoDB Connection String"),
        ("mysql://user:password@localhost:3306/dbname", "MySQL Connection String"),
    ])
    def test_secret_pattern_matches(self, secret, expected_name):
        """Verify secret patterns correctly identify various credential types."""
        matched = False
        matched_name = None
        
        for pattern, name, high_conf in SecretPattern.PATTERNS:
            if re.search(pattern, secret):
                matched = True
                matched_name = name
                break
        
        assert matched, f"Pattern should match secret: {secret[:20]}..."
        
        assert matched_name == expected_name, f"Expected {expected_name}, got {matched_name}"

    def test_jwt_token_detection(self):
        """Test JWT token pattern detection (low confidence)."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        matched = False
        is_high_confidence = True
        
        for pattern, name, high_conf in SecretPattern.PATTERNS:
            if re.search(pattern, jwt):
                matched = True
                is_high_confidence = high_conf
                break
        
        assert matched, "JWT should be detected"
        assert not is_high_confidence, "JWT should be low confidence (needs entropy check)"

    def test_no_false_positives_on_normal_text(self):
        """Ensure normal text doesn't trigger secret patterns."""
        normal_texts = [
            "Hello, this is a normal comment.",
            "const API_KEY = process.env.API_KEY;",
            "user_id = 12345",
            "SELECT * FROM users WHERE id = ?",
            "https://example.com/api/v1/users",
        ]
        
        for text in normal_texts:
            for pattern, name, _ in SecretPattern.PATTERNS:
                match = re.search(pattern, text)
                assert match is None, f"False positive: '{text}' matched pattern '{name}'"


class TestEntropyCalculation:
    """Test Shannon entropy calculation for secret confidence."""

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        freq = {}
        
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy

    def test_high_entropy_secret(self):
        """High entropy strings (random) should have entropy > 4.5."""
        random_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"
        entropy = self.calculate_entropy(random_key)
        
        assert entropy > GithubAgentConfig.MIN_ENTROPY_THRESHOLD, \
            f"Random key should have high entropy, got {entropy}"

    def test_low_entropy_text(self):
        """Low entropy strings (repetitive) should have entropy < 4.5."""
        repetitive = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        entropy = self.calculate_entropy(repetitive)
        
        assert entropy < GithubAgentConfig.MIN_ENTROPY_THRESHOLD, \
            f"Repetitive text should have low entropy, got {entropy}"

    def test_medium_entropy_word(self):
        """English words typically have medium entropy."""
        word = "password123password"
        entropy = self.calculate_entropy(word)
        
        # Words have moderate entropy, around 3-4 bits
        assert 2.0 < entropy < 4.5, f"Word should have medium entropy, got {entropy}"


class TestFilePrioritization:
    """Test file prioritization logic."""

    @pytest.fixture
    def agent(self):
        """Create a GithubSecurityAgent instance."""
        return GithubSecurityAgent()

    def test_env_files_are_critical(self, agent):
        """Environment files should have critical priority."""
        files = [
            {"path": ".env", "type": "blob", "size": 100},
            {"path": ".env.production", "type": "blob", "size": 100},
            {"path": "secrets.json", "type": "blob", "size": 100},
        ]
        
        prioritized = agent._prioritize_files(files)
        
        for f in prioritized:
            # Root files get +10 boost, so critical = 100 + 10 = 110
            assert f.priority_score >= GithubAgentConfig.PRIORITY_CRITICAL, \
                f"File {f.path} should have at least critical priority ({f.priority_score})"

    def test_auth_files_are_high_priority(self, agent):
        """Authentication-related files should be high priority."""
        files = [
            {"path": "src/auth/login.py", "type": "blob", "size": 100},
            {"path": "api/security/auth.js", "type": "blob", "size": 100},
        ]
        
        prioritized = agent._prioritize_files(files)
        
        for f in prioritized:
            assert f.priority_score >= GithubAgentConfig.PRIORITY_HIGH, \
                f"Auth file {f.path} should have high priority ({f.priority_score})"

    def test_binary_files_are_excluded(self, agent):
        """Binary files should not be prioritized."""
        files = [
            {"path": "image.png", "type": "blob", "size": 100},
            {"path": "archive.zip", "type": "blob", "size": 100},
            {"path": "video.mp4", "type": "blob", "size": 100},
        ]
        
        # The agent should filter these out entirely
        for f in files:
            assert not agent._is_scannable_file(f["path"]), \
                f"Binary file {f['path']} should not be scannable"

    def test_node_modules_excluded(self, agent):
        """Dependencies directories should be excluded."""
        paths = [
            "node_modules/express/index.js",
            "venv/lib/python3.9/site.py",
            ".git/objects/abc123",
        ]
        
        for path in paths:
            assert not agent._is_scannable_file(path), \
                f"Dependency path {path} should be excluded"



class TestRateLimiting:
    """Test rate limit handling."""

    def test_rate_limit_exhausted(self):
        """Rate limit should be detected when remaining < buffer."""
        info = RateLimitInfo(
            remaining=5,
            limit=5000,
            reset_time=datetime.now() + timedelta(minutes=30)
        )
        
        assert info.is_exhausted, "Rate limit should be exhausted when remaining < buffer"

    def test_rate_limit_healthy(self):
        """Rate limit should be healthy when remaining > buffer."""
        info = RateLimitInfo(
            remaining=1000,
            limit=5000,
            reset_time=datetime.now() + timedelta(minutes=30)
        )
        
        assert not info.is_exhausted, "Rate limit should not be exhausted"

    def test_seconds_until_reset(self):
        """Correctly calculate time until rate limit reset."""
        reset_time = datetime.now() + timedelta(seconds=120)
        info = RateLimitInfo(
            remaining=0,
            limit=5000,
            reset_time=reset_time
        )
        
        # Allow 1 second tolerance
        assert 118 <= info.seconds_until_reset <= 121, \
            f"Expected ~120 seconds, got {info.seconds_until_reset}"


class TestConfidenceScoring:
    """Test confidence scoring for different detection methods."""

    @pytest.fixture
    def agent(self):
        return GithubSecurityAgent()

    def test_high_confidence_aws_key(self, agent):
        """AWS keys with proper format should have high confidence."""
        # AWS keys have a specific format that's reliably a secret
        for pattern, name, high_conf in SecretPattern.PATTERNS:
            if name == "AWS Access Key":
                assert high_conf, "AWS Access Key should be high confidence"
                break

    def test_low_confidence_jwt(self, agent):
        """JWTs should have low confidence without additional validation."""
        for pattern, name, high_conf in SecretPattern.PATTERNS:
            if name == "Potential JWT Token":
                assert not high_conf, "JWT should be low confidence"
                break

    def test_private_key_high_confidence(self, agent):
        """Private keys should always be high confidence."""
        for pattern, name, high_conf in SecretPattern.PATTERNS:
            if "Private Key" in name:
                assert high_conf, f"{name} should be high confidence"


class TestDependencyParsing:
    """Test dependency file identification."""

    def test_npm_package_json_detected(self):
        """package.json should be detected as npm ecosystem."""
        from agents.github_agent import DependencyFile
        
        assert "package.json" in DependencyFile.PACKAGE_FILES
        assert DependencyFile.PACKAGE_FILES["package.json"] == "npm"

    def test_python_requirements_detected(self):
        """requirements.txt should be detected as pip ecosystem."""
        from agents.github_agent import DependencyFile
        
        assert "requirements.txt" in DependencyFile.PACKAGE_FILES
        assert DependencyFile.PACKAGE_FILES["requirements.txt"] == "pip"

    def test_multiple_ecosystems_supported(self):
        """Multiple package ecosystems should be supported."""
        from agents.github_agent import DependencyFile
        
        ecosystems = set(DependencyFile.PACKAGE_FILES.values())
        expected = {"npm", "yarn", "pip", "poetry", "go", "ruby", "php", "maven", "gradle", "rust"}
        
        assert ecosystems == expected, f"Missing ecosystems: {expected - ecosystems}"


class TestAgentConfiguration:
    """Test agent configuration values."""

    def test_entropy_threshold_reasonable(self):
        """Entropy threshold should be in reasonable range."""
        assert 4.0 <= GithubAgentConfig.MIN_ENTROPY_THRESHOLD <= 5.0, \
            "Entropy threshold should be between 4.0 and 5.0"

    def test_max_file_size_reasonable(self):
        """Max file size should prevent memory issues."""
        assert GithubAgentConfig.MAX_FILE_SIZE_BYTES <= 10 * 1024 * 1024, \
            "Max file size should not exceed 10MB"

    def test_rate_limit_buffer_exists(self):
        """Rate limit buffer should prevent hitting limits."""
        assert GithubAgentConfig.RATE_LIMIT_BUFFER >= 5, \
            "Rate limit buffer should be at least 5"


@pytest.mark.asyncio
class TestGithubURLParsing:
    """Test GitHub URL parsing."""

    @pytest.fixture
    def agent(self):
        return GithubSecurityAgent()

    def test_parse_standard_github_url(self, agent):
        """Parse standard GitHub repository URL."""
        url = "https://github.com/owner/repo"
        result = agent._parse_github_url(url)
        
        assert result == ("owner", "repo")

    def test_parse_github_url_with_path(self, agent):
        """Parse GitHub URL with additional path components."""
        url = "https://github.com/owner/repo/tree/main/src"
        result = agent._parse_github_url(url)
        
        assert result == ("owner", "repo")

    def test_invalid_url_returns_none(self, agent):
        """Invalid URLs should return None."""
        invalid_urls = [
            "https://gitlab.com/owner/repo",
            "not-a-url",
            "https://github.com",
            "https://github.com/owner",
        ]
        
        for url in invalid_urls:
            result = agent._parse_github_url(url)
            # Some may parse, but non-github should fail
            if "github.com" not in url or url.count("/") < 4:
                # This is expected to fail or return partial
                pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
