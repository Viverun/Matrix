"""
Diff-Based Detection - Detects subtle response changes for blind vulnerabilities.

This module provides advanced response comparison capabilities for detecting
blind vulnerabilities through subtle changes in HTTP responses, including
blind SQL injection, boolean-based detection, and error suppression.

Features:
- Baseline vs exploitation response comparison
- Token-level and byte-level diffing
- Statistical similarity analysis
- Content normalization for accurate comparison
- Boolean-based blind vulnerability detection
"""
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
import difflib
import re
from collections import Counter
import hashlib
from core.logger import get_logger

# Initialize structured logger
logger = get_logger(__name__)

# Configuration constants
DEFAULT_SIMILARITY_THRESHOLD = 0.95  # Similarity below this is significant
DEFAULT_MIN_BYTE_DIFF = 10          # Minimum bytes different to be significant
DEFAULT_MODIFICATION_THRESHOLD = 0.6  # Similarity threshold for detecting modifications
MAX_RESPONSE_SIZE_FOR_LOGGING = 1000  # Max response chars to log

# Normalization patterns
TIMESTAMP_PATTERNS = [
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?',  # ISO format
    r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?',  # SQL format
    r'\d{10,13}',                                       # Unix timestamp
    r'Date: [^\r\n]+',                                  # HTTP Date header
    r'Last-Modified: [^\r\n]+',                         # Last-Modified header
]

SESSION_ID_PATTERNS = [
    r'\b[0-9a-f]{32,}\b',  # Hex strings (session IDs, tokens)
    r'PHPSESSID=[^;\s]+',
    r'JSESSIONID=[^;\s]+',
    r'ASP\.NET_SessionId=[^;\s]+',
]

CSRF_PATTERNS = [
    r'csrf[_-]?token["\']?\s*[:=]\s*["\']?[\w-]+',
    r'_token["\']?\s*[:=]\s*["\']?[\w-]+',
    r'authenticity_token["\']?\s*[:=]\s*["\']?[\w-]+',
]

# Security keywords for detection
ERROR_KEYWORDS = [
    'error', 'exception', 'warning', 'failed', 'denied', 
    'forbidden', 'unauthorized', 'invalid', 'fatal'
]

DB_ERROR_PATTERNS = [
    r'SQL syntax',
    r'mysql_',
    r'mysqli',
    r'ORA-\d+',
    r'PostgreSQL',
    r'sqlite',
    r'SQLSTATE',
    r'syntax error',
    r'unterminated',
    r'unexpected end of SQL',
]

AUTH_KEYWORDS = [
    'login', 'logout', 'authenticated', 'session', 
    'unauthorized', 'access denied', 'permission'
]


@dataclass
class ResponseDiff:
    """
    Represents differences between two HTTP responses.
    
    This dataclass encapsulates all comparison results including line-level
    differences, similarity metrics, and significance analysis.
    
    Attributes:
        added_lines: Lines present in test but not in baseline
        removed_lines: Lines present in baseline but not in test
        modified_lines: Lines that changed between responses (before, after tuples)
        similarity_ratio: Sequence similarity score (0.0 = completely different, 1.0 = identical)
        byte_diff_count: Absolute difference in response sizes
        token_diff_count: Number of unique tokens that differ
        is_significant: Whether the differences are considered significant
        significance_reasons: List of reasons why differences are significant
        unified_diff: Raw unified diff output
        metadata: Additional metadata about the comparison
    """
    # Content differences
    added_lines: List[str] = field(default_factory=list)
    removed_lines: List[str] = field(default_factory=list)
    modified_lines: List[Tuple[str, str]] = field(default_factory=list)  # (before, after)
    
    # Metrics
    similarity_ratio: float = 1.0
    byte_diff_count: int = 0
    token_diff_count: int = 0
    
    # Significant changes
    is_significant: bool = False
    significance_reasons: List[str] = field(default_factory=list)
    
    # Raw diff
    unified_diff: str = ""
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert ResponseDiff to dictionary for serialization.
        
        Returns:
            Dictionary representation of the diff.
        """
        return {
            "added_lines": self.added_lines,
            "removed_lines": self.removed_lines,
            "modified_lines": [{"before": m[0], "after": m[1]} for m in self.modified_lines],
            "similarity_ratio": self.similarity_ratio,
            "byte_diff_count": self.byte_diff_count,
            "token_diff_count": self.token_diff_count,
            "is_significant": self.is_significant,
            "significance_reasons": self.significance_reasons,
            "metadata": self.metadata,
        }
    
    def get_summary(self) -> str:
        """
        Get a human-readable summary of the diff.
        
        Returns:
            Formatted summary string.
        """
        parts = [
            f"Similarity: {self.similarity_ratio:.2%}",
            f"Bytes changed: {self.byte_diff_count}",
            f"Tokens changed: {self.token_diff_count}",
            f"Added lines: {len(self.added_lines)}",
            f"Removed lines: {len(self.removed_lines)}",
            f"Modified lines: {len(self.modified_lines)}",
        ]
        
        if self.is_significant:
            parts.append(f"SIGNIFICANT: {', '.join(self.significance_reasons)}")
        
        return " | ".join(parts)


class DiffDetector:
    """
    Advanced diff-based detection for subtle response changes.
    
    This class provides comprehensive response comparison capabilities for
    detecting security vulnerabilities through response analysis. It's particularly
    useful for blind vulnerability detection where subtle changes indicate
    successful exploitation.
    
    Use Cases:
    - Blind SQL injection (time-based with small content changes)
    - Boolean-based blind vulnerabilities
    - Error suppression detection
    - Authentication bypass validation
    - Response consistency validation
    
    Example:
        ```python
        detector = DiffDetector(significance_threshold=0.95)
        
        # Compare baseline vs test response
        diff = detector.compare_responses(baseline_response, test_response)
        
        if diff.is_significant:
            print(f"Significant changes detected: {diff.significance_reasons}")
        
        # Boolean-based detection
        result = detector.detect_boolean_based(baseline, true_resp, false_resp)
        if result["is_boolean_based"]:
            print("Boolean-based blind vulnerability detected!")
        ```
    """
    
    def __init__(
        self,
        significance_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        min_byte_diff: int = DEFAULT_MIN_BYTE_DIFF,
        modification_threshold: float = DEFAULT_MODIFICATION_THRESHOLD
    ) -> None:
        """
        Initialize the diff detector with configuration parameters.
        
        Args:
            significance_threshold: Similarity ratio below this value is considered
                                   significant (0.0-1.0, default 0.95)
            min_byte_diff: Minimum byte difference to be considered significant
            modification_threshold: Similarity threshold for detecting line modifications
        
        Raises:
            ValueError: If parameters are out of valid ranges
        """
        # Validate parameters
        if not 0.0 <= significance_threshold <= 1.0:
            raise ValueError(f"significance_threshold must be between 0.0 and 1.0, got {significance_threshold}")
        
        if min_byte_diff < 0:
            raise ValueError(f"min_byte_diff must be non-negative, got {min_byte_diff}")
        
        if not 0.0 <= modification_threshold <= 1.0:
            raise ValueError(f"modification_threshold must be between 0.0 and 1.0, got {modification_threshold}")
        
        self.significance_threshold = significance_threshold
        self.min_byte_diff = min_byte_diff
        self.modification_threshold = modification_threshold
        
        logger.info(
            f"DiffDetector initialized: threshold={significance_threshold}, "
            f"min_bytes={min_byte_diff}, mod_threshold={modification_threshold}"
        )
    
    def compare_responses(
        self,
        baseline_response: str,
        test_response: str,
        normalize: bool = True,
        label: Optional[str] = None
    ) -> ResponseDiff:
        """
        Compare two HTTP responses and detect significant differences.
        
        This method performs comprehensive response comparison including
        normalization, similarity calculation, and significance analysis.
        
        Args:
            baseline_response: Original/normal response to compare against
            test_response: Response after exploitation attempt
            normalize: Whether to normalize responses before comparison (removes
                      timestamps, session IDs, etc.)
            label: Optional label for logging purposes
            
        Returns:
            ResponseDiff object with detailed comparison results
            
        Example:
            ```python
            diff = detector.compare_responses(
                baseline_response="<html>User not found</html>",
                test_response="<html>SQL error: syntax</html>",
                normalize=True,
                label="SQL Injection Test"
            )
            ```
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            # Log comparison start
            label_info = f" ({label})" if label else ""
            logger.debug(
                f"Starting response comparison{label_info}: "
                f"baseline={len(baseline_response)} bytes, test={len(test_response)} bytes"
            )
            
            # Normalize if requested
            if normalize:
                baseline_normalized = self._normalize_response(baseline_response)
                test_normalized = self._normalize_response(test_response)
                logger.debug("Response normalization completed")
            else:
                baseline_normalized = baseline_response
                test_normalized = test_response
            
            # Calculate similarity
            similarity = difflib.SequenceMatcher(
                None,
                baseline_normalized,
                test_normalized
            ).ratio()
            
            logger.debug(f"Similarity ratio calculated: {similarity:.4f}")
            
            # Line-by-line diff
            baseline_lines = baseline_normalized.splitlines()
            test_lines = test_normalized.splitlines()
            
            diff_output = list(difflib.unified_diff(
                baseline_lines,
                test_lines,
                lineterm='',
                n=0  # No context lines
            ))
            
            # Parse diff
            added, removed, modified = self._parse_diff_output(diff_output)
            
            logger.debug(
                f"Diff parsed: +{len(added)} lines, -{len(removed)} lines, "
                f"~{len(modified)} modified"
            )
            
            # Calculate byte and token differences
            byte_diff = abs(len(baseline_normalized) - len(test_normalized))
            token_diff = self._calculate_token_diff(baseline_normalized, test_normalized)
            
            # Determine significance
            is_sig, reasons = self._is_significant(
                similarity, byte_diff, token_diff, added, removed, modified
            )
            
            # Create result
            result = ResponseDiff(
                added_lines=added,
                removed_lines=removed,
                modified_lines=modified,
                similarity_ratio=similarity,
                byte_diff_count=byte_diff,
                token_diff_count=token_diff,
                is_significant=is_sig,
                significance_reasons=reasons,
                unified_diff='\n'.join(diff_output),
                metadata={
                    "normalized": normalize,
                    "label": label,
                    "comparison_time_ms": (datetime.now(timezone.utc) - start_time).total_seconds() * 1000,
                    "baseline_size": len(baseline_response),
                    "test_size": len(test_response),
                }
            )
            
            # Log result
            if is_sig:
                logger.info(f"Significant differences detected{label_info}: {', '.join(reasons)}")
            else:
                logger.debug(f"No significant differences detected{label_info}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error during response comparison: {str(e)}", exc_info=True)
            # Return empty diff with error metadata
            return ResponseDiff(
                metadata={
                    "error": str(e),
                    "label": label,
                }
            )
    
    def _parse_diff_output(
        self,
        diff_output: List[str]
    ) -> Tuple[List[str], List[str], List[Tuple[str, str]]]:
        """
        Parse unified diff output into added, removed, and modified lines.
        
        Args:
            diff_output: Output from difflib.unified_diff
            
        Returns:
            Tuple of (added_lines, removed_lines, modified_lines)
        """
        added = []
        removed = []
        modified = []
        
        # Skip header lines (first 2 lines typically)
        for line in diff_output[2:] if len(diff_output) > 2 else []:
            if line.startswith('+'):
                added.append(line[1:])
            elif line.startswith('-'):
                removed.append(line[1:])
        
        # Detect modifications (removed + added on similar lines)
        for r in removed[:]:
            for a in added[:]:
                similarity = difflib.SequenceMatcher(None, r, a).ratio()
                if similarity > self.modification_threshold:
                    modified.append((r, a))
                    removed.remove(r)
                    added.remove(a)
                    break
        
        return added, removed, modified
    
    def _calculate_token_diff(self, baseline: str, test: str) -> int:
        """
        Calculate the number of unique tokens that differ between responses.
        
        Args:
            baseline: Baseline response text
            test: Test response text
            
        Returns:
            Number of unique tokens that differ
        """
        baseline_tokens = set(self._tokenize(baseline))
        test_tokens = set(self._tokenize(test))
        return len(baseline_tokens ^ test_tokens)  # Symmetric difference
    
    def _normalize_response(self, response: str) -> str:
        """
        Normalize response for better comparison.
        
        This removes dynamic content that changes between requests to focus
        on meaningful differences:
        - Timestamps (ISO, SQL, Unix)
        - Session IDs and tokens
        - CSRF tokens
        - Request IDs
        - Random values
        
        Args:
            response: Raw response content
            
        Returns:
            Normalized response content
        """
        try:
            normalized = response
            
            # Remove timestamps
            for pattern in TIMESTAMP_PATTERNS:
                normalized = re.sub(pattern, '[TIMESTAMP]', normalized)
            
            # Remove session/request IDs
            for pattern in SESSION_ID_PATTERNS:
                normalized = re.sub(pattern, '[SESSION_ID]', normalized, flags=re.IGNORECASE)
            
            # Remove CSRF tokens
            for pattern in CSRF_PATTERNS:
                normalized = re.sub(pattern, 'csrf_token=[TOKEN]', normalized, flags=re.IGNORECASE)
            
            # Normalize whitespace
            normalized = re.sub(r'\s+', ' ', normalized)
            
            # Remove HTML comments
            normalized = re.sub(r'<!--.*?-->', '', normalized, flags=re.DOTALL)
            
            # Remove script tags content (often contains dynamic data)
            normalized = re.sub(r'<script\b[^>]*>.*?</script>', '<script>[REMOVED]</script>', normalized, flags=re.DOTALL | re.IGNORECASE)
            
            return normalized.strip()
            
        except Exception as e:
            logger.warning(f"Error during response normalization: {str(e)}")
            return response  # Return original on error
    
    def _tokenize(self, text: str) -> List[str]:
        """
        Tokenize text into words and symbols for token-level comparison.
        
        Args:
            text: Text to tokenize
            
        Returns:
            List of tokens
        """
        return re.findall(r'\w+|[^\w\s]', text)
    
    def _is_significant(
        self,
        similarity: float,
        byte_diff: int,
        token_diff: int,
        added: List[str],
        removed: List[str],
        modified: List[Tuple[str, str]]
    ) -> Tuple[bool, List[str]]:
        """
        Determine if differences are significant for vulnerability detection.
        
        Args:
            similarity: Similarity ratio (0.0-1.0)
            byte_diff: Byte count difference
            token_diff: Token count difference
            added: Added lines
            removed: Removed lines
            modified: Modified lines
            
        Returns:
            Tuple of (is_significant, list_of_reasons)
        """
        reasons = []
        
        # Check similarity threshold
        if similarity < self.significance_threshold:
            reasons.append(
                f"Low similarity: {similarity:.2%} (threshold: {self.significance_threshold:.2%})"
            )
        
        # Check byte diff
        if byte_diff >= self.min_byte_diff:
            reasons.append(f"Significant byte difference: {byte_diff} bytes")
        
        # Check for error indicators
        all_new_content = '\n'.join(added + [m[1] for m in modified])
        
        for keyword in ERROR_KEYWORDS:
            if keyword in all_new_content.lower():
                reasons.append(f"Error indicator found: '{keyword}' in added/modified content")
                break  # Only report first match per category
        
        # Check for SQL/database errors
        for pattern in DB_ERROR_PATTERNS:
            if re.search(pattern, all_new_content, re.IGNORECASE):
                reasons.append(f"Database error pattern detected: '{pattern}'")
                break
        
        # Check for authentication changes
        for keyword in AUTH_KEYWORDS:
            if keyword in all_new_content.lower():
                reasons.append(f"Authentication-related change: '{keyword}'")
                break
        
        # Check for stack traces
        if re.search(r'at\s+[\w.]+\([^)]+:\d+\)', all_new_content):
            reasons.append("Stack trace detected in response")
        
        # Check for file paths (potential information disclosure)
        if re.search(r'[A-Za-z]:\\|/(?:var|usr|home|etc)/', all_new_content):
            reasons.append("File system paths detected in response")
        
        # Significant if we have reasons
        is_significant = len(reasons) > 0
        
        if is_significant:
            logger.debug(f"Significance detected: {len(reasons)} reasons")
        
        return is_significant, reasons
    
    def compare_multiple_responses(
        self,
        baseline: str,
        test_responses: List[str],
        labels: Optional[List[str]] = None
    ) -> Dict[str, ResponseDiff]:
        """
        Compare baseline against multiple test responses.
        
        Useful for:
        - Boolean-based detection (true vs false responses)
        - Error message enumeration
        - State change validation
        - Batch response analysis
        
        Args:
            baseline: Baseline response to compare against
            test_responses: List of test responses to compare
            labels: Optional labels for each test response
            
        Returns:
            Dictionary mapping labels to ResponseDiff objects
            
        Example:
            ```python
            results = detector.compare_multiple_responses(
                baseline=normal_response,
                test_responses=[sqli_response, xss_response, lfi_response],
                labels=["SQL Injection", "XSS", "LFI"]
            )
            
            for label, diff in results.items():
                if diff.is_significant:
                    print(f"{label}: Significant changes detected!")
            ```
        """
        if labels is None:
            labels = [f"Test {i+1}" for i in range(len(test_responses))]
        
        if len(labels) != len(test_responses):
            logger.warning(
                f"Label count ({len(labels)}) doesn't match response count ({len(test_responses)})"
            )
            labels = labels[:len(test_responses)] + [
                f"Test {i+1}" for i in range(len(labels), len(test_responses))
            ]
        
        logger.info(f"Comparing baseline against {len(test_responses)} test responses")
        
        results = {}
        
        for label, test_response in zip(labels, test_responses):
            diff = self.compare_responses(baseline, test_response, label=label)
            results[label] = diff
        
        # Summary logging
        significant_count = sum(1 for diff in results.values() if diff.is_significant)
        logger.info(
            f"Multiple response comparison complete: "
            f"{significant_count}/{len(results)} showed significant differences"
        )
        
        return results
    
    def detect_boolean_based(
        self,
        baseline: str,
        true_response: str,
        false_response: str
    ) -> Dict[str, Any]:
        """
        Detect boolean-based blind vulnerabilities.
        
        This method analyzes responses from true and false conditions to determine
        if the application exhibits boolean-based blind vulnerability characteristics.
        The key indicator is that true and false responses differ significantly from
        each other while maintaining consistency with the baseline.
        
        Args:
            baseline: Normal response (neither true nor false condition)
            true_response: Response when injected condition evaluates to TRUE
            false_response: Response when injected condition evaluates to FALSE
            
        Returns:
            Detailed analysis dictionary containing:
            - is_boolean_based: Whether boolean behavior was detected
            - true_diff: Comparison of true response vs baseline
            - false_diff: Comparison of false response vs baseline
            - true_vs_false: Direct comparison of true vs false
            - recommendation: Human-readable assessment
            
        Example:
            ```python
            # Test: 1' AND 1=1-- vs 1' AND 1=2--
            result = detector.detect_boolean_based(
                baseline=normal_response,
                true_response=response_1_equals_1,
                false_response=response_1_equals_2
            )
            
            if result["is_boolean_based"]:
                print("Boolean-based SQL injection detected!")
                print(result["recommendation"])
            ```
        """
        logger.info("Starting boolean-based vulnerability detection")
        
        try:
            # Compare each condition against baseline
            true_diff = self.compare_responses(baseline, true_response, label="TRUE condition")
            false_diff = self.compare_responses(baseline, false_response, label="FALSE condition")
            
            # Compare true vs false directly
            true_vs_false = self.compare_responses(
                true_response, false_response, label="TRUE vs FALSE"
            )
            
            # Boolean-based if:
            # 1. True and false responses differ significantly from each other
            # 2. At least one maintains high similarity to baseline (consistent behavior)
            is_boolean_based = (
                true_vs_false.is_significant and
                (true_diff.similarity_ratio > 0.85 or false_diff.similarity_ratio > 0.85)
            )
            
            result = {
                "is_boolean_based": is_boolean_based,
                "confidence": "high" if is_boolean_based else "low",
                "true_diff": {
                    "similarity_to_baseline": true_diff.similarity_ratio,
                    "is_significant": true_diff.is_significant,
                    "reasons": true_diff.significance_reasons,
                    "byte_diff": true_diff.byte_diff_count
                },
                "false_diff": {
                    "similarity_to_baseline": false_diff.similarity_ratio,
                    "is_significant": false_diff.is_significant,
                    "reasons": false_diff.significance_reasons,
                    "byte_diff": false_diff.byte_diff_count
                },
                "true_vs_false": {
                    "similarity": true_vs_false.similarity_ratio,
                    "byte_diff": true_vs_false.byte_diff_count,
                    "is_significant": true_vs_false.is_significant,
                    "reasons": true_vs_false.significance_reasons
                },
                "recommendation": (
                    "Likely boolean-based blind vulnerability detected. "
                    "TRUE and FALSE conditions produce distinguishable responses, "
                    "indicating the application is processing the injected logic."
                    if is_boolean_based else
                    "Responses do not show clear boolean behavior. "
                    "Consider alternative detection methods or verify injection points."
                )
            }
            
            if is_boolean_based:
                logger.info("Boolean-based vulnerability detected!")
            else:
                logger.info("No boolean-based behavior detected")
            
            return result
            
        except Exception as e:
            logger.error(f"Error during boolean-based detection: {str(e)}", exc_info=True)
            return {
                "is_boolean_based": False,
                "confidence": "error",
                "error": str(e),
                "recommendation": f"Detection failed due to error: {str(e)}"
            }
    
    def calculate_response_hash(
        self,
        response: str,
        normalize: bool = True,
        algorithm: str = "md5"
    ) -> str:
        """
        Calculate cryptographic hash of response for quick comparison.
        
        Args:
            response: Response content to hash
            normalize: Whether to normalize before hashing
            algorithm: Hash algorithm ('md5', 'sha1', 'sha256')
            
        Returns:
            Hex digest of response hash
            
        Raises:
            ValueError: If algorithm is not supported
        """
        # Validate algorithm
        valid_algorithms = {'md5', 'sha1', 'sha256'}
        if algorithm not in valid_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Use one of {valid_algorithms}")
        
        try:
            content = self._normalize_response(response) if normalize else response
            content_bytes = content.encode('utf-8', errors='replace')
            
            if algorithm == 'md5':
                return hashlib.md5(content_bytes).hexdigest()
            elif algorithm == 'sha1':
                return hashlib.sha1(content_bytes).hexdigest()
            else:  # sha256
                return hashlib.sha256(content_bytes).hexdigest()
                
        except Exception as e:
            logger.error(f"Error calculating response hash: {str(e)}")
            raise
    
    def find_unique_responses(
        self,
        responses: List[str],
        normalize: bool = True
    ) -> Dict[str, List[int]]:
        """
        Group responses by similarity using hash-based clustering.
        
        This method identifies unique response patterns by hashing each response
        and grouping identical hashes together. Useful for analyzing multiple
        exploit attempts to find which ones produce distinct behaviors.
        
        Args:
            responses: List of responses to analyze
            normalize: Whether to normalize before hashing
            
        Returns:
            Dictionary mapping response hash to list of response indices
            
        Example:
            ```python
            responses = [resp1, resp2, resp3, resp4, resp5]
            groups = detector.find_unique_responses(responses)
            
            print(f"Found {len(groups)} unique response patterns")
            for hash_val, indices in groups.items():
                print(f"Pattern {hash_val[:8]}: responses {indices}")
            ```
        """
        logger.debug(f"Grouping {len(responses)} responses by similarity")
        
        groups: Dict[str, List[int]] = {}
        
        for idx, response in enumerate(responses):
            try:
                hash_val = self.calculate_response_hash(response, normalize)
                if hash_val not in groups:
                    groups[hash_val] = []
                groups[hash_val].append(idx)
            except Exception as e:
                logger.warning(f"Failed to hash response {idx}: {str(e)}")
                # Put in separate error group
                error_key = f"error_{idx}"
                groups[error_key] = [idx]
        
        logger.info(f"Found {len(groups)} unique response patterns from {len(responses)} responses")
        
        return groups
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current detector configuration and statistics.
        
        Returns:
            Dictionary with configuration and usage statistics
        """
        return {
            "configuration": {
                "significance_threshold": self.significance_threshold,
                "min_byte_diff": self.min_byte_diff,
                "modification_threshold": self.modification_threshold,
            },
            "normalization_patterns": {
                "timestamp_patterns": len(TIMESTAMP_PATTERNS),
                "session_id_patterns": len(SESSION_ID_PATTERNS),
                "csrf_patterns": len(CSRF_PATTERNS),
            },
            "detection_keywords": {
                "error_keywords": len(ERROR_KEYWORDS),
                "db_error_patterns": len(DB_ERROR_PATTERNS),
                "auth_keywords": len(AUTH_KEYWORDS),
            }
        }


# Convenience functions for quick operations
def compare_responses(
    baseline: str,
    test: str,
    normalize: bool = True
) -> ResponseDiff:
    """
    Quick response comparison using default settings.
    
    Args:
        baseline: Baseline response
        test: Test response
        normalize: Whether to normalize responses
        
    Returns:
        ResponseDiff object with comparison results
    """
    detector = DiffDetector()
    return detector.compare_responses(baseline, test, normalize)


def detect_boolean_vulnerability(
    baseline: str,
    true_response: str,
    false_response: str
) -> bool:
    """
    Quick boolean-based vulnerability check.
    
    Args:
        baseline: Normal response
        true_response: TRUE condition response
        false_response: FALSE condition response
        
    Returns:
        True if boolean-based vulnerability detected, False otherwise
    """
    detector = DiffDetector()
    result = detector.detect_boolean_based(baseline, true_response, false_response)
    return result["is_boolean_based"]