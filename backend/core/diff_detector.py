"""
Diff-Based Detection - Detects subtle response changes for blind vulnerabilities.

Features:
- Baseline vs exploitation response comparison
- Token-level and byte-level diffing
- Statistical similarity analysis
- Content normalization for accurate comparison
"""
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import difflib
import re
from collections import Counter
import hashlib


@dataclass
class ResponseDiff:
    """Represents differences between two HTTP responses."""
    # Content differences
    added_lines: List[str]
    removed_lines: List[str]
    modified_lines: List[Tuple[str, str]]  # (before, after)
    
    # Metrics
    similarity_ratio: float  # 0.0 - 1.0
    byte_diff_count: int
    token_diff_count: int
    
    # Significant changes
    is_significant: bool
    significance_reasons: List[str]
    
    # Raw diff
    unified_diff: str


class DiffDetector:
    """
    Advanced diff-based detection for subtle response changes.
    
    Useful for:
    - Blind SQL injection (time-based with small content changes)
    - Boolean-based blind vulnerabilities
    - Error suppression detection
    - Authentication bypass validation
    """
    
    def __init__(
        self,
        significance_threshold: float = 0.95,  # Similarity below this is significant
        min_byte_diff: int = 10                # Minimum bytes different to be significant
    ):
        self.significance_threshold = significance_threshold
        self.min_byte_diff = min_byte_diff
    
    def compare_responses(
        self,
        baseline_response: str,
        test_response: str,
        normalize: bool = True
    ) -> ResponseDiff:
        """
        Compare two HTTP responses and detect significant differences.
        
        Args:
            baseline_response: Original/normal response
            test_response: Response after exploitation attempt
            normalize: Whether to normalize responses before comparison
            
        Returns:
            ResponseDiff object with detailed comparison
        """
        # Normalize if requested
        if normalize:
            baseline_normalized = self._normalize_response(baseline_response)
            test_normalized = self._normalize_response(test_response)
        else:
            baseline_normalized = baseline_response
            test_normalized = test_response
        
        # Calculate similarity
        similarity = difflib.SequenceMatcher(
            None,
            baseline_normalized,
            test_normalized
        ).ratio()
        
        # Line-by-line diff
        baseline_lines = baseline_normalized.splitlines()
        test_lines = test_normalized.splitlines()
        
        diff = list(difflib.unified_diff(
            baseline_lines,
            test_lines,
            lineterm='',
            n=0  # No context lines
        ))
        
        # Parse diff
        added = []
        removed = []
        modified = []
        
        for line in diff[2:]:  # Skip header lines
            if line.startswith('+'):
                added.append(line[1:])
            elif line.startswith('-'):
                removed.append(line[1:])
        
        # Detect modifications (removed + added on similar lines)
        for r in removed[:]:
            for a in added[:]:
                if difflib.SequenceMatcher(None, r, a).ratio() > 0.6:
                    modified.append((r, a))
                    removed.remove(r)
                    added.remove(a)
                    break
        
        # Calculate byte and token differences
        byte_diff = abs(len(baseline_normalized) - len(test_normalized))
        
        baseline_tokens = self._tokenize(baseline_normalized)
        test_tokens = self._tokenize(test_normalized)
        token_diff = len(set(baseline_tokens) ^ set(test_tokens))
        
        # Determine significance
        is_sig, reasons = self._is_significant(
            similarity, byte_diff, token_diff, added, removed, modified
        )
        
        return ResponseDiff(
            added_lines=added,
            removed_lines=removed,
            modified_lines=modified,
            similarity_ratio=similarity,
            byte_diff_count=byte_diff,
            token_diff_count=token_diff,
            is_significant=is_sig,
            significance_reasons=reasons,
            unified_diff='\n'.join(diff)
        )
    
    def _normalize_response(self, response: str) -> str:
        """
        Normalize response for better comparison.
        
        Removes dynamic content that changes between requests:
        - Timestamps
        - Session IDs
        - Request IDs
        - CSRF tokens
        - Random values
        """
        normalized = response
        
        # Remove common timestamp formats
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO format
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # SQL format
            r'\d{10,13}',                             # Unix timestamp
            r'Date: [^\r\n]+',                        # HTTP Date header
        ]
        
        for pattern in timestamp_patterns:
            normalized = re.sub(pattern, '[TIMESTAMP]', normalized)
        
        # Remove session/request IDs (hex strings of certain lengths)
        normalized = re.sub(r'\b[0-9a-f]{32,}\b', '[ID]', normalized, flags=re.IGNORECASE)
        
        # Remove CSRF tokens (common patterns)
        csrf_patterns = [
            r'csrf[_-]?token["\']?\s*[:=]\s*["\']?[\w-]+',
            r'_token["\']?\s*[:=]\s*["\']?[\w-]+',
        ]
        
        for pattern in csrf_patterns:
            normalized = re.sub(pattern, 'csrf_token=[TOKEN]', normalized, flags=re.IGNORECASE)
        
        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized)
        
        # Remove HTML comments
        normalized = re.sub(r'<!--.*?-->', '', normalized, flags=re.DOTALL)
        
        return normalized.strip()
    
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words and symbols."""
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
        """Determine if differences are significant."""
        reasons = []
        
        # Check similarity threshold
        if similarity < self.significance_threshold:
            reasons.append(f"Low similarity: {similarity:.2%} (threshold: {self.significance_threshold:.2%})")
        
        # Check byte diff
        if byte_diff >= self.min_byte_diff:
            reasons.append(f"Significant byte difference: {byte_diff} bytes")
        
        # Check for error indicators
        error_keywords = ['error', 'exception', 'warning', 'failed', 'denied', 'forbidden', 'unauthorized']
        
        for line in added + [m[1] for m in modified]:
            for keyword in error_keywords:
                if keyword in line.lower():
                    reasons.append(f"Error indicator found: '{keyword}' in added/modified content")
                    break
        
        # Check for SQL/database errors
        db_error_patterns = [
            r'SQL syntax',
            r'mysql_',
            r'ORA-\d+',
            r'PostgreSQL',
            r'sqlite',
        ]
        
        all_new_content = ' '.join(added + [m[1] for m in modified])
        for pattern in db_error_patterns:
            if re.search(pattern, all_new_content, re.IGNORECASE):
                reasons.append(f"Database error pattern detected: {pattern}")
                break
        
        # Check for authentication changes
        auth_keywords = ['login', 'logout', 'authenticated', 'session', 'unauthorized']
        
        for line in added + removed + [m[1] for m in modified]:
            for keyword in auth_keywords:
                if keyword in line.lower():
                    reasons.append(f"Authentication-related change: '{keyword}'")
                    break
        
        # Significant if we have reasons
        return len(reasons) > 0, reasons
    
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
        
        Args:
            baseline: Baseline response
            test_responses: List of test responses to compare
            labels: Optional labels for each test response
            
        Returns:
            Dictionary mapping labels to ResponseDiff objects
        """
        if labels is None:
            labels = [f"Test {i+1}" for i in range(len(test_responses))]
        
        results = {}
        
        for label, test_response in zip(labels, test_responses):
            diff = self.compare_responses(baseline, test_response)
            results[label] = diff
        
        return results
    
    def detect_boolean_based(
        self,
        baseline: str,
        true_response: str,
        false_response: str
    ) -> Dict[str, Any]:
        """
        Detect boolean-based blind vulnerabilities.
        
        Compares true and false condition responses against baseline.
        
        Args:
            baseline: Normal response
            true_response: Response when condition is TRUE
            false_response: Response when condition is FALSE
            
        Returns:
            Analysis of boolean behavior
        """
        true_diff = self.compare_responses(baseline, true_response)
        false_diff = self.compare_responses(baseline, false_response)
        
        # Compare true vs false
        true_vs_false = self.compare_responses(true_response, false_response)
        
        # Boolean-based if true and false differ significantly from each other
        # but each is consistent (similar to baseline or predictably different)
        is_boolean_based = (
            true_vs_false.is_significant and
            (true_diff.similarity_ratio > 0.85 or false_diff.similarity_ratio > 0.85)
        )
        
        return {
            "is_boolean_based": is_boolean_based,
            "true_diff": {
                "similarity_to_baseline": true_diff.similarity_ratio,
                "is_significant": true_diff.is_significant,
                "reasons": true_diff.significance_reasons
            },
            "false_diff": {
                "similarity_to_baseline": false_diff.similarity_ratio,
                "is_significant": false_diff.is_significant,
                "reasons": false_diff.significance_reasons
            },
            "true_vs_false": {
                "similarity": true_vs_false.similarity_ratio,
                "byte_diff": true_vs_false.byte_diff_count,
                "is_significant": true_vs_false.is_significant
            },
            "recommendation": (
                "Likely boolean-based blind vulnerability - TRUE and FALSE conditions produce different responses"
                if is_boolean_based else
                "Responses do not show clear boolean behavior"
            )
        }
    
    def calculate_response_hash(self, response: str, normalize: bool = True) -> str:
        """
        Calculate hash of response for quick comparison.
        
        Args:
            response: Response content
            normalize: Whether to normalize before hashing
            
        Returns:
            MD5 hash of response
        """
        content = self._normalize_response(response) if normalize else response
        return hashlib.md5(content.encode()).hexdigest()
    
    def find_unique_responses(
        self,
        responses: List[str],
        normalize: bool = True
    ) -> Dict[str, List[int]]:
        """
        Group responses by similarity.
        
        Args:
            responses: List of responses
            normalize: Whether to normalize before comparison
            
        Returns:
            Dictionary mapping response hash to list of indices
        """
        groups = {}
        
        for idx, response in enumerate(responses):
            hash_val = self.calculate_response_hash(response, normalize)
            if hash_val not in groups:
                groups[hash_val] = []
            groups[hash_val].append(idx)
        
        return groups


# Convenience function
def compare_responses(
    baseline: str,
    test: str,
    normalize: bool = True
) -> ResponseDiff:
    """Quick response comparison."""
    detector = DiffDetector()
    return detector.compare_responses(baseline, test, normalize)
