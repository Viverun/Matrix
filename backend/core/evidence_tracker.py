"""
Evidence Chain Tracker - Maintains detailed evidence for vulnerability findings.

This module provides comprehensive evidence tracking for security vulnerability
findings, including request/response pairs, confidence evolution, attack chains,
and cross-finding correlations.

Features:
- Chronological request/response tracking
- Timestamp tracking with timezone awareness
- Detection method categorization
- Confidence score evolution
- Attack chain reconstruction
- Finding correlation
- Evidence export and analysis
"""
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from core.logger import get_logger

# Initialize structured logger
logger = get_logger(__name__)

# Configuration constants
DEFAULT_CONFIDENCE_THRESHOLD = 80.0
MAX_INTERACTIONS_PER_CHAIN = 1000
MAX_NOTES_PER_CHAIN = 500
EVIDENCE_CHAIN_ID_LENGTH = 16


class DetectionMethod(str, Enum):
    """
    Methods used to detect vulnerabilities.
    
    This enum categorizes the various techniques used to identify security
    vulnerabilities during scanning and testing.
    """
    ERROR_BASED = "error_based"           # Error messages in response
    TIME_BASED = "time_based"             # Response time analysis
    BOOLEAN_BASED = "boolean_based"       # True/false response differences
    CONTENT_BASED = "content_based"       # Content changes in response
    OUT_OF_BAND = "out_of_band"          # External interactions (DNS, HTTP)
    SIGNATURE_BASED = "signature_based"   # Known vulnerability signatures
    BEHAVIORAL = "behavioral"             # Behavioral analysis
    AI_ANALYSIS = "ai_analysis"           # AI-powered detection
    DIFF_BASED = "diff_based"             # Response diff analysis
    PATTERN_MATCHING = "pattern_matching" # Regex/pattern matching


@dataclass
class RequestResponsePair:
    """
    Single request-response interaction with timing and status information.
    
    This dataclass captures a complete HTTP interaction for evidence tracking,
    including request details, response data, timing metrics, and status codes.
    
    Attributes:
        timestamp: When the interaction occurred (timezone-aware)
        request: Request details (method, URL, headers, body, etc.)
        response: Response data (headers, body, etc.)
        response_time_ms: Time taken for the response in milliseconds
        status_code: HTTP status code
        metadata: Additional context about the interaction
    """
    timestamp: datetime
    request: Dict[str, Any]
    response: Dict[str, Any]
    response_time_ms: float
    status_code: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.
        
        Returns:
            Dictionary representation of the interaction.
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "request": self.request,
            "response": self.response,
            "response_time_ms": self.response_time_ms,
            "status_code": status_code,
            "metadata": self.metadata
        }
    
    def get_request_summary(self) -> str:
        """
        Get a brief summary of the request.
        
        Returns:
            Human-readable request summary.
        """
        method = self.request.get('method', 'UNKNOWN')
        url = self.request.get('url', 'unknown')
        return f"{method} {url} -> {self.status_code} ({self.response_time_ms:.2f}ms)"


@dataclass
class EvidenceChain:
    """
    Complete evidence chain for a vulnerability finding.
    
    This class maintains a chronological record of all tests, responses, and
    analysis that led to vulnerability confirmation. It tracks confidence
    evolution, attack steps, and correlations with other findings.
    
    Attributes:
        vulnerability_id: Unique identifier for the vulnerability
        detection_method: Method used to detect the vulnerability
        initial_timestamp: When evidence collection started
        interactions: List of all request-response pairs
        baseline_interaction: Baseline for comparison
        confidence_scores: Evolution of confidence over time
        attack_steps: Sequential steps in the attack chain
        related_findings: IDs of correlated findings
        notes: Timestamped analysis notes
        metadata: Additional context about the chain
    """
    vulnerability_id: str
    detection_method: DetectionMethod
    initial_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Request/response pairs
    interactions: List[RequestResponsePair] = field(default_factory=list)
    
    # Baseline for comparison
    baseline_interaction: Optional[RequestResponsePair] = None
    
    # Confidence evolution
    confidence_scores: List[Dict[str, Any]] = field(default_factory=list)
    
    # Attack chain (for multi-step exploits)
    attack_steps: List[str] = field(default_factory=list)
    
    # Correlation with other findings
    related_findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # Analysis notes
    notes: List[str] = field(default_factory=list)
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_interaction(
        self,
        request: Dict[str, Any],
        response: Dict[str, Any],
        response_time_ms: float,
        status_code: int,
        note: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add a request-response interaction to the evidence chain.
        
        Args:
            request: Request details (method, URL, headers, body)
            response: Response data (headers, body, status)
            response_time_ms: Response time in milliseconds
            status_code: HTTP status code
            note: Optional note about this interaction
            metadata: Additional metadata for this interaction
            
        Raises:
            ValueError: If max interactions limit is reached
        """
        if len(self.interactions) >= MAX_INTERACTIONS_PER_CHAIN:
            logger.warning(
                f"Evidence chain {self.vulnerability_id} reached max interactions "
                f"({MAX_INTERACTIONS_PER_CHAIN})"
            )
            raise ValueError(f"Maximum interactions ({MAX_INTERACTIONS_PER_CHAIN}) reached")
        
        try:
            interaction = RequestResponsePair(
                timestamp=datetime.now(timezone.utc),
                request=request,
                response=response,
                response_time_ms=response_time_ms,
                status_code=status_code,
                metadata=metadata or {}
            )
            self.interactions.append(interaction)
            
            if note:
                self.add_note(note)
            
            logger.debug(
                f"Added interaction to chain {self.vulnerability_id}: "
                f"{interaction.get_request_summary()}"
            )
            
        except Exception as e:
            logger.error(
                f"Failed to add interaction to chain {self.vulnerability_id}: {str(e)}",
                exc_info=True
            )
            raise
    
    def set_baseline(
        self,
        request: Dict[str, Any],
        response: Dict[str, Any],
        response_time_ms: float,
        status_code: int,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Set baseline interaction for comparison purposes.
        
        The baseline represents the normal/expected behavior against which
        exploitation attempts are compared.
        
        Args:
            request: Baseline request details
            response: Baseline response data
            response_time_ms: Baseline response time
            status_code: Baseline status code
            metadata: Additional metadata for baseline
        """
        try:
            self.baseline_interaction = RequestResponsePair(
                timestamp=datetime.now(timezone.utc),
                request=request,
                response=response,
                response_time_ms=response_time_ms,
                status_code=status_code,
                metadata=metadata or {}
            )
            
            self.add_note("Baseline established")
            logger.info(
                f"Baseline set for chain {self.vulnerability_id}: "
                f"{self.baseline_interaction.get_request_summary()}"
            )
            
        except Exception as e:
            logger.error(f"Failed to set baseline: {str(e)}", exc_info=True)
            raise
    
    def update_confidence(self, score: float, reason: str) -> None:
        """
        Update confidence score with reasoning.
        
        Confidence scores track how certain the system is about the vulnerability
        finding as more evidence is collected.
        
        Args:
            score: Confidence score (0.0-100.0)
            reason: Explanation for the confidence level
            
        Raises:
            ValueError: If score is out of valid range
        """
        if not 0.0 <= score <= 100.0:
            raise ValueError(f"Confidence score must be between 0.0 and 100.0, got {score}")
        
        try:
            confidence_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "score": score,
                "reason": reason
            }
            self.confidence_scores.append(confidence_entry)
            
            logger.debug(
                f"Confidence updated for chain {self.vulnerability_id}: "
                f"{score:.1f}% - {reason}"
            )
            
        except Exception as e:
            logger.error(f"Failed to update confidence: {str(e)}", exc_info=True)
            raise
    
    def add_attack_step(self, step_description: str) -> None:
        """
        Add a step to the attack chain.
        
        Attack chains document the sequential steps required to exploit
        a vulnerability, useful for understanding exploit paths.
        
        Args:
            step_description: Description of the attack step
        """
        try:
            step_number = len(self.attack_steps) + 1
            formatted_step = f"{step_number}. {step_description}"
            self.attack_steps.append(formatted_step)
            
            logger.debug(f"Attack step added to chain {self.vulnerability_id}: {formatted_step}")
            
        except Exception as e:
            logger.warning(f"Failed to add attack step: {str(e)}")
    
    def correlate_with(self, finding_id: str, relationship: str) -> None:
        """
        Link this finding with another related finding.
        
        Correlation helps identify relationships between vulnerabilities,
        such as chained exploits or related security issues.
        
        Args:
            finding_id: ID of the related finding
            relationship: Description of the relationship
        """
        try:
            correlation = {
                "finding_id": finding_id,
                "relationship": relationship,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.related_findings.append(correlation)
            
            logger.info(
                f"Chain {self.vulnerability_id} correlated with {finding_id}: {relationship}"
            )
            
        except Exception as e:
            logger.warning(f"Failed to correlate findings: {str(e)}")
    
    def add_note(self, note: str) -> None:
        """
        Add a timestamped note to the evidence chain.
        
        Args:
            note: Note text to add
            
        Raises:
            ValueError: If max notes limit is reached
        """
        if len(self.notes) >= MAX_NOTES_PER_CHAIN:
            logger.warning(f"Chain {self.vulnerability_id} reached max notes limit")
            raise ValueError(f"Maximum notes ({MAX_NOTES_PER_CHAIN}) reached")
        
        timestamp = datetime.now(timezone.utc).isoformat()
        formatted_note = f"[{timestamp}] {note}"
        self.notes.append(formatted_note)
    
    def get_final_confidence(self) -> float:
        """
        Get the most recent confidence score.
        
        Returns:
            Latest confidence score, or 0.0 if no scores recorded.
        """
        if not self.confidence_scores:
            return 0.0
        return self.confidence_scores[-1]["score"]
    
    def get_confidence_trend(self) -> str:
        """
        Analyze the confidence trend over time.
        
        Returns:
            String describing trend: "increasing", "decreasing", "stable", or "no_data"
        """
        if len(self.confidence_scores) < 2:
            return "no_data"
        
        scores = [entry["score"] for entry in self.confidence_scores]
        first_half_avg = sum(scores[:len(scores)//2]) / (len(scores)//2)
        second_half_avg = sum(scores[len(scores)//2:]) / (len(scores) - len(scores)//2)
        
        diff = second_half_avg - first_half_avg
        
        if abs(diff) < 5.0:
            return "stable"
        elif diff > 0:
            return "increasing"
        else:
            return "decreasing"
    
    def get_total_response_time(self) -> float:
        """
        Calculate total time spent in all interactions.
        
        Returns:
            Total response time in milliseconds.
        """
        return sum(i.response_time_ms for i in self.interactions)
    
    def get_average_response_time(self) -> float:
        """
        Calculate average response time across interactions.
        
        Returns:
            Average response time in milliseconds, or 0.0 if no interactions.
        """
        if not self.interactions:
            return 0.0
        return self.get_total_response_time() / len(self.interactions)
    
    def get_status_code_distribution(self) -> Dict[int, int]:
        """
        Get distribution of HTTP status codes in interactions.
        
        Returns:
            Dictionary mapping status codes to occurrence counts.
        """
        distribution: Dict[int, int] = {}
        for interaction in self.interactions:
            code = interaction.status_code
            distribution[code] = distribution.get(code, 0) + 1
        return distribution
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Export evidence chain to dictionary for serialization.
        
        Returns:
            Complete dictionary representation of the evidence chain.
        """
        try:
            return {
                "vulnerability_id": self.vulnerability_id,
                "detection_method": self.detection_method.value,
                "initial_timestamp": self.initial_timestamp.isoformat(),
                "baseline": self.baseline_interaction.to_dict() if self.baseline_interaction else None,
                "interactions": [i.to_dict() for i in self.interactions],
                "confidence_evolution": self.confidence_scores,
                "confidence_trend": self.get_confidence_trend(),
                "attack_chain": self.attack_steps,
                "related_findings": self.related_findings,
                "notes": self.notes,
                "metadata": self.metadata,
                "summary": {
                    "total_interactions": len(self.interactions),
                    "final_confidence": self.get_final_confidence(),
                    "total_time_ms": self.get_total_response_time(),
                    "average_time_ms": self.get_average_response_time(),
                    "status_codes": self.get_status_code_distribution(),
                    "has_baseline": self.baseline_interaction is not None,
                    "attack_steps_count": len(self.attack_steps),
                    "related_findings_count": len(self.related_findings)
                }
            }
        except Exception as e:
            logger.error(f"Failed to serialize evidence chain: {str(e)}", exc_info=True)
            return {
                "vulnerability_id": self.vulnerability_id,
                "error": f"Serialization failed: {str(e)}"
            }
    
    def to_json(self, indent: int = 2) -> str:
        """
        Export evidence chain to JSON string.
        
        Args:
            indent: Number of spaces for JSON indentation
            
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=indent)


class EvidenceTracker:
    """
    Centralized evidence tracking for all vulnerability findings.
    
    This class manages evidence chains across multiple agents and correlates
    findings for comprehensive attack path analysis. It provides a global
    repository for all evidence collected during security scans.
    
    Features:
    - Create and manage evidence chains
    - Cross-finding correlation
    - High-confidence finding identification
    - Detection method filtering
    - Bulk export capabilities
    - Statistics and reporting
    
    Example:
        ```python
        tracker = get_evidence_tracker()
        
        # Create evidence chain
        chain_id = tracker.generate_chain_id(url, param, "sqli")
        chain = tracker.create_chain(chain_id, DetectionMethod.ERROR_BASED)
        
        # Add interactions
        chain.add_interaction(req, resp, 150.5, 200, "Testing payload")
        chain.update_confidence(85.0, "Error message detected")
        
        # Export findings
        high_confidence = tracker.get_high_confidence_chains(threshold=80.0)
        ```
    """
    
    def __init__(self) -> None:
        """Initialize the evidence tracker."""
        self.evidence_chains: Dict[str, EvidenceChain] = {}
        self._creation_time = datetime.now(timezone.utc)
        logger.info("EvidenceTracker initialized")
    
    def create_chain(
        self,
        vulnerability_id: str,
        detection_method: DetectionMethod,
        metadata: Optional[Dict[str, Any]] = None
    ) -> EvidenceChain:
        """
        Create a new evidence chain.
        
        Args:
            vulnerability_id: Unique identifier for the vulnerability
            detection_method: Method used for detection
            metadata: Additional metadata for the chain
            
        Returns:
            Newly created EvidenceChain instance
            
        Raises:
            ValueError: If chain with this ID already exists
        """
        if vulnerability_id in self.evidence_chains:
            logger.warning(f"Evidence chain {vulnerability_id} already exists")
            raise ValueError(f"Evidence chain {vulnerability_id} already exists")
        
        try:
            chain = EvidenceChain(
                vulnerability_id=vulnerability_id,
                detection_method=detection_method,
                metadata=metadata or {}
            )
            self.evidence_chains[vulnerability_id] = chain
            
            logger.info(
                f"Created evidence chain: {vulnerability_id} "
                f"(method: {detection_method.value})"
            )
            
            return chain
            
        except Exception as e:
            logger.error(f"Failed to create evidence chain: {str(e)}", exc_info=True)
            raise
    
    def get_chain(self, vulnerability_id: str) -> Optional[EvidenceChain]:
        """
        Retrieve an evidence chain by ID.
        
        Args:
            vulnerability_id: ID of the chain to retrieve
            
        Returns:
            EvidenceChain if found, None otherwise
        """
        chain = self.evidence_chains.get(vulnerability_id)
        if chain is None:
            logger.debug(f"Evidence chain not found: {vulnerability_id}")
        return chain
    
    def get_or_create_chain(
        self,
        vulnerability_id: str,
        detection_method: DetectionMethod,
        metadata: Optional[Dict[str, Any]] = None
    ) -> EvidenceChain:
        """
        Get existing chain or create new one if it doesn't exist.
        
        Args:
            vulnerability_id: Chain identifier
            detection_method: Detection method for new chains
            metadata: Metadata for new chains
            
        Returns:
            Existing or newly created EvidenceChain
        """
        chain = self.get_chain(vulnerability_id)
        if chain is None:
            chain = self.create_chain(vulnerability_id, detection_method, metadata)
        return chain
    
    def generate_chain_id(
        self,
        url: str,
        parameter: str,
        vuln_type: str,
        algorithm: str = "md5"
    ) -> str:
        """
        Generate unique ID for an evidence chain.
        
        Args:
            url: Target URL
            parameter: Parameter name being tested
            vuln_type: Type of vulnerability (e.g., "sqli", "xss")
            algorithm: Hash algorithm to use ("md5" or "sha256")
            
        Returns:
            Unique chain identifier
            
        Raises:
            ValueError: If algorithm is not supported
        """
        if algorithm not in ("md5", "sha256"):
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        try:
            unique_string = f"{url}|{parameter}|{vuln_type}"
            
            if algorithm == "md5":
                hash_obj = hashlib.md5(unique_string.encode())
            else:
                hash_obj = hashlib.sha256(unique_string.encode())
            
            chain_id = hash_obj.hexdigest()[:EVIDENCE_CHAIN_ID_LENGTH]
            
            logger.debug(f"Generated chain ID: {chain_id} for {vuln_type} on {parameter}")
            
            return chain_id
            
        except Exception as e:
            logger.error(f"Failed to generate chain ID: {str(e)}")
            raise
    
    def correlate_findings(
        self,
        finding_id1: str,
        finding_id2: str,
        relationship: str
    ) -> bool:
        """
        Create bidirectional correlation between findings.
        
        Args:
            finding_id1: First finding ID
            finding_id2: Second finding ID
            relationship: Description of the relationship
            
        Returns:
            True if correlation succeeded, False otherwise
        """
        try:
            chain1 = self.get_chain(finding_id1)
            chain2 = self.get_chain(finding_id2)
            
            success = False
            
            if chain1:
                chain1.correlate_with(finding_id2, relationship)
                success = True
            else:
                logger.warning(f"Cannot correlate: chain {finding_id1} not found")
            
            if chain2:
                chain2.correlate_with(finding_id1, relationship)
                success = True
            else:
                logger.warning(f"Cannot correlate: chain {finding_id2} not found")
            
            if success:
                logger.info(f"Correlated findings: {finding_id1} <-> {finding_id2}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to correlate findings: {str(e)}", exc_info=True)
            return False
    
    def delete_chain(self, vulnerability_id: str) -> bool:
        """
        Delete an evidence chain.
        
        Args:
            vulnerability_id: ID of the chain to delete
            
        Returns:
            True if deleted, False if not found
        """
        if vulnerability_id in self.evidence_chains:
            del self.evidence_chains[vulnerability_id]
            logger.info(f"Deleted evidence chain: {vulnerability_id}")
            return True
        else:
            logger.debug(f"Cannot delete: chain {vulnerability_id} not found")
            return False
    
    def get_all_chains(self) -> Dict[str, EvidenceChain]:
        """
        Get all evidence chains.
        
        Returns:
            Dictionary of all evidence chains
        """
        return self.evidence_chains
    
    def export_all(self) -> Dict[str, Any]:
        """
        Export all evidence chains to dictionary.
        
        Returns:
            Complete export of all evidence with metadata
        """
        try:
            return {
                "metadata": {
                    "total_chains": len(self.evidence_chains),
                    "tracker_created": self._creation_time.isoformat(),
                    "export_time": datetime.now(timezone.utc).isoformat()
                },
                "chains": {
                    chain_id: chain.to_dict()
                    for chain_id, chain in self.evidence_chains.items()
                }
            }
        except Exception as e:
            logger.error(f"Failed to export evidence chains: {str(e)}", exc_info=True)
            return {
                "error": f"Export failed: {str(e)}",
                "metadata": {"total_chains": len(self.evidence_chains)}
            }
    
    def export_to_json(self, filepath: Optional[str] = None, indent: int = 2) -> str:
        """
        Export all evidence to JSON.
        
        Args:
            filepath: Optional file path to write JSON to
            indent: Number of spaces for indentation
            
        Returns:
            JSON string
        """
        json_str = json.dumps(self.export_all(), indent=indent)
        
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                logger.info(f"Evidence exported to {filepath}")
            except Exception as e:
                logger.error(f"Failed to write evidence to {filepath}: {str(e)}")
                raise
        
        return json_str
    
    def get_high_confidence_chains(
        self,
        threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    ) -> List[EvidenceChain]:
        """
        Get evidence chains with high confidence scores.
        
        Args:
            threshold: Minimum confidence score (0.0-100.0)
            
        Returns:
            List of high-confidence evidence chains
        """
        high_conf_chains = [
            chain for chain in self.evidence_chains.values()
            if chain.get_final_confidence() >= threshold
        ]
        
        logger.debug(
            f"Found {len(high_conf_chains)} chains with confidence >= {threshold}%"
        )
        
        return high_conf_chains
    
    def get_chains_by_method(self, method: DetectionMethod) -> List[EvidenceChain]:
        """
        Get all chains using a specific detection method.
        
        Args:
            method: Detection method to filter by
            
        Returns:
            List of evidence chains using the specified method
        """
        filtered_chains = [
            chain for chain in self.evidence_chains.values()
            if chain.detection_method == method
        ]
        
        logger.debug(
            f"Found {len(filtered_chains)} chains using {method.value} method"
        )
        
        return filtered_chains
    
    def get_correlated_chains(self, vulnerability_id: str) -> List[EvidenceChain]:
        """
        Get all chains correlated with a specific finding.
        
        Args:
            vulnerability_id: ID of the finding
            
        Returns:
            List of correlated evidence chains
        """
        chain = self.get_chain(vulnerability_id)
        if not chain:
            return []
        
        related_ids = {rel["finding_id"] for rel in chain.related_findings}
        correlated = [
            self.evidence_chains[rid]
            for rid in related_ids
            if rid in self.evidence_chains
        ]
        
        logger.debug(f"Found {len(correlated)} chains correlated with {vulnerability_id}")
        
        return correlated
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about tracked evidence.
        
        Returns:
            Dictionary containing various statistics
        """
        if not self.evidence_chains:
            return {
                "total_chains": 0,
                "message": "No evidence chains tracked"
            }
        
        chains = list(self.evidence_chains.values())
        
        # Calculate statistics
        total_interactions = sum(len(c.interactions) for c in chains)
        total_response_time = sum(c.get_total_response_time() for c in chains)
        
        method_distribution = {}
        for chain in chains:
            method = chain.detection_method.value
            method_distribution[method] = method_distribution.get(method, 0) + 1
        
        confidence_scores = [c.get_final_confidence() for c in chains if c.confidence_scores]
        
        return {
            "total_chains": len(self.evidence_chains),
            "total_interactions": total_interactions,
            "total_response_time_ms": total_response_time,
            "average_interactions_per_chain": total_interactions / len(chains) if chains else 0,
            "detection_methods": method_distribution,
            "confidence_statistics": {
                "tracked_chains": len(confidence_scores),
                "average_confidence": sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0,
                "max_confidence": max(confidence_scores) if confidence_scores else 0,
                "min_confidence": min(confidence_scores) if confidence_scores else 0,
            },
            "high_confidence_count": len(self.get_high_confidence_chains()),
            "tracker_uptime_seconds": (datetime.now(timezone.utc) - self._creation_time).total_seconds()
        }
    
    def clear_all(self) -> int:
        """
        Clear all evidence chains.
        
        Returns:
            Number of chains cleared
        """
        count = len(self.evidence_chains)
        self.evidence_chains.clear()
        logger.warning(f"Cleared all evidence chains ({count} chains removed)")
        return count


# Global tracker instance
_evidence_tracker: Optional[EvidenceTracker] = None


def get_evidence_tracker() -> EvidenceTracker:
    """
    Get the global evidence tracker instance (singleton pattern).
    
    Returns:
        The global EvidenceTracker instance
    """
    global _evidence_tracker
    if _evidence_tracker is None:
        _evidence_tracker = EvidenceTracker()
        logger.debug("Created global evidence tracker instance")
    return _evidence_tracker


def reset_evidence_tracker() -> None:
    """
    Reset the global evidence tracker.
    
    This creates a fresh tracker instance, clearing all existing evidence.
    Useful for testing or starting new scan sessions.
    """
    global _evidence_tracker
    old_count = len(_evidence_tracker.evidence_chains) if _evidence_tracker else 0
    _evidence_tracker = EvidenceTracker()
    logger.info(f"Reset evidence tracker (cleared {old_count} chains)")