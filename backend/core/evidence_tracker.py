"""
Evidence Chain Tracker - Maintains detailed evidence for vulnerability findings.

Tracks:
- Request/response pairs
- Timestamps and detection methods
- Confidence evolution
- Attack chains and correlations
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib


class DetectionMethod(str, Enum):
    """Methods used to detect vulnerabilities."""
    ERROR_BASED = "error_based"           # Error messages in response
    TIME_BASED = "time_based"             # Response time analysis
    BOOLEAN_BASED = "boolean_based"       # True/false response differences
    CONTENT_BASED = "content_based"       # Content changes in response
    OUT_OF_BAND = "out_of_band"          # External interactions (DNS, HTTP)
    SIGNATURE_BASED = "signature_based"   # Known vulnerability signatures
    BEHAVIORAL = "behavioral"             # Behavioral analysis
    AI_ANALYSIS = "ai_analysis"           # AI-powered detection


@dataclass
class RequestResponsePair:
    """Single request-response interaction."""
    timestamp: datetime
    request: Dict[str, Any]
    response: Dict[str, Any]
    response_time_ms: float
    status_code: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "request": self.request,
            "response": self.response,
            "response_time_ms": self.response_time_ms,
            "status_code": self.status_code
        }


@dataclass
class EvidenceChain:
    """
    Complete evidence chain for a vulnerability finding.
    
    Maintains chronological record of all tests, responses, and analysis
    that led to vulnerability confirmation.
    """
    vulnerability_id: str
    detection_method: DetectionMethod
    initial_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Request/response pairs
    interactions: List[RequestResponsePair] = field(default_factory=list)
    
    # Baseline for comparison
    baseline_interaction: Optional[RequestResponsePair] = None
    
    # Confidence evolution
    confidence_scores: List[Dict[str, Any]] = field(default_factory=list)
    
    # Attack chain (for multi-step exploits)
    attack_steps: List[str] = field(default_factory=list)
    
    # Correlation with other findings
    related_findings: List[str] = field(default_factory=list)
    
    # Analysis notes
    notes: List[str] = field(default_factory=list)
    
    def add_interaction(
        self,
        request: Dict[str, Any],
        response: Dict[str, Any],
        response_time_ms: float,
        status_code: int,
        note: Optional[str] = None
    ) -> None:
        """Add a request-response interaction to the chain."""
        interaction = RequestResponsePair(
            timestamp=datetime.utcnow(),
            request=request,
            response=response,
            response_time_ms=response_time_ms,
            status_code=status_code
        )
        self.interactions.append(interaction)
        
        if note:
            self.notes.append(f"[{interaction.timestamp.isoformat()}] {note}")
    
    def set_baseline(
        self,
        request: Dict[str, Any],
        response: Dict[str, Any],
        response_time_ms: float,
        status_code: int
    ) -> None:
        """Set baseline interaction for comparison."""
        self.baseline_interaction = RequestResponsePair(
            timestamp=datetime.utcnow(),
            request=request,
            response=response,
            response_time_ms=response_time_ms,
            status_code=status_code
        )
        self.notes.append(f"[{self.baseline_interaction.timestamp.isoformat()}] Baseline established")
    
    def update_confidence(self, score: float, reason: str) -> None:
        """Update confidence score with reasoning."""
        self.confidence_scores.append({
            "timestamp": datetime.utcnow().isoformat(),
            "score": score,
            "reason": reason
        })
    
    def add_attack_step(self, step_description: str) -> None:
        """Add step to attack chain."""
        self.attack_steps.append(f"{len(self.attack_steps) + 1}. {step_description}")
    
    def correlate_with(self, finding_id: str, relationship: str) -> None:
        """Link this finding with another."""
        self.related_findings.append({
            "finding_id": finding_id,
            "relationship": relationship,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def get_final_confidence(self) -> float:
        """Get the most recent confidence score."""
        if not self.confidence_scores:
            return 0.0
        return self.confidence_scores[-1]["score"]
    
    def get_total_response_time(self) -> float:
        """Calculate total time spent in interactions."""
        return sum(i.response_time_ms for i in self.interactions)
    
    def to_dict(self) -> Dict[str, Any]:
        """Export evidence chain to dictionary."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "detection_method": self.detection_method.value,
            "initial_timestamp": self.initial_timestamp.isoformat(),
            "baseline": self.baseline_interaction.to_dict() if self.baseline_interaction else None,
            "interactions": [i.to_dict() for i in self.interactions],
            "confidence_evolution": self.confidence_scores,
            "attack_chain": self.attack_steps,
            "related_findings": self.related_findings,
            "notes": self.notes,
            "summary": {
                "total_interactions": len(self.interactions),
                "final_confidence": self.get_final_confidence(),
                "total_time_ms": self.get_total_response_time()
            }
        }


class EvidenceTracker:
    """
    Centralized evidence tracking for all vulnerability findings.
    
    Manages evidence chains across multiple agents and correlates
    findings for comprehensive attack path analysis.
    """
    
    def __init__(self):
        self.evidence_chains: Dict[str, EvidenceChain] = {}
    
    def create_chain(
        self,
        vulnerability_id: str,
        detection_method: DetectionMethod
    ) -> EvidenceChain:
        """Create a new evidence chain."""
        chain = EvidenceChain(
            vulnerability_id=vulnerability_id,
            detection_method=detection_method
        )
        self.evidence_chains[vulnerability_id] = chain
        return chain
    
    def get_chain(self, vulnerability_id: str) -> Optional[EvidenceChain]:
        """Retrieve an evidence chain."""
        return self.evidence_chains.get(vulnerability_id)
    
    def generate_chain_id(self, url: str, parameter: str, vuln_type: str) -> str:
        """Generate unique ID for an evidence chain."""
        unique_string = f"{url}|{parameter}|{vuln_type}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:16]
    
    def correlate_findings(self, finding_id1: str, finding_id2: str, relationship: str) -> None:
        """Create bidirectional correlation between findings."""
        chain1 = self.get_chain(finding_id1)
        chain2 = self.get_chain(finding_id2)
        
        if chain1:
            chain1.correlate_with(finding_id2, relationship)
        if chain2:
            chain2.correlate_with(finding_id1, relationship)
    
    def get_all_chains(self) -> Dict[str, EvidenceChain]:
        """Get all evidence chains."""
        return self.evidence_chains
    
    def export_all(self) -> Dict[str, Any]:
        """Export all evidence chains to dictionary."""
        return {
            "total_chains": len(self.evidence_chains),
            "chains": {
                chain_id: chain.to_dict() 
                for chain_id, chain in self.evidence_chains.items()
            }
        }
    
    def get_high_confidence_chains(self, threshold: float = 80.0) -> List[EvidenceChain]:
        """Get evidence chains with high confidence scores."""
        return [
            chain for chain in self.evidence_chains.values()
            if chain.get_final_confidence() >= threshold
        ]
    
    def get_chains_by_method(self, method: DetectionMethod) -> List[EvidenceChain]:
        """Get all chains using a specific detection method."""
        return [
            chain for chain in self.evidence_chains.values()
            if chain.detection_method == method
        ]


# Global tracker instance
_evidence_tracker: Optional[EvidenceTracker] = None


def get_evidence_tracker() -> EvidenceTracker:
    """Get the global evidence tracker instance."""
    global _evidence_tracker
    if _evidence_tracker is None:
        _evidence_tracker = EvidenceTracker()
    return _evidence_tracker


def reset_evidence_tracker() -> None:
    """Reset the global evidence tracker."""
    global _evidence_tracker
    _evidence_tracker = EvidenceTracker()
