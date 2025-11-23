"""
Finding merger for deduplicating similar vulnerability findings.

Implements conservative merging logic that only combines findings when
they are highly similar in both title and file_paths, and have the same severity.
"""
import logging
from typing import List, Set

from agent.services.models import VulnerabilityFinding

logger = logging.getLogger(__name__)


# Severity hierarchy for comparison (higher index = higher severity)
SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
    "Informational": 1,  # Alias for Info
}


def _normalize_title(title: str) -> str:
    """
    Normalize title for comparison by lowercasing and removing extra whitespace.
    
    Args:
        title: Title string to normalize
        
    Returns:
        Normalized title
    """
    return " ".join(title.strip().lower().split())


def _normalize_file_path(path: str) -> str:
    """
    Normalize file path for comparison by lowercasing and stripping whitespace.
    
    Args:
        path: File path string to normalize
        
    Returns:
        Normalized file path
    """
    return path.strip().lower()


def _titles_similar(title1: str, title2: str, threshold: float = 0.75) -> bool:
    """
    Check if two titles are similar enough to be considered duplicates.
    
    Uses simple word overlap and substring matching for conservative comparison.
    Titles are normalized (lowercase, stripped) before comparison.
    
    Args:
        title1: First title
        title2: Second title
        threshold: Similarity threshold (0.0 to 1.0), default 0.75
        
    Returns:
        True if titles are similar enough
    """
    # Normalize titles before comparison
    norm1 = _normalize_title(title1)
    norm2 = _normalize_title(title2)
    
    # Exact match after normalization
    if norm1 == norm2:
        return True
    
    # Check if one title contains the other (for cases like "Reentrancy" vs "Reentrancy vulnerability")
    if norm1 in norm2 or norm2 in norm1:
        return True
    
    # Word-based similarity: count common words
    words1 = set(norm1.split())
    words2 = set(norm2.split())
    
    if not words1 or not words2:
        return False
    
    # Calculate Jaccard similarity (intersection over union)
    intersection = len(words1 & words2)
    union = len(words1 | words2)
    
    if union == 0:
        return False
    
    similarity = intersection / union
    
    # Also check if significant words overlap
    # If more than 50% of words from shorter title are in longer title
    min_words = min(len(words1), len(words2))
    if min_words > 0 and intersection >= (min_words * 0.5):
        return True
    
    return similarity >= threshold


def _file_paths_overlap(paths1: List[str], paths2: List[str], min_overlap: int = 1) -> bool:
    """
    Check if file paths overlap significantly.
    
    File paths are normalized (lowercase, stripped) before comparison.
    
    Args:
        paths1: First list of file paths
        paths2: Second list of file paths
        min_overlap: Minimum number of overlapping paths required (default: 1)
        
    Returns:
        True if paths overlap enough
    """
    # Normalize file paths before comparison
    set1 = set(_normalize_file_path(p) for p in paths1)
    set2 = set(_normalize_file_path(p) for p in paths2)
    
    # Check if there's at least min_overlap common paths
    overlap = len(set1 & set2)
    
    if overlap >= min_overlap:
        return True
    
    # If one list is empty or both are empty, don't consider them overlapping
    if not paths1 or not paths2:
        return False
    
    # If one set is a subset of the other, consider it overlapping
    if set1.issubset(set2) or set2.issubset(set1):
        return True
    
    return False


def _severities_match(severity1: str, severity2: str) -> bool:
    """
    Check if two severities match exactly (case-insensitive, whitespace-normalized).
    
    Findings must have identical severities to be merged - this is a strict requirement.
    
    Args:
        severity1: First severity
        severity2: Second severity
        
    Returns:
        True if severities match exactly
    """
    return severity1.strip().lower() == severity2.strip().lower()


def _get_higher_severity(severity1: str, severity2: str) -> str:
    """
    Return the higher severity of the two.
    
    Args:
        severity1: First severity
        severity2: Second severity
        
    Returns:
        Higher severity string
    """
    order1 = SEVERITY_ORDER.get(severity1.strip(), 0)
    order2 = SEVERITY_ORDER.get(severity2.strip(), 0)
    
    if order1 >= order2:
        return severity1
    return severity2


def _merge_findings(finding1: VulnerabilityFinding, finding2: VulnerabilityFinding) -> VulnerabilityFinding:
    """
    Merge two similar findings into one.
    
    Args:
        finding1: First finding
        finding2: Second finding
        
    Returns:
        Merged finding with:
        - Highest severity
        - Longest/most informative description
        - Union of file paths
        - More specific title (or first if equal)
    """
    # Get highest severity
    merged_severity = _get_higher_severity(finding1.severity, finding2.severity)
    
    # Get longest description
    merged_description = finding1.description
    if len(finding2.description) > len(finding1.description):
        merged_description = finding2.description
    
    # Union of file paths (remove duplicates, preserve order)
    merged_paths = list(dict.fromkeys(finding1.file_paths + finding2.file_paths))
    
    # Use more specific title (longer one, or first if equal)
    merged_title = finding1.title
    if len(finding2.title) > len(finding1.title):
        merged_title = finding2.title
    
    return VulnerabilityFinding(
        title=merged_title,
        description=merged_description,
        severity=merged_severity,
        file_paths=merged_paths
    )


def merge_findings(findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
    """
    Merge duplicate or highly similar findings.
    
    Conservative merging strategy:
    - Only merges findings with similar titles AND overlapping file paths
    - Only merges findings with the same severity
    - Keeps highest severity, longest description, union of file paths
    
    Args:
        findings: List of findings to merge
        
    Returns:
        List of deduplicated findings
    """
    if not findings:
        return []
    
    if len(findings) == 1:
        return findings
    
    logger.info(f"Merging {len(findings)} findings...")
    
    # Track which findings have been merged
    merged_indices: Set[int] = set()
    merged_findings: List[VulnerabilityFinding] = []
    
    for i, finding1 in enumerate(findings):
        if i in merged_indices:
            continue
        
        # Try to find similar findings to merge with
        current_merged = finding1
        merged_count = 0
        
        for j, finding2 in enumerate(findings[i + 1:], start=i + 1):
            if j in merged_indices:
                continue
            
            # Check if findings should be merged
            titles_similar = _titles_similar(finding1.title, finding2.title)
            paths_overlap = _file_paths_overlap(finding1.file_paths, finding2.file_paths)
            severities_match = _severities_match(finding1.severity, finding2.severity)
            
            if titles_similar and paths_overlap and severities_match:
                # Merge the findings
                current_merged = _merge_findings(current_merged, finding2)
                merged_indices.add(j)
                merged_count += 1
                logger.debug(
                    f"Merged finding {j} into {i}: "
                    f"'{finding2.title[:50]}...' -> '{current_merged.title[:50]}...'"
                )
        
        merged_findings.append(current_merged)
        
        if merged_count > 0:
            logger.debug(f"Merged {merged_count} duplicate(s) into finding {i}")
    
    logger.info(f"Merged {len(findings)} findings into {len(merged_findings)} unique findings")
    return merged_findings

