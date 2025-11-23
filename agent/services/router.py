"""
Strategy router for coordinating multiple vulnerability detection strategies.
"""
import logging
from typing import List, Optional

from agent.services.models import Audit, VulnerabilityFinding
from agent.services.strategies.base_strategy import BaseStrategy
from agent.services.utils.finding_merger import merge_findings

logger = logging.getLogger(__name__)


class StrategyRouter:
    """
    Coordinates execution of multiple vulnerability detection strategies.
    
    The router executes strategies in parallel (when possible) and aggregates
    their findings. It handles errors gracefully, ensuring one strategy failure
    doesn't break the entire audit.
    """
    
    def __init__(self, strategies: List[BaseStrategy]):
        """
        Initialize the router with a list of strategies.
        
        Args:
            strategies: List of BaseStrategy instances to execute
        """
        # Sort strategies by priority (higher priority first)
        self.strategies = sorted(strategies, key=lambda s: s.priority, reverse=True)
        logger.info(f"Initialized StrategyRouter with {len(self.strategies)} strategies")
        for strategy in self.strategies:
            logger.debug(f"  - {strategy.name} (priority: {strategy.priority})")
    
    def execute_all(
        self,
        contracts: str,
        docs: str = "",
        additional_links: Optional[List[str]] = None,
        additional_docs: Optional[str] = None,
        qa_responses: Optional[List] = None
    ) -> Audit:
        """
        Execute all strategies and aggregate findings.
        
        Currently executes strategies sequentially. Future enhancement:
        can be made async for parallel execution.
        
        After all strategies complete, findings are merged to remove duplicates
        using conservative merging logic.
        
        Args:
            contracts: String containing all contract code
            docs: String containing documentation
            additional_links: List of additional reference links
            additional_docs: Additional documentation text
            qa_responses: List of question-answer pairs
            
        Returns:
            Audit object containing aggregated and deduplicated findings from all strategies
        """
        all_findings: List[VulnerabilityFinding] = []
        
        # Execute all strategies
        for strategy in self.strategies:
            try:
                logger.info(f"Executing strategy: {strategy.name}")
                findings = strategy.analyze(
                    contracts=contracts,
                    docs=docs,
                    additional_links=additional_links,
                    additional_docs=additional_docs,
                    qa_responses=qa_responses
                )
                
                logger.info(f"Strategy {strategy.name} found {len(findings)} vulnerabilities")
                all_findings.extend(findings)
                
            except Exception as e:
                logger.error(
                    f"Strategy {strategy.name} failed: {str(e)}",
                    exc_info=True
                )
                # Continue with other strategies even if one fails
                continue
        
        logger.info(f"Total findings from all strategies: {len(all_findings)}")
        
        # Merge duplicate findings
        if all_findings:
            merged_findings = merge_findings(all_findings)
            logger.info(f"After merging: {len(merged_findings)} unique findings")
        else:
            merged_findings = []
        
        return Audit(findings=merged_findings)

