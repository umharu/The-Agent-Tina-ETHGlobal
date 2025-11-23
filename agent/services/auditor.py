"""
Core service for auditing Solidity contracts using OpenAI.
"""
import logging
from typing import List

from agent.services.models import Audit as _Audit, VulnerabilityFinding as _VulnerabilityFinding
from agent.services.router import StrategyRouter
from agent.services.strategies import (
    GeneralStrategy,
    ReentrancyStrategy,
    FlashLoanStrategy,
    AccessControlStrategy,
)

logger = logging.getLogger(__name__)

# Re-export models for backward compatibility
Audit = _Audit
VulnerabilityFinding = _VulnerabilityFinding
__all__ = ["SolidityAuditor", "Audit", "VulnerabilityFinding"]

class SolidityAuditor:
    """Service for auditing Solidity contracts using OpenAI."""
    
    def __init__(self, api_key: str, model: str):
        """
        Initialize the auditor with OpenAI credentials.
        
        Args:
            api_key: OpenAI API key
            model: OpenAI model to use
        """
        self.api_key = api_key
        self.model = model

    def audit_files(self, contracts: str, docs: str = "", additional_links: List[str] = None, additional_docs: str = None, qa_responses: List = None) -> Audit:
        """
        Audit Solidity contracts and return structured findings.
        
        Uses multiple specialized strategies to perform comprehensive analysis.
        
        Args:
            contracts: String containing all contract code
            docs: String containing documentation
            additional_links: List of additional reference links
            additional_docs: Additional documentation text
            qa_responses: List of question-answer pairs
            
        Returns:
            Audit object containing the findings
        """
        try:
            # Initialize optional parameters
            additional_links = additional_links or []
            qa_responses = qa_responses or []
            
            # Create all strategies
            strategies = [
                GeneralStrategy(self.api_key, self.model),
                ReentrancyStrategy(self.api_key, self.model),
                FlashLoanStrategy(self.api_key, self.model),
                AccessControlStrategy(self.api_key, self.model),
            ]
            
            # Create router and execute all strategies
            router = StrategyRouter(strategies)
            audit_result = router.execute_all(
                contracts=contracts,
                docs=docs,
                additional_links=additional_links,
                additional_docs=additional_docs,
                qa_responses=qa_responses
            )
            
            logger.info(f"Audit completed successfully with {len(audit_result.findings)} total findings")
            return audit_result
            
        except Exception as e:
            logger.error(f"Error during audit: {str(e)}", exc_info=True)
            return Audit(findings=[])