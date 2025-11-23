"""
Abstract base class for vulnerability detection strategies.
"""
import logging
from abc import ABC, abstractmethod
from typing import List, Optional

from agent.services.models import VulnerabilityFinding

logger = logging.getLogger(__name__)


class BaseStrategy(ABC):
    """
    Abstract base class for all vulnerability detection strategies.
    
    Each strategy focuses on a specific class of vulnerabilities and uses
    specialized prompts to analyze contracts from that perspective.
    """
    
    def __init__(self, api_key: str, model: str):
        """
        Initialize the strategy with OpenAI credentials.
        
        Args:
            api_key: OpenAI API key
            model: OpenAI model to use
        """
        self.api_key = api_key
        self.model = model
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return the strategy identifier name.
        
        Returns:
            Strategy name (e.g., "reentrancy", "flash_loan")
        """
        pass
    
    @property
    @abstractmethod
    def priority(self) -> int:
        """
        Return the execution priority.
        
        Higher priority strategies are executed first.
        Default range: 0-100, where 100 is highest priority.
        
        Returns:
            Priority integer
        """
        pass
    
    @abstractmethod
    def analyze(
        self,
        contracts: str,
        docs: str = "",
        additional_links: Optional[List[str]] = None,
        additional_docs: Optional[str] = None,
        qa_responses: Optional[List] = None
    ) -> List[VulnerabilityFinding]:
        """
        Execute strategy analysis and return findings.
        
        Args:
            contracts: String containing all contract code
            docs: String containing documentation
            additional_links: List of additional reference links
            additional_docs: Additional documentation text
            qa_responses: List of question-answer pairs
            
        Returns:
            List of VulnerabilityFinding objects
        """
        pass
    
    def _format_qa_responses(self, qa_responses: Optional[List]) -> str:
        """
        Format QA responses for prompt inclusion.
        
        Args:
            qa_responses: List of QAPair objects
            
        Returns:
            Formatted string for prompt
        """
        if not qa_responses:
            return ""
        
        qa_formatted = "## Q&A Information\n"
        for qa in qa_responses:
            qa_formatted += f"Q: {qa.question}\nA: {qa.answer}\n\n"
        return qa_formatted
    
    def _format_additional_links(self, additional_links: Optional[List[str]]) -> str:
        """
        Format additional links for prompt inclusion.
        
        Args:
            additional_links: List of URL strings
            
        Returns:
            Formatted string for prompt
        """
        if not additional_links:
            return ""
        
        links_formatted = "## Additional References\n"
        for link in additional_links:
            links_formatted += f"- {link}\n"
        return links_formatted
    
    def _format_additional_docs(self, additional_docs: Optional[str]) -> str:
        """
        Format additional documentation for prompt inclusion.
        
        Args:
            additional_docs: Additional documentation text
            
        Returns:
            Formatted string for prompt
        """
        if not additional_docs:
            return ""
        
        return f"## Additional Documentation\n{additional_docs}\n"

