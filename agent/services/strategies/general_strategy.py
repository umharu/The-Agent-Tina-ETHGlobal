"""
General-purpose vulnerability detection strategy using the main audit prompt.
"""
import json
import logging
from typing import List, Optional

from openai import OpenAI

from agent.services.models import VulnerabilityFinding, Audit
from agent.services.prompts.audit_prompt import AUDIT_PROMPT
from agent.services.strategies.base_strategy import BaseStrategy

logger = logging.getLogger(__name__)


class GeneralStrategy(BaseStrategy):
    """
    General-purpose strategy that performs comprehensive vulnerability analysis.
    
    This strategy uses the main AUDIT_PROMPT and covers all vulnerability
    categories. It serves as the baseline analysis for every audit.
    """
    
    def __init__(self, api_key: str, model: str):
        """
        Initialize the general strategy.
        
        Args:
            api_key: OpenAI API key
            model: OpenAI model to use
        """
        super().__init__(api_key, model)
        self.client = OpenAI(api_key=api_key)
    
    @property
    def name(self) -> str:
        """Return strategy name."""
        return "general"
    
    @property
    def priority(self) -> int:
        """Return execution priority (highest priority for general analysis)."""
        return 100
    
    def analyze(
        self,
        contracts: str,
        docs: str = "",
        additional_links: Optional[List[str]] = None,
        additional_docs: Optional[str] = None,
        qa_responses: Optional[List] = None
    ) -> List[VulnerabilityFinding]:
        """
        Execute general vulnerability analysis.
        
        Args:
            contracts: String containing all contract code
            docs: String containing documentation
            additional_links: List of additional reference links
            additional_docs: Additional documentation text
            qa_responses: List of question-answer pairs
            
        Returns:
            List of VulnerabilityFinding objects
        """
        try:
            # Format inputs for prompt
            qa_formatted = self._format_qa_responses(qa_responses)
            links_formatted = self._format_additional_links(additional_links)
            additional_docs_formatted = self._format_additional_docs(additional_docs)
            
            # Prepare the audit prompt with all information
            audit_prompt = AUDIT_PROMPT.format(
                contracts=contracts,
                docs=docs,
                additional_links=links_formatted,
                additional_docs=additional_docs_formatted,
                qa_responses=qa_formatted
            )
            
            # Send request to OpenAI
            logger.info(f"[{self.name}] Sending audit request to OpenAI")
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert Solidity smart contract auditor."},
                    {"role": "user", "content": audit_prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            # Extract and parse the JSON response
            result_text = response.choices[0].message.content
            logger.debug(f"[{self.name}] Received audit response from OpenAI")
            
            try:
                # Parse the JSON response
                audit_result = json.loads(result_text)
                
                # Validate using Pydantic model
                validated_result = Audit(**audit_result)
                
                logger.info(
                    f"[{self.name}] Analysis completed successfully with "
                    f"{len(validated_result.findings)} findings"
                )
                return validated_result.findings
                
            except json.JSONDecodeError as json_err:
                logger.error(f"[{self.name}] Failed to parse JSON response: {json_err}")
                logger.debug(f"[{self.name}] Raw response: {result_text}")
                return []
            except Exception as validation_err:
                logger.error(
                    f"[{self.name}] Validation error with audit response: {validation_err}",
                    exc_info=True
                )
                return []
                
        except Exception as e:
            logger.error(
                f"[{self.name}] Error during analysis: {str(e)}",
                exc_info=True
            )
            return []

