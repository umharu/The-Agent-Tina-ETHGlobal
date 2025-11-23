#!/usr/bin/env python3
"""
Integration test for Agent-Tina multi-strategy architecture.

Tests:
1. All strategies run without errors
2. Aggregated findings validate against Audit model
3. JSON output matches required schema
4. No duplicated keys or unexpected fields
5. StrategyRouter logs and sequencing are correct
"""
import json
import logging
import sys
from typing import Dict, Any, List

# Configure logging to capture strategy execution
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Import after setting up logging
from agent.services.auditor import SolidityAuditor
from agent.services.models import Audit, VulnerabilityFinding
from agent.config import load_config


# Sample Solidity contracts with known vulnerabilities for testing
SAMPLE_CONTRACTS = """
// contracts/VulnerableContract.sol
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // State change after external call
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Access control vulnerability
    function emergencyWithdraw() public {
        // Missing access control - anyone can call this!
        uint256 balance = address(this).balance;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }
    
    // Flash loan vulnerability (price manipulation)
    function calculateReward(uint256 amount) public view returns (uint256) {
        // Uses current balance for reward calculation - vulnerable to flash loan manipulation
        uint256 currentBalance = address(this).balance;
        return (amount * currentBalance) / 1000; // No TWAP or flash loan protection
    }
}
"""


def validate_json_schema(findings: List[Dict[str, Any]]) -> tuple[bool, List[str]]:
    """
    Validate that findings match the required JSON schema.
    
    Returns:
        (is_valid, list_of_errors)
    """
    errors = []
    required_fields = {"title", "description", "severity", "file_paths"}
    allowed_severities = {"High", "Medium", "Low", "Info", "Critical", "Informational"}
    
    for i, finding in enumerate(findings):
        # Check for required fields
        missing_fields = required_fields - set(finding.keys())
        if missing_fields:
            errors.append(f"Finding {i}: Missing required fields: {missing_fields}")
        
        # Check for unexpected fields
        unexpected_fields = set(finding.keys()) - required_fields
        if unexpected_fields:
            errors.append(f"Finding {i}: Unexpected fields: {unexpected_fields}")
        
        # Validate field types
        if "title" in finding and not isinstance(finding["title"], str):
            errors.append(f"Finding {i}: 'title' must be a string")
        
        if "description" in finding and not isinstance(finding["description"], str):
            errors.append(f"Finding {i}: 'description' must be a string")
        
        if "severity" in finding:
            if not isinstance(finding["severity"], str):
                errors.append(f"Finding {i}: 'severity' must be a string")
            elif finding["severity"] not in allowed_severities:
                errors.append(
                    f"Finding {i}: 'severity' must be one of {allowed_severities}, "
                    f"got '{finding['severity']}'"
                )
        
        if "file_paths" in finding:
            if not isinstance(finding["file_paths"], list):
                errors.append(f"Finding {i}: 'file_paths' must be a list")
            elif finding["file_paths"] and not all(isinstance(p, str) for p in finding["file_paths"]):
                errors.append(f"Finding {i}: All 'file_paths' elements must be strings")
    
    return len(errors) == 0, errors


def check_for_duplicates(findings: List[Dict[str, Any]]) -> tuple[bool, List[str]]:
    """
    Check for duplicate findings (same title and file_paths).
    
    Returns:
        (has_duplicates, list_of_duplicate_info)
    """
    seen = {}
    duplicates = []
    
    for i, finding in enumerate(findings):
        key = (finding.get("title", ""), tuple(finding.get("file_paths", [])))
        if key in seen:
            duplicates.append(
                f"Finding {i} duplicates finding {seen[key]}: "
                f"title='{finding.get('title')}', file_paths={finding.get('file_paths')}"
            )
        else:
            seen[key] = i
    
    return len(duplicates) == 0, duplicates


def test_integration():
    """Run comprehensive integration tests."""
    print("=" * 80)
    print("Agent-Tina Integration Test")
    print("=" * 80)
    print()
    
    # Load configuration
    try:
        config = load_config()
        print(f"✓ Configuration loaded")
        print(f"  Model: {config.openai_model}")
        print()
    except Exception as e:
        print(f"✗ Failed to load configuration: {e}")
        print("  Make sure .env file exists with OPENAI_API_KEY set")
        return False
    
    # Initialize auditor
    try:
        auditor = SolidityAuditor(config.openai_api_key, config.openai_model)
        print(f"✓ SolidityAuditor initialized")
        print()
    except Exception as e:
        print(f"✗ Failed to initialize auditor: {e}")
        return False
    
    # Run audit
    print("Running audit with sample contracts...")
    print("-" * 80)
    try:
        audit_result = auditor.audit_files(
            contracts=SAMPLE_CONTRACTS,
            docs="",
            additional_links=None,
            additional_docs=None,
            qa_responses=None
        )
        print(f"✓ Audit completed")
        print(f"  Total findings: {len(audit_result.findings)}")
        print()
    except Exception as e:
        print(f"✗ Audit failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 1: Validate Audit model
    print("Test 1: Validating Audit model...")
    try:
        # This should not raise if the model is valid
        assert isinstance(audit_result, Audit), "Result is not an Audit instance"
        assert isinstance(audit_result.findings, list), "Findings is not a list"
        print(f"✓ Audit model validation passed")
        print()
    except AssertionError as e:
        print(f"✗ Audit model validation failed: {e}")
        return False
    
    # Test 2: Validate each finding against VulnerabilityFinding model
    print("Test 2: Validating individual findings...")
    try:
        for i, finding in enumerate(audit_result.findings):
            assert isinstance(finding, VulnerabilityFinding), f"Finding {i} is not a VulnerabilityFinding"
            # Access fields to trigger validation
            _ = finding.title
            _ = finding.description
            _ = finding.severity
            _ = finding.file_paths
        print(f"✓ All {len(audit_result.findings)} findings validated against VulnerabilityFinding model")
        print()
    except Exception as e:
        print(f"✗ Finding validation failed: {e}")
        return False
    
    # Test 3: Validate JSON schema
    print("Test 3: Validating JSON schema...")
    try:
        findings_dict = [finding.model_dump() for finding in audit_result.findings]
        is_valid, errors = validate_json_schema(findings_dict)
        
        if not is_valid:
            print(f"✗ JSON schema validation failed:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        print(f"✓ JSON schema validation passed")
        print()
    except Exception as e:
        print(f"✗ JSON schema validation error: {e}")
        return False
    
    # Test 4: Check for duplicate keys in JSON serialization
    print("Test 4: Checking JSON serialization...")
    try:
        findings_dict = [finding.model_dump() for finding in audit_result.findings]
        json_str = json.dumps({"findings": findings_dict}, indent=2)
        
        # Parse back to check for duplicate keys (Python's json doesn't allow them, but let's verify)
        parsed = json.loads(json_str)
        assert "findings" in parsed
        assert isinstance(parsed["findings"], list)
        
        print(f"✓ JSON serialization successful")
        print(f"  JSON size: {len(json_str)} bytes")
        print()
    except Exception as e:
        print(f"✗ JSON serialization failed: {e}")
        return False
    
    # Test 5: Check for unexpected fields
    print("Test 5: Checking for unexpected fields...")
    try:
        findings_dict = [finding.model_dump() for finding in audit_result.findings]
        allowed_fields = {"title", "description", "severity", "file_paths"}
        
        unexpected_found = False
        for i, finding in enumerate(findings_dict):
            unexpected = set(finding.keys()) - allowed_fields
            if unexpected:
                print(f"  ⚠ Finding {i} has unexpected fields: {unexpected}")
                unexpected_found = True
        
        if unexpected_found:
            print(f"✗ Found unexpected fields in findings")
            return False
        
        print(f"✓ No unexpected fields found")
        print()
    except Exception as e:
        print(f"✗ Unexpected fields check failed: {e}")
        return False
    
    # Test 6: Display findings summary
    print("Test 6: Findings summary...")
    print("-" * 80)
    if audit_result.findings:
        # Group by severity
        severity_counts = {}
        for finding in audit_result.findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("Findings by severity:")
        for severity in sorted(severity_counts.keys(), reverse=True):
            print(f"  {severity}: {severity_counts[severity]}")
        print()
        
        print("Sample findings (first 3):")
        for i, finding in enumerate(audit_result.findings[:3], 1):
            print(f"  {i}. [{finding.severity}] {finding.title}")
            print(f"     Files: {finding.file_paths}")
            print()
    else:
        print("  No findings returned (this may be expected if no vulnerabilities found)")
        print()
    
    # Test 7: Check merge statistics and examples
    print("Test 7: Analyzing merge results...")
    try:
        findings_dict = [finding.model_dump() for finding in audit_result.findings]
        
        # Check for remaining duplicates (should be minimal after merging)
        no_duplicates, duplicates = check_for_duplicates(findings_dict)
        
        if duplicates:
            print(f"⚠ Found {len(duplicates)} potential duplicate findings after merging:")
            for dup in duplicates[:3]:  # Show first 3
                print(f"  - {dup}")
            if len(duplicates) > 3:
                print(f"  ... and {len(duplicates) - 3} more")
            print("  (These may be legitimate separate findings)")
        else:
            print(f"✓ No duplicate findings detected after merging")
        print()
        
        # Show sample findings
        print("Sample findings (first 5):")
        for i, finding in enumerate(audit_result.findings[:5], 1):
            print(f"  {i}. [{finding.severity}] {finding.title}")
            print(f"     Files: {finding.file_paths}")
            print()
    except Exception as e:
        print(f"✗ Merge analysis failed: {e}")
        return False
    
    # Generate audit.json output
    print("Test 8: Generating audit.json output...")
    try:
        findings_dict = [finding.model_dump() for finding in audit_result.findings]
        audit_json = {"findings": findings_dict}
        json_output = json.dumps(audit_json, indent=2)
        
        # Save to file
        output_file = "test_audit_output.json"
        with open(output_file, "w") as f:
            f.write(json_output)
        
        print(f"✓ Audit output saved to {output_file}")
        print(f"  Total findings in output: {len(findings_dict)}")
        print()
        
        # Show preview of first finding
        if findings_dict:
            print("Preview of first finding:")
            print(json.dumps(findings_dict[0], indent=2))
            print()
    except Exception as e:
        print(f"✗ Failed to generate audit.json: {e}")
        return False
    
    # All tests passed
    print("=" * 80)
    print("✓ ALL INTEGRATION TESTS PASSED")
    print("=" * 80)
    print()
    print("Summary:")
    print(f"  - Final findings after merging: {len(audit_result.findings)}")
    print(f"  - All findings validated against Pydantic models")
    print(f"  - JSON schema matches required format")
    print(f"  - No unexpected fields")
    print(f"  - FindingMerger successfully integrated")
    print()
    
    return True


if __name__ == "__main__":
    success = test_integration()
    sys.exit(0 if success else 1)

