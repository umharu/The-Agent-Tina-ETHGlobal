# The Agent Tina – AI-Powered Solidity Audit Agent

An AI-powered security audit agent for Solidity smart contracts, built for an ETHGlobal hackathon. The Agent Tina analyzes smart contract codebases using multiple specialized analysis strategies to identify security vulnerabilities and produce comprehensive audit reports.

## Features

- **Multi-Strategy Analysis**: Employs specialized AI agents focused on different vulnerability categories:
  - **Reentrancy Detector**: Specialized in identifying reentrancy attack vectors
  - **Flash Loan Attack Vector Detector**: Detects vulnerabilities related to flash loan exploits
  - **Access Control & Privilege Escalation Detector**: Identifies authorization and access control issues
  - **General Strategy**: Broad security analysis for other common vulnerabilities
- **Security Findings Classification**: Findings are classified by severity level (Critical, High, Medium, Low, Informational)
- **Extensible Architecture**: Easy to add new specialized strategies and detectors
- **Dual Operation Modes**:
  - **Server mode**: Runs a webhook server to receive notifications from AgentArena when a new challenge begins
  - **Local mode**: Processes a GitHub repository directly via CLI
- **Structured Output**: Produces JSON reports with detailed findings, locations, and recommendations

## Installation

```bash
# Clone the repository
git clone https://github.com/umharu/The-Agent-Tina.git
cd The-Agent-Tina

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .

# Create .env file
cp .env.example .env  # If .env.example exists, or create .env manually
# Edit .env with your configuration (see Configuration section below)
```

## Configuration

Create a `.env` file in the project root with the following variables:

```env
# OpenAI Configuration
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4.1-nano-2025-04-14

# Logging
LOG_LEVEL=INFO
LOG_FILE=agent.log

# Server Mode (optional, only needed for AgentArena integration)
AGENTARENA_API_KEY=aa-...
WEBHOOK_AUTH_TOKEN=your_webhook_auth_token
DATA_DIR=./data
```

**Required for all modes:**
- `OPENAI_API_KEY`: Your OpenAI API key
- `OPENAI_MODEL`: The OpenAI model to use (default: `gpt-4.1-nano-2025-04-14`)

**Optional:**
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR) - default: `INFO`
- `LOG_FILE`: Path to log file - default: `agent.log`

**Server mode only:**
- `AGENTARENA_API_KEY`: Your AgentArena API key
- `WEBHOOK_AUTH_TOKEN`: Webhook authorization token
- `DATA_DIR`: Directory for storing audit data

## Usage

### Local Mode

Run the agent in local mode to audit a GitHub repository directly. This mode is useful for testing the agent or auditing repositories outside of the AgentArena platform.

**Basic usage:**

```bash
audit-agent local --repo https://github.com/umharu/Kipubank.git --output audit.json
```

This will:
1. Clone the specified repository
2. Analyze all Solidity contracts using all available strategies
3. Merge and deduplicate findings
4. Save the results to `audit.json` (or your specified output file)

**Additional options:**

```bash
# Audit a specific commit
audit-agent local --repo https://github.com/umharu/Kipubank.git --commit abc123 --output audit.json

# Select specific files to audit interactively
audit-agent local --repo https://github.com/umharu/Kipubank.git --only-selected-files --output audit.json

# View all available options
audit-agent --help
```

The output JSON file contains structured findings with:
- Vulnerability title and description
- Severity level
- File and line number references
- Recommendations for fixes

### Server Mode

⚠️ **Note**: Server mode is designed for integration with the AgentArena platform. For local testing, use local mode instead.

To run the agent in server mode:

1. Go to the [AgentArena website](https://app.agentarena.staging-nethermind.xyz/) and create a builder account
2. Register a new agent:
   - Give it a name and paste in its webhook URL (e.g., `http://localhost:8000/webhook`)
   - Generate a webhook authorization token
   - Copy the AgentArena API key and Webhook Authorization Token and paste them in your `.env` file
   - Click the `Test` button to verify the webhook is working
3. Run the agent in server mode:

```bash
audit-agent server
```

By default, the agent will run on port 8000. To use a custom port:

```bash
audit-agent server --port 8008
```

## How It Works

The Agent Tina uses a multi-strategy architecture to perform comprehensive security analysis:

1. **Strategy Execution**: The `agent` package orchestrates multiple specialized analysis strategies, each with its own dedicated system prompt optimized for specific vulnerability types.

2. **Parallel Analysis**: Each strategy independently analyzes the contract codebase:
   - **ReentrancyStrategy**: Focuses on reentrancy vulnerabilities using specialized prompts
   - **FlashLoanStrategy**: Detects flash loan attack vectors
   - **AccessControlStrategy**: Identifies access control and privilege escalation issues
   - **GeneralStrategy**: Performs broad security analysis

3. **Finding Aggregation**: The `StrategyRouter` coordinates execution and collects findings from all strategies. A `FindingMerger` utility then deduplicates and merges similar findings to produce a clean, consolidated report.

4. **AI-Powered Analysis**: All strategies use OpenAI models (configured via `OPENAI_MODEL`) to analyze code, understand context, and identify vulnerabilities that might be missed by static analysis tools alone.

5. **Report Generation**: The final audit result is structured as a JSON report containing all findings with severity levels, locations, and remediation recommendations.

The entire process runs from the CLI, making it easy to integrate into CI/CD pipelines or use for one-off audits.

## For ETHGlobal

This project was built for an ETHGlobal hackathon as a demonstration of AI-assisted security analysis for Solidity smart contracts. The Agent Tina showcases a multi-agent / multi-strategy audit architecture where specialized AI agents work together to provide comprehensive security coverage. By combining domain-specific expertise (reentrancy, flash loans, access control) with general security analysis, the system aims to catch vulnerabilities that might be missed by single-purpose tools.

## Roadmap / Future Work

Potential improvements and enhancements for The Agent Tina:

- **Additional Vulnerability Detectors**:
  - Price oracle manipulation detection
  - MEV (Maximal Extractable Value) attack vectors
  - Economic attack analysis (tokenomics, flash loan economics)
  - Front-running and sandwich attack detection

- **Enhanced Analysis**:
  - Better deduplication and ranking algorithms for findings
  - Cross-contract analysis and dependency tracking
  - Gas optimization recommendations
  - Code quality and best practices suggestions

- **Reporting & Visualization**:
  - HTML / Markdown report generation on top of `audit.json`
  - Interactive web UI or dashboard for viewing results
  - Visual code highlighting for identified vulnerabilities
  - Comparison tools for tracking fixes across commits

- **Performance & Scalability**:
  - Parallel strategy execution for faster analysis
  - Caching mechanisms for repeated analyses
  - Incremental analysis for large codebases

- **Integration**:
  - GitHub Actions integration
  - CI/CD pipeline plugins
  - IDE extensions (VS Code, etc.)

## License

MIT

🤝 Credits
Built with ❤️ by maximilian0.eth for ETH Global