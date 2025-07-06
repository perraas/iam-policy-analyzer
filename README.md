# IAM Policy Analyzer

## Overview

IAM Policy Analyzer is a Python-based command-line tool that connects to an AWS account, retrieves IAM policies for users, roles, and groups, and analyzes them for potential security risks such as overly permissive actions, wildcard usage, or high-privilege access.

The goal of this project is to demonstrate how to interface with AWS using Python (`boto3`), understand IAM policy structures, and apply security best practices such as the principle of least privilege.

## Project Structure

```

iam-policy-analyzer/
├── analyzer.py
├── fetcher.py
├── reporter.py
├── main.py
├── requirements.txt
├── README.md
├── tests/
├── data/
└── output/

```

### `main.py`
- Acts as the CLI entry point.
- Parses command-line arguments.
- Orchestrates the fetch-analyze-report workflow.
- Supports output options (CSV, JSON) and verbosity control.

### `fetcher.py`
- Interfaces with AWS IAM using `boto3`.
- Retrieves IAM users, roles, and groups.
- Fetches inline and managed policy documents for each identity.
- Returns structured data containing entity names and associated policy JSONs.

### `analyzer.py`
- Contains logic for parsing IAM policy JSON documents.
- Identifies:
  - Use of wildcard actions or resources (`*`)
  - High-risk services (e.g., `iam:*`, `ec2:*`)
  - Overall risk level (High, Medium, Low)
- Returns a structured summary of findings per policy.

### `reporter.py`
- Handles output of analysis results.
- Prints a human-readable summary to the terminal.
- Supports exporting results as `.csv` and `.json` files in the `output/` directory.

### `requirements.txt`
- Lists required Python dependencies for the project.
- Primarily includes `boto3` and any others used for CLI or output formatting.


### `data/`
- Stores sample IAM policy JSON files for testing and demonstration purposes.

### `output/`
- Contains generated analysis reports (CSV/JSON format) from tool runs.
