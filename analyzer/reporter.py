# reporter.py
import csv
import json

def print_summary_to_terminal(results):
    # Display a readable summary of results
    # Print entity, policy name, risk level, and issues found
    pass

def export_to_csv(results, filename='output/reports/iam_risks.csv'):
    # Write the summarized results to a CSV file
    # Each row should include: entity, policy name, risk score, details
    pass

def export_to_json(results, filename='output/reports/iam_risks.json'):
    # Write full analysis results to JSON for further automation
    pass
