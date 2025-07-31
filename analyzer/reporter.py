# reporter.py
import csv
import json
import os


def print_summary_to_terminal(results):
    """
    Display a readable summary of results, focusing on high and medium risk entities.
    """
    print("--- IAM Policy Analysis Report ---")
    
    summary = results.get('summary', {})
    print(f"\nSummary:\n- Total entities analyzed: {summary.get('total_entities', 0)}")
    print(f"- High risk entities: {summary.get('high_risk_entities', 0)}")
    print(f"- Medium risk entities: {summary.get('medium_risk_entities', 0)}")
    print(f"- Low risk entities: {summary.get('low_risk_entities', 0)}")

    for entity_type in ['users', 'roles', 'groups']:
        for entity_name, entity_data in results[entity_type].items():
            if entity_data.get('overall_risk') in ['High', 'Medium']:
                print(f"\n--- Entity: {entity_name} ({entity_type}) ---")
                print(f"Overall Risk: {entity_data['overall_risk']}")
                if entity_data['risk_reasons']:
                    print("Key Issues:")
                    for reason in set(entity_data['risk_reasons']):
                        print(f"- {reason}")
                print("\nAssociated Policies:")
                for policy in entity_data['policies']:
                    print(f"  - Policy: {policy['policy_name']} ({policy['policy_type']}) - Risk: {policy['analysis']['risk_score']}")

def export_to_csv(results, filename='output/reports/iam_risks.csv'):
    """
    Write the summarized results to a CSV file.
    Each row includes: entity, policy name, risk score, and details.
    """
    # Ensure the directory exists if specified
    dirname = os.path.dirname(filename)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    
    headers = ['EntityType', 'EntityName', 'PolicyName', 'PolicyType', 'RiskScore', 'Issues', 'HighRiskActions', 'WildcardAction', 'WildcardResource']
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        
        for entity_type in ['users', 'roles', 'groups']:
            for entity_name, entity_data in results[entity_type].items():
                for policy in entity_data['policies']:
                    analysis = policy['analysis']
                    writer.writerow({
                        'EntityType': entity_type,
                        'EntityName': entity_name,
                        'PolicyName': policy['policy_name'],
                        'PolicyType': policy['policy_type'],
                        'RiskScore': analysis['risk_score'],
                        'Issues': ", ".join(analysis['issues']),
                        'HighRiskActions': ", ".join(analysis['high_risk_actions']),
                        'WildcardAction': analysis['wildcard_action'],
                        'WildcardResource': analysis['wildcard_resource']
                    })
    print(f"\n[+] CSV report saved to {filename}")

def export_to_json(results, filename='output/reports/iam_risks.json'):
    """
    Write full analysis results to JSON for further automation.
    """
    # Ensure the directory exists if specified
    dirname = os.path.dirname(filename)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"[+] JSON report saved to {filename}")

def main():
    """
    Main function to load analysis results and generate reports.
    """
    try:
        with open('iam_analysis_results.json', 'r') as f:
            analysis_results = json.load(f)
    except FileNotFoundError:
        print("Error: iam_analysis_results.json not found. Please run analyzer.py first.")
        return
    
    # Generate reports
    print_summary_to_terminal(analysis_results)
    export_to_csv(analysis_results)
    export_to_json(analysis_results)

