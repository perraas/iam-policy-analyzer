# analyzer.py
import json
from .fetcher import fetch_iam_data

# Define services or actions considered high risk
HIGH_RISK_ACTIONS = ['iam:*', 'ec2:*', 's3:*', '*', 'sts:AssumeRole']
HIGH_RISK_SERVICES = ['iam', 'ec2', 's3', 'sts', 'kms', 'lambda', 'cloudformation']

def analyze_policy(policy_json):
    """
    Analyze a single policy document for:
    - Wildcard actions
    - Wildcard resources
    - High-risk permissions
    Return a dict summary with risk score and reasons
    """
    analysis = {
        'wildcard_action': False,
        'wildcard_resource': False,
        'high_risk_actions': [],
        'high_risk_services': set(),
        'admin_privileges': False,
        'issues': []
    }
    
    # Handle both single statement and multiple statements
    statements = policy_json.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        # Skip Deny statements for now
        if statement.get('Effect') == 'Deny':
            continue
            
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        
        # Normalize to lists
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        # Check for wildcard actions
        for action in actions:
            if '*' in action:
                analysis['wildcard_action'] = True
                if action == '*':
                    analysis['admin_privileges'] = True
                    analysis['issues'].append('Full admin privileges (*) detected')
                
            # Check for high-risk actions
            if action in HIGH_RISK_ACTIONS or action == '*':
                analysis['high_risk_actions'].append(action)
                
            # Check for high-risk services
            service = action.split(':')[0] if ':' in action else ''
            if service in HIGH_RISK_SERVICES or action == '*':
                analysis['high_risk_services'].add(service if service else 'all')
        
        # Check for wildcard resources
        for resource in resources:
            if '*' in resource:
                analysis['wildcard_resource'] = True
                if resource == '*':
                    analysis['issues'].append('Wildcard resource (*) detected')
    
    # Convert set to list for JSON serialization
    analysis['high_risk_services'] = list(analysis['high_risk_services'])
    
    # Calculate risk score
    analysis['risk_score'] = get_risk_score(analysis)
    
    return analysis

def get_risk_score(result_dict):
    """
    Assign High / Medium / Low based on flags set in result_dict
    """
    if result_dict.get('admin_privileges') or '*' in result_dict.get('high_risk_actions', []):
        return 'High'
    
    high_risk_count = len(result_dict.get('high_risk_actions', []))
    has_wildcards = result_dict.get('wildcard_action') or result_dict.get('wildcard_resource')
    high_risk_services = len(result_dict.get('high_risk_services', []))
    
    if high_risk_count >= 3 or (has_wildcards and high_risk_services >= 2):
        return 'High'
    elif high_risk_count >= 1 or has_wildcards or high_risk_services >= 1:
        return 'Medium'
    else:
        return 'Low'

def analyze_all_policies(iam_data):
    """
    Iterate over all entities and their policies from fetcher data
    Return full analysis result for reporting
    """
    analysis_results = {
        'users': {},
        'roles': {},
        'groups': {},
        'summary': {
            'total_entities': 0,
            'high_risk_entities': 0,
            'medium_risk_entities': 0,
            'low_risk_entities': 0
        }
    }
    
    # Analyze each entity type
    for entity_type in ['users', 'roles', 'groups']:
        for entity_name, entity_data in iam_data[entity_type].items():
            entity_analysis = {
                'policies': [],
                'overall_risk': 'Low',
                'risk_reasons': []
            }
            
            max_risk_score = 'Low'
            
            for policy in entity_data['policies']:
                policy_analysis = {
                    'policy_name': policy['policy_name'],
                    'policy_type': policy['policy_type'],
                    'policy_arn': policy.get('policy_arn', 'N/A'),
                    'analysis': analyze_policy(policy['policy_document'])
                }
                
                entity_analysis['policies'].append(policy_analysis)
                
                # Track highest risk score for this entity
                current_risk = policy_analysis['analysis']['risk_score']
                if current_risk == 'High':
                    max_risk_score = 'High'
                elif current_risk == 'Medium' and max_risk_score != 'High':
                    max_risk_score = 'Medium'
                
                # Collect risk reasons
                if policy_analysis['analysis']['issues']:
                    entity_analysis['risk_reasons'].extend(policy_analysis['analysis']['issues'])
            
            entity_analysis['overall_risk'] = max_risk_score
            analysis_results[entity_type][entity_name] = entity_analysis
            
            # Update summary counts
            analysis_results['summary']['total_entities'] += 1
            if max_risk_score == 'High':
                analysis_results['summary']['high_risk_entities'] += 1
            elif max_risk_score == 'Medium':
                analysis_results['summary']['medium_risk_entities'] += 1
            else:
                analysis_results['summary']['low_risk_entities'] += 1
    
    return analysis_results

def main():
    """
    Main function to fetch IAM data and analyze it
    """
    print("[+] Fetching IAM data...")
    iam_data = fetch_iam_data()
    
    print("[+] Analyzing policies...")
    analysis_results = analyze_all_policies(iam_data)
    
    print("[+] Analysis complete!")
    print(f"Total entities analyzed: {analysis_results['summary']['total_entities']}")
    print(f"High risk entities: {analysis_results['summary']['high_risk_entities']}")
    print(f"Medium risk entities: {analysis_results['summary']['medium_risk_entities']}")
    print(f"Low risk entities: {analysis_results['summary']['low_risk_entities']}")
    
    return analysis_results

