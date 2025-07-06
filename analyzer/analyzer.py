# analyzer.py
import json

# Define services or actions considered high risk
HIGH_RISK_ACTIONS = ['iam:*', 'ec2:*', 's3:*', '*']

def analyze_policy(policy_json):
    # Analyze a single policy document for:
    # - Wildcard actions
    # - Wildcard resources
    # - High-risk permissions
    # Return a dict summary with risk score and reasons
    # Example return:
    # {
    #   'wildcard_action': True,
    #   'wildcard_resource': True,
    #   'high_risk_services': ['iam:*'],
    #   'risk_score': 'High'
    # }
    pass

def get_risk_score(result_dict):
    # Assign High / Medium / Low based on flags set in result_dict
    pass

def analyze_all_policies(policy_dict_by_entity):
    # Iterate over all entities and their policies
    # Return full analysis result for reporting
    # {
    #   'entity_name': [
    #       { 'policy_name': ..., 'analysis': ... },
    #       ...
    #   ]
    # }
    pass
