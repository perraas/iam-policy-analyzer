# fetcher.py
import boto3

def list_users():
    # Return a list of IAM user names
    pass

def list_roles():
    # Return a list of IAM roles
    pass

def list_groups():
    # Return a list of IAM groups
    pass

def get_attached_policies(entity_type, entity_name):
    # Retrieve attached managed policies for a user/role/group
    # entity_type = 'user' | 'role' | 'group'
    pass

def get_inline_policies(entity_type, entity_name):
    # Retrieve inline policies defined directly on the entity
    pass

def fetch_policy_document(policy_arn):
    # Fetch the JSON policy document for a managed policy version
    pass

def fetch_all_policies():
    # High-level wrapper: returns all relevant policies in dict format
    # {
    #   'entity_name': {
    #       'inline': [policy_json],
    #       'managed': [policy_json]
    #   }
    # }
    pass
