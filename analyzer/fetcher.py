# fetcher.py
import boto3
import logging
from botocore.exceptions import ClientError, NoCredentialsError

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

iam_client = boto3.client('iam')

def list_users():
    try:
        response = iam_client.list_users()
        return [user['UserName'] for user in response.get('Users', [])]
    except ClientError as e:
        logger.error(f"Error listing users: {e}")
        return []
    except NoCredentialsError:
        logger.error("AWS credentials not found")
        return []

def list_roles():
    try:
        response = iam_client.list_roles()
        return [role['RoleName'] for role in response.get('Roles', [])]
    except ClientError as e:
        logger.error(f"Error listing roles: {e}")
        return []
    except NoCredentialsError:
        logger.error("AWS credentials not found")
        return []

def list_groups():
    try:
        response = iam_client.list_groups()
        return [group['GroupName'] for group in response.get('Groups', [])]
    except ClientError as e:
        logger.error(f"Error listing groups: {e}")
        return []
    except NoCredentialsError:
        logger.error("AWS credentials not found")
        return []

def get_attached_policies(entity_type, entity_name):
    if entity_type not in ['user', 'role', 'group']:
        raise ValueError("Invalid entity type")
    try:
        if entity_type == 'user':
            response = iam_client.list_attached_user_policies(UserName=entity_name)
        elif entity_type == 'role':
            response = iam_client.list_attached_role_policies(RoleName=entity_name)
        elif entity_type == 'group':
            response = iam_client.list_attached_group_policies(GroupName=entity_name)
        return [policy['PolicyArn'] for policy in response.get('AttachedPolicies', [])]
    except ClientError as e:
        logger.error(f"Error getting attached policies for {entity_type} {entity_name}: {e}")
        return []

def get_inline_policies(entity_type, entity_name):
    if entity_type not in ['user', 'role', 'group']:
        raise ValueError("Invalid entity type")
    try:
        if entity_type == 'user':
            response = iam_client.list_user_policies(UserName=entity_name)
        elif entity_type == 'role':
            response = iam_client.list_role_policies(RoleName=entity_name)
        elif entity_type == 'group':
            response = iam_client.list_group_policies(GroupName=entity_name)
        return response.get('PolicyNames', [])
    except ClientError as e:
        logger.error(f"Error getting inline policies for {entity_type} {entity_name}: {e}")
        return []

def fetch_policy_document(policy_arn):
    try:
        response = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = response['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        return policy_version['PolicyVersion']['Document']
    except ClientError as e:
        logger.error(f"Error fetching policy document for {policy_arn}: {e}")
        return None

def fetch_inline_policy_document(entity_type, entity_name, policy_name):
    try:
        if entity_type == 'user':
            response = iam_client.get_user_policy(UserName=entity_name, PolicyName=policy_name)
        elif entity_type == 'role':
            response = iam_client.get_role_policy(RoleName=entity_name, PolicyName=policy_name)
        elif entity_type == 'group':
            response = iam_client.get_group_policy(GroupName=entity_name, PolicyName=policy_name)
        return response['PolicyDocument']
    except ClientError as e:
        logger.error(f"Error fetching inline policy {policy_name} for {entity_type} {entity_name}: {e}")
        return None

def fetch_all_policies():
    all_policies = {}
    
    try:
        # Fetch policies for users
        for user in list_users():
            inline_policy_names = get_inline_policies('user', user)
            managed_policy_arns = get_attached_policies('user', user)
            
            inline_policies = [fetch_inline_policy_document('user', user, policy_name) 
                              for policy_name in inline_policy_names]
            managed_policies = [fetch_policy_document(arn) for arn in managed_policy_arns]
            
            all_policies[user] = {
                'inline': [policy for policy in inline_policies if policy is not None],
                'managed': [policy for policy in managed_policies if policy is not None]
            }
        
        # Fetch policies for roles
        for role in list_roles():
            inline_policy_names = get_inline_policies('role', role)
            managed_policy_arns = get_attached_policies('role', role)
            
            inline_policies = [fetch_inline_policy_document('role', role, policy_name) 
                              for policy_name in inline_policy_names]
            managed_policies = [fetch_policy_document(arn) for arn in managed_policy_arns]
            
            all_policies[role] = {
                'inline': [policy for policy in inline_policies if policy is not None],
                'managed': [policy for policy in managed_policies if policy is not None]
            }
        
        # Fetch policies for groups
        for group in list_groups():
            inline_policy_names = get_inline_policies('group', group)
            managed_policy_arns = get_attached_policies('group', group)
            
            inline_policies = [fetch_inline_policy_document('group', group, policy_name) 
                              for policy_name in inline_policy_names]
            managed_policies = [fetch_policy_document(arn) for arn in managed_policy_arns]
            
            all_policies[group] = {
                'inline': [policy for policy in inline_policies if policy is not None],
                'managed': [policy for policy in managed_policies if policy is not None]
            }
        
        logger.info(f"Successfully fetched policies for {len(all_policies)} entities")
        return all_policies
    
    except Exception as e:
        logger.error(f"Unexpected error in fetch_all_policies: {e}")
        return {}
