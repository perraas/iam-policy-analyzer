# fetcher.py
import boto3
import json

iam_client = boto3.client('iam')

def get_doc(policy_arn):
  # Gets the policy document for a given policy ARN.
    policy = iam_client.get_policy(PolicyArn=policy_arn)
    policy_version = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=policy['Policy']['DefaultVersionId']
    )
    return policy_version['PolicyVersion']['Document']


def fetch_iam_data():

   # Retrieves IAM info and policies
    iam_data = {
        "users": {},
        "roles": {},
        "groups": {}
    }

    # Fetch Users and their policies
    paginator = iam_client.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            user_name = user['UserName']
            iam_data["users"][user_name] = {'policies': []}

            # Get attached policies
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
            for policy in attached_policies['AttachedPolicies']:
                doc = get_doc(policy['PolicyArn'])
                if doc:
                    iam_data["users"][user_name]['policies'].append({
                        'policy_name': policy['PolicyName'],
                        'policy_arn': policy['PolicyArn'],
                        'policy_type': 'managed',
                        'doc': doc
                    })

            # Get inline policies
            inline_policies = iam_client.list_user_policies(UserName=user_name)
            for policy_name in inline_policies['PolicyNames']:
                doc = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
                iam_data["users"][user_name]['policies'].append({
                    'policy_name': policy_name,
                    'policy_type': 'inline',
                    'doc': doc
                })


    # Fetch Roles and their policies
    paginator = iam_client.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            iam_data["roles"][role_name] = {'policies': []}

            # Get attached policies
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies['AttachedPolicies']:
                doc = get_doc(policy['PolicyArn'])
                if doc:
                    iam_data["roles"][role_name]['policies'].append({
                        'policy_name': policy['PolicyName'],
                        'policy_arn': policy['PolicyArn'],
                        'policy_type': 'managed',
                        'doc': doc
                    })

            # Get inline policies
            inline_policies = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline_policies['PolicyNames']:
                doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
                iam_data["roles"][role_name]['policies'].append({
                    'policy_name': policy_name,
                    'policy_type': 'inline',
                    'doc': doc
                })

    # Fetch Groups and their policies
    paginator = iam_client.get_paginator('list_groups')
    for page in paginator.paginate():
        for group in page['Groups']:
            group_name = group['GroupName']
            iam_data["groups"][group_name] = {'policies': []}

            # Get attached policies
            attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)
            for policy in attached_policies['AttachedPolicies']:
                doc = get_doc(policy['PolicyArn'])
                if doc:
                    iam_data["groups"][group_name]['policies'].append({
                        'policy_name': policy['PolicyName'],
                        'policy_arn': policy['PolicyArn'],
                        'policy_type': 'managed',
                        'doc': doc
                    })

            # Get inline policies
            inline_policies = iam_client.list_group_policies(GroupName=group_name)
            for policy_name in inline_policies['PolicyNames']:
                doc = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
                iam_data["groups"][group_name]['policies'].append({
                    'policy_name': policy_name,
                    'policy_type': 'inline',
                    'doc': doc
                })


    return iam_data

