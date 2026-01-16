import boto3
import argparse
from botocore.exceptions import ClientError

DANGEROUS_ACTIONS = {
    's3:*': 'Full S3 access',
    'iam:*': 'Full IAM access',
    'ec2:*': 'Full EC2 access',
    '*:*': 'Administrator access',
    's3:DeleteBucket': 'Can delete S3 buckets',
    'iam:CreateUser': 'Can create IAM users',
    'iam:AttachUserPolicy': 'Can escalate privileges',
}


def list_all_iam_roles(session):
    """
    List all IAM roles in the account.

    Args:
        session: boto3.Session object

    Returns:
        list: List of role dicts
    """
    iam_client = session.client('iam')

    response = iam_client.list_roles()
    roles = response['Roles']
    while response.get('IsTruncated', False):
        response = iam_client.list_roles(Marker=response['Marker'])
        roles.extend(response['Roles'])

    return(roles)


def get_role_policies(iam_client, role_name):
    """
    Get all policies attached to a role (both managed and inline).

    Args:
        iam_client: boto3 IAM client
        role_name: Role name string

    Returns:
        dict: {
            'managed': [list of managed policy ARNs],
            'inline': [list of inline policy names]
        }
    """
    managed_policies = []

    managed_response = iam_client.list_attached_role_policies(RoleName=role_name)
    for policy in managed_response['AttachedPolicies']:
        managed_policies.append(policy['PolicyArn'])

    inline_response = iam_client.list_role_policies(RoleName=role_name)

    inline_policies = inline_response['PolicyNames']

    return {
            'managed': managed_policies,
            'inline': inline_policies
            }

def get_policy_document(iam_client, policy_arn):
    """
    Get the actual policy document (JSON) for a managed policy.

    Args:
        iam_client: boto3 IAM client
        policy_arn: Policy ARN string

    Returns:
        dict: Policy document
    """
    policy_response = iam_client.get_policy(PolicyArn=policy_arn)
    default_version_id = policy_response['Policy']['DefaultVersionId']
    policy_version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)

    return policy_version['PolicyVersion']['Document']


def get_inline_policy_document(iam_client, role_name, policy_name):
    """
    Get inline policy document.

    Args:
        iam_client: boto3 IAM client
        role_name: Role name
        policy_name: Inline policy name

    Returns:
        dict: Policy document
    """
    response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    return response['PolicyDocument']


def analyze_policy_document(policy_doc):
    """
    Analyze a policy document for dangerous permissions.

    Args:
        policy_doc: Policy document dict

    Returns:
        list: List of dangerous actions found
    """
    dangerous_found = []

    for statement in policy_doc['Statement']:
        if statement['Effect'] == "Allow":
            action = statement['Action']
            if isinstance(action, list):
                for action in statement['Action']:
                    if action in DANGEROUS_ACTIONS.keys():
                        dangerous_found.append(action)
            else:
                if action in DANGEROUS_ACTIONS.keys():
                    dangerous_found.append(action)

    return dangerous_found

def generate_security_report(session):
    """
    Generate IAM security report for entire account.

    Args:
        session: boto3.Session object
    """
    iam_client = session.client('iam')

    print("=== IAM Security Audit Report ===\n")

    # Get all roles
    roles = list_all_iam_roles(session)
    print(f"Total IAM roles: {len(roles)}\n")

    high_risk_roles = []

    for role in roles:
        role_name = role['RoleName']

        # Get policies for this role
        policies = get_role_policies(iam_client, role_name)

        # Analyze each managed policy
        dangerous_actions = []
        for policy_arn in policies['managed']:
            try:
                doc = get_policy_document(iam_client, policy_arn)
                dangerous = analyze_policy_document(doc)
                dangerous_actions.extend(dangerous)
            except Exception as e:
                print(f"  Warning: Could not analyze {policy_arn}: {e}")

        # Analyze each inline policy
        for policy_name in policies['inline']:
            try:
                doc = get_inline_policy_document(iam_client, role_name, policy_name)
                dangerous = analyze_policy_document(doc)
                dangerous_actions.extend(dangerous)
            except Exception as e:
                print(f"  Warning: Could not analyze inline policy {policy_name}: {e}")

        # If dangerous actions found, flag the role
        if dangerous_actions:
            high_risk_roles.append({
                'role_name': role_name,
                'dangerous_actions': list(set(dangerous_actions))
                })

    # Print high-risk roles
    if high_risk_roles:
        print(f" HIGH RISK ROLES ({len(high_risk_roles)}):\n")
        for role in high_risk_roles:
            print(f"Role: {role['role_name']}")
            for action in role['dangerous_actions']:
                reason = DANGEROUS_ACTIONS.get(action, 'Unknown risk')
                print(f"    - {action}: {reason}")
            print()
    else:
        print(" No high-risk roles found\n")

    # Summary
    print(f"\n=== Summary ===")
    print(f"Roles analyzed: {len(roles)}")
    print(f"High-risk roles: {len(high_risk_roles)}")
    if high_risk_roles:
        risk_percentage = (len(high_risk_roles) / len(roles)) * 100
        print(f"Risk percentage: {risk_percentage:.1f}%")

def parse_args():
    parser = argparse.ArgumentParser(
        description='Audit IAM policies for security issues'
    )
    parser.add_argument('--profile', help='AWS profile')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    return parser.parse_args()

def main():
    args = parse_args()
    session = boto3.Session(
        profile_name=args.profile,
        region_name=args.region
    )
    generate_security_report(session)

if __name__ == '__main__':
    main()

