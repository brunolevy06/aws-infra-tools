#!/usr/bin/env python3

import boto3
import argparse

def list_all_vpcs(ec2_client):
    """
    List all VPCs in a region.

    Args:
        region: AWS region string (e.g., 'us-east-1')

    Returns:
        list: List of VPC dicts with VpcId, CidrBlock, Tags
    """
    response = ec2_client.describe_vpcs()
    vpcs = response['Vpcs']
    return vpcs


def list_subnets_for_vpc(ec2_client, vpc_id):
    """
    List all subnets in a specific VPC.
    Args:
        ec2_client: boto3 EC2 client
        vpc_id: VPC ID string
    Returns:
        list: List of subnet dicts
    """

    response = ec2_client.describe_subnets(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                    }
                ]
            )
    subnets = response['Subnets']
    return subnets

def list_route_tables_for_vpc(ec2_client, vpc_id):
    """
    List all route tables in a specific VPC.

    Args:
        ec2_client: boto3 EC2 client
        vpc_id: VPC ID string

    Returns:
        list: List of route table dicts
    """
    response = ec2_client.describe_route_tables(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                    }
                ]
            )
    return response['RouteTables']

def is_subnet_public(subnet, route_tables):
    """
    Determine if a subnet is public by checking its route table.

    A subnet is public if its route table has a route to an Internet Gateway.

    Args:
        subnet: Subnet dict from AWS
        route_tables: List of all route tables in the VPC

    Returns:
        bool: True if public, False if private
    """
    subnet_id = subnet['SubnetId']

    route_table = None
    for rt in route_tables:
        for association in rt.get('Associations', []):
            if association.get('SubnetId') == subnet_id:
                route_table = rt
                break
        if route_table:
            break

    if not route_table:
        for rt in route_tables:
            for association in rt.get('Associations', []):
                if association.get('Main'):
                    route_table = rt
                    break
            if route_table:
                break

    if not route_table:
        return False

    for route in route_table.get('Routes', []):
        gateway_id = route.get('GatewayId', '')
        if gateway_id.startswith('igw-'):
            return True

    return False

def list_internet_gateways_for_vpc(ec2_client, vpc_id):
    """
    List Internet Gateways attached to a VPC.

    Args:
        ec2_client: boto3 EC2 client
        vpc_id: VPC ID string

    Returns:
        list: List of IGW dicts
    """
    response = ec2_client.describe_internet_gateways(
            Filters=[
                {
                'Name': 'attachment.vpc-id',
                'Values': [vpc_id]
                    }
                ]
            )
    igws = response['InternetGateways']
    return igws


def get_parameters():
    parser = argparse.ArgumentParser(
            description="List a brief vpc inventory of a specific region"
            )
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--region', required=True, help='AWS region (required)')
    return parser.parse_args()

def main():
    args = get_parameters()
    print(f"My profile is {args.profile} and my region is {args.region}")

    session = boto3.Session(
        profile_name=args.profile,
        region_name=args.region
    )
    ec2_client = session.client('ec2')

    vpcs = list_all_vpcs(ec2_client)
    print(f"Found {len(vpcs)} VPCs\n")



    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        cidr = vpc['CidrBlock']

        print (f"VPC: {vpc_id} ({cidr})")

        route_tables = list_route_tables_for_vpc(ec2_client, vpc_id)
        print(f"    Route Tables: {len(route_tables)}")

        igws = list_internet_gateways_for_vpc(ec2_client, vpc_id)

        if igws:
            print(f"    Internet Gateways: {len(igws)}")
            for igw in igws:
                igw_id = igw['InternetGatewayId']
                print(f"    - {igw_id}")

        subnets = list_subnets_for_vpc(ec2_client, vpc_id)
        print(f"Subnets: {len(subnets)}")

        for subnet in subnets:
            subnet_id = subnet['SubnetId']
            subnet_cidr = subnet['CidrBlock']
            az = subnet['AvailabilityZone']

            is_public = is_subnet_public(subnet, route_tables)
            subnet_type = "PUBLIC" if is_public else "PRIVATE"
            print(f"    - [{subnet_type}] {subnet_id} ({subnet_cidr} in {az})")

        print ()


if __name__ == '__main__':
    main()
