# AWS Infra Tools

A collection of Python-based CLI tools for auditing and managing AWS infrastructure.

## Purpose

These tools help DevOps engineers and Cloud Architects:
- Audit VPC configurations across AWS accounts
- Classify subnets as public or private
- Generate network inventory reports

## Tools Included

### 1. VPC Inventory Tool (`vpc_inventory.py`)

A comprehensive network inventory tool that lists all VPCs and their associated resources in a region.

**Features:**
- Lists all VPCs with CIDR blocks
- Inventories subnets with availability zone information
- Automatically classifies subnets as PUBLIC or PRIVATE
- Lists route tables and Internet Gateways
- Supports multiple AWS profiles
- Clean, formatted output for easy analysis

**Usage:**
```bash
# List VPCs in a specific region
python vpc_inventory.py --region us-east-1

# Use a specific AWS profile
python vpc_inventory.py --profile production --region us-west-2
```

**Example Output:**
```
Found 2 VPCs

VPC: vpc-abc123 (10.0.0.0/16)
  Route Tables: 2
  Internet Gateways: 1
    - igw-xyz789
  Subnets: 4
    - [PUBLIC] subnet-pub1 (10.0.1.0/24) in us-east-1a
    - [PUBLIC] subnet-pub2 (10.0.2.0/24) in us-east-1b
    - [PRIVATE] subnet-prv1 (10.0.11.0/24) in us-east-1a
    - [PRIVATE] subnet-prv2 (10.0.12.0/24) in us-east-1b
```

##  Requirements

- Python 3.8+
- boto3
- argparse
- AWS credentials configured (via `aws configure` or environment variables)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/aws-network-tools.git
cd aws-network-tools
```
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure AWS credentials:
```bash
aws configure
```

## Configuration

### AWS Credentials

Tools support multiple authentication methods (in priority order):
1. Command-line `--profile` argument
2. `AWS_PROFILE` environment variable
3. `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables
4. AWS credentials file (`~/.aws/credentials`)
5. IAM role (when running on EC2)

### Example: Using Profiles
```bash
# Configure a profile
aws configure --profile production

# Use it with tools
python vpc_inventory.py --profile production --region us-east-1
```

## How It Works

### Subnet Classification Algorithm

The tools determine if a subnet is PUBLIC or PRIVATE by analyzing route tables:

1. Find the route table associated with the subnet
2. If no explicit association, use the VPC's main route table
3. Check if the route table contains a route to an Internet Gateway (target starts with `igw-`)
4. If IGW route exists → PUBLIC, otherwise → PRIVATE

## 🎓 Learning Resources

These tools were built following AWS and Python best practices:

- [AWS VPC Documentation](https://docs.aws.amazon.com/vpc/)
- [Boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [AWS CLI Configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)

## License

MIT License - feel free to use these tools in your own projects.

## Author

**Bruno Levy**

## Acknowledgments

Built as part of a structured DevOps learning path, focusing on:
- AWS networking fundamentals
- Python automation
- Production-grade error handling
- Clean code practices

