import boto3
from fastapi import FastAPI, HTTPException
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

app = FastAPI()

def validate_credentials(access_key: str, secret_key: str, region: str = "us-east-1"):
    try:
        ec2_client = boto3.client(
            "ec2",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        ec2_client.describe_instances() 
    except NoCredentialsError:
        raise HTTPException(status_code=400, detail="No AWS credentials provided.")
    except PartialCredentialsError:
        raise HTTPException(status_code=400, detail="Incomplete AWS credentials provided.")
    except ClientError as e:
        raise HTTPException(status_code=400, detail=f"AWS error: {e.response['Error']['Message']}")

def create_key_pair(ec2_client, key_name: str):
    try:
        key_pair = ec2_client.create_key_pair(KeyName=key_name)
        with open(f"{key_name}.pem", "w") as file:
            file.write(key_pair["KeyMaterial"])
        return key_name
    except ClientError as e:
        if "InvalidKeyPair.Duplicate" in str(e):
            return key_name  
        raise HTTPException(status_code=500, detail=f"Error creating key pair: {e.response['Error']['Message']}")

def create_security_group(ec2_client, group_name: str, description: str, vpc_id: str):
    try:
        response = ec2_client.create_security_group(
            GroupName=group_name,
            Description=description,
            VpcId=vpc_id
        )
        security_group_id = response["GroupId"]

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            ],
        )
        return security_group_id
    except ClientError as e:
        if "InvalidGroup.Duplicate" in str(e):
            groups = ec2_client.describe_security_groups(GroupNames=[group_name])["SecurityGroups"]
            return groups[0]["GroupId"]
        raise HTTPException(status_code=500, detail=f"Error creating security group: {e.response['Error']['Message']}")

def get_subnet_id(ec2_client, vpc_id: str):
    try:
        response = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        subnets = response["Subnets"]
        if subnets:
            return subnets[0]["SubnetId"]  
        else:
            raise HTTPException(status_code=404, detail="No subnets found in the specified VPC.")
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"Error fetching subnet: {e.response['Error']['Message']}")

def create_ec2_instance(ec2_resource, ami_id, instance_type, key_name, security_group_id, subnet_id):
    try:
        instances = ec2_resource.create_instances(
            ImageId=ami_id,
            MinCount=1,
            MaxCount=1,
            InstanceType=instance_type,
            KeyName=key_name,
            SecurityGroupIds=[security_group_id],
            SubnetId=subnet_id,
        )
        instance = instances[0]
        instance.wait_until_running()
        instance.load()
        return {
            "InstanceId": instance.id,
            "State": instance.state["Name"],
            "PublicIP": instance.public_ip_address,
            "PrivateIP": instance.private_ip_address,
        }
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"Error launching EC2 instance: {e.response['Error']['Message']}")

@app.post("/create-vm")
def create_vm(
    access_key: str,
    secret_key: str,
    region: str = "us-east-1",
    ami_id: str = "ami-0c02fb55956c7d316",
    instance_type: str = "t2.micro",
    vpc_id: str = "vpc-0abcd1234abcd1234"
):
    validate_credentials(access_key, secret_key, region)

    ec2_client = boto3.client(
        "ec2", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region
    )
    ec2_resource = boto3.resource(
        "ec2", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region
    )

    subnet_id = get_subnet_id(ec2_client, vpc_id)

    key_name = create_key_pair(ec2_client, "user-dynamic-key")
    security_group_id = create_security_group(ec2_client, "user-dynamic-sg", "Default group", vpc_id)

    vm_details = create_ec2_instance(
        ec2_resource,
        ami_id=ami_id,
        instance_type=instance_type,
        key_name=key_name,
        security_group_id=security_group_id,
        subnet_id=subnet_id,
    )

    return {"message": "EC2 instance created successfully", "details": vm_details}
