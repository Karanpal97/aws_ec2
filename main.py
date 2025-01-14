import os
import boto3
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
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
        ec2_client.describe_instances()  # Simple call to validate credentials
    except NoCredentialsError:
        raise HTTPException(status_code=400, detail="No AWS credentials provided.")
    except PartialCredentialsError:
        raise HTTPException(status_code=400, detail="Incomplete AWS credentials provided.")
    except ClientError as e:
        raise HTTPException(status_code=400, detail=f"AWS error: {e.response['Error']['Message']}")


def create_key_pair(ec2_client, key_name: str, save_dir: str = "/tmp"):
    try:
        key_pair = ec2_client.create_key_pair(KeyName=key_name)

        # Ensure the save directory exists
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        # Define the full path to the .pem file
        pem_file_path = os.path.join(save_dir, f"{key_name}.pem")

        # Save the key material
        with open(pem_file_path, "w") as file:
            file.write(key_pair["KeyMaterial"])

        # Set appropriate permissions for the .pem file
        os.chmod(pem_file_path, 0o400)

        return key_name, pem_file_path
    except ClientError as e:
        if "InvalidKeyPair.Duplicate" in str(e):
            return key_name, None  # Return None if the key pair already exists
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
            ],
        )
        return security_group_id
    except ClientError as e:
        if "InvalidGroup.Duplicate" in str(e):
            groups = ec2_client.describe_security_groups(GroupNames=[group_name])["SecurityGroups"]
            return groups[0]["GroupId"]
        raise HTTPException(status_code=500, detail=f"Error creating security group: {e.response['Error']['Message']}")


def create_ec2_instance(ec2_resource, ami_id, instance_type, key_name, security_group_id, subnet_id, docker_image):
    user_data_script = f"""#!/bin/bash
    sudo yum update -y
    sudo amazon-linux-extras enable docker
    sudo yum install docker -y
    sudo systemctl start docker
    sudo systemctl enable docker
    sudo usermod -aG docker ec2-user
    sleep 10

    sudo docker pull {docker_image}
    sudo docker run -d -p 80:80 {docker_image}
    """
    try:
        instances = ec2_resource.create_instances(
            ImageId=ami_id,
            MinCount=1,
            MaxCount=1,
            InstanceType=instance_type,
            KeyName=key_name,
            SecurityGroupIds=[security_group_id],
            SubnetId=subnet_id,
            UserData=user_data_script,
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
    docker_image: str,
    region: str = "us-east-1",
    ami_id: str = "ami-0c02fb55956c7d316",
    instance_type: str = "t2.micro",
    vpc_id: str = "vpc-0b314c72b3329f060"
):
    validate_credentials(access_key, secret_key, region)

    ec2_client = boto3.client(
        "ec2", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region
    )
    ec2_resource = boto3.resource(
        "ec2", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region
    )

    key_name, pem_file_path = create_key_pair(ec2_client, "user", save_dir="/tmp")
    security_group_id = create_security_group(ec2_client, "user-dynamic-sg", "Default group", vpc_id)

    response = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    subnets = response["Subnets"]
    if not subnets:
        raise HTTPException(status_code=404, detail="No subnets found in the specified VPC.")
    subnet_id = subnets[0]["SubnetId"]

    vm_details = create_ec2_instance(
        ec2_resource,
        ami_id=ami_id,
        instance_type=instance_type,
        key_name=key_name,
        security_group_id=security_group_id,
        subnet_id=subnet_id,
        docker_image=docker_image,
    )

    return {
        "message": "EC2 instance created and Docker application deployed successfully",
        "pem_file_path": f"/download-key/{key_name}",
        "details": vm_details
    }


@app.get("/download-key/{key_name}")
def download_key(key_name: str):
    pem_file_path = f"/tmp/{key_name}.pem"
    if not os.path.exists(pem_file_path):
        raise HTTPException(status_code=404, detail="Key file not found.")
    return FileResponse(
        pem_file_path,
        media_type="application/x-pem-file",
        filename=f"{key_name}.pem"
    )