import boto3
import json
import logging
import traceback

# constants
OPERATOR = "CREATE_SECURE_PROXY_INSTANCE"

# boto 3
ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')
ssm_client = boto3.client('ssm')


def _add_ssm_param(
        name: str,
        description: str,
        value: str,
        type: str
    ):
    ssm_client.put_parameter(
        Name=name,
        Description=description,
        Value=value,
        Type=type,
        Overwrite=True
    )


def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # get details from previous stage
        secure_proxy_ami_id = event['secure_proxy_event']['output']['ami_ids']['secure_proxy']
        secure_proxy_ec2_instance_profile_arn = event['secure_proxy_event']['input']["secure_proxy_ec2_instance_profile_arn"]
        secure_proxy_vpc_public_subnet_id = event['secure_proxy_event']['input']["secure_proxy_vpc_public_subnet_id"]
        secure_proxy_security_group_id = event['secure_proxy_event']['input']["secure_proxy_security_group_id"]

        secure_proxy_instances = ec2_resource.create_instances(
            ImageId=secure_proxy_ami_id,
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.medium",
            SecurityGroupIds=[
                secure_proxy_security_group_id,
            ],
            SubnetId=secure_proxy_vpc_public_subnet_id,
            IamInstanceProfile={
                'Arn': secure_proxy_ec2_instance_profile_arn
            },
            DisableApiTermination=False,
            InstanceInitiatedShutdownBehavior='terminate',
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': 'Secure Proxy Instance'
                        }
                    ]
                }
            ]
        )

        assert len(secure_proxy_instances) == 1
        secure_proxy_instance_id = secure_proxy_instances[0].instance_id
        assert secure_proxy_instance_id is not None

        waiter = ec2_client.get_waiter('instance_running')

        waiter.wait(
            InstanceIds=[
                secure_proxy_instance_id
            ],
            WaiterConfig={
                'Delay': 10,
                'MaxAttempts': 60
            }
        )

        secure_proxy_instance = ec2_resource.Instance(secure_proxy_instance_id)
        secure_proxy_public_ip = secure_proxy_instance.public_ip_address
        assert secure_proxy_public_ip is not None

        # add dnyamic resoure handler ids to ssm param store
        SSM_SECURE_PROXY_PREFIX = "secure-proxy"
        _add_ssm_param(
            name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-instance-id',
            value=secure_proxy_instance_id,
            description="Secure Proxy EC2 Instance Id",
            type="String"
        )
        _add_ssm_param(
            name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-public-ip',
            value=secure_proxy_public_ip,
            description="Secure Proxy EC2 Public IP",
            type="String"
        )

        # create output event data
        event['secure_proxy_event']['output']['ec2'] = {}
        event['secure_proxy_event']['output']['ec2']['secure_proxy_instance_id'] = secure_proxy_instance_id
        event['secure_proxy_event']['output']['ec2']['secure_proxy_public_ip'] = secure_proxy_public_ip
        event['secure_proxy_event']['output']['status'] = "COMPLETED"
        event['secure_proxy_event']['output']['hasError'] = False

        return {
            'statusCode': 200,
            'body': event,
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        stack_trace = traceback.format_exc()

        logger.error(f'Error in executing {OPERATOR} operation: {str(e)}')

        event['secure_proxy_event']['output']['status'] = "ERROR"
        event['secure_proxy_event']['output']['hasError'] = True
        event['secure_proxy_event']['output']['errorMessage'] = stack_trace
        
        return {
            'statusCode': 500,
            'body': event,
            'headers': {'Content-Type': 'application/json'}
        }