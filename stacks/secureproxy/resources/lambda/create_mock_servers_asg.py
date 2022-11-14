import json
import logging
import traceback

import boto3

# constants
OPERATOR = "CREATE_MOCK_SERVERS_ASG"
MOCK_SERVERS_LAUNCH_CONFIG_NAME = "mock-servers-launch-config"
MOCK_SERVERS_AUTO_SCALING_GROUP_NAME = "mock-servers-asg"
MOCK_SERVERS_WSS_TARGET_GROUP = "mock-servers-wss-target-group"
MOCK_SERVERS_OAUTH_TARGET_GROUP = "mock-servers-oauth-target-group"

# boto3
autoscale_client = boto3.client('autoscaling')
elbv2_client = boto3.client('elbv2')
ssm_client = boto3.client('ssm')
iam_client = boto3.client('iam')

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


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

def _create_launch_configuration(
        ami_id: str,
        security_group_id: str,
        iam_instance_profile: str
    ):
    # create the auto scaling launch configuration
    autoscale_client.create_launch_configuration(
        LaunchConfigurationName=MOCK_SERVERS_LAUNCH_CONFIG_NAME,
        ImageId=ami_id,
        SecurityGroups=[
            security_group_id,
        ],
        InstanceType='t2.medium',
        IamInstanceProfile=iam_instance_profile
    )


def _create_autoscaling_group(
        autoscaling_group_name: str,
        launch_configuration_name: str,
        subnet_id: str,
        target_groups_arns: list[str]
    ) -> str:
    autoscale_client.create_auto_scaling_group(
        AutoScalingGroupName=autoscaling_group_name,
        LaunchConfigurationName=launch_configuration_name,
        MaxInstanceLifetime=2592000,
        MaxSize=1,
        MinSize=1,
        VPCZoneIdentifier=subnet_id,
        TargetGroupARNs=target_groups_arns
    )

    mock_servers_asg_details = autoscale_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[
            autoscaling_group_name
        ]
    )

    assert "AutoScalingGroups" in mock_servers_asg_details
    for mock_servers_asg_detail in mock_servers_asg_details["AutoScalingGroups"]:
        if mock_servers_asg_detail["AutoScalingGroupName"] == autoscaling_group_name:
            return mock_servers_asg_detail["AutoScalingGroupARN"]

    raise RuntimeError(f"Unable to obtain ASG ARN for: {autoscaling_group_name}.")


def _create_target_group(
        target_group_name: str,
        elb_port: int,
        vpc_id: str
    ) -> str:
    tg_response = elbv2_client.create_target_group(
        Name=target_group_name,
        Protocol='TCP',
        Port=elb_port,
        VpcId=vpc_id,
        TargetType='instance'
    )

    assert "TargetGroups" in tg_response
    for target_group in tg_response["TargetGroups"]:
        if target_group["TargetGroupName"] == target_group_name:
            return target_group["TargetGroupArn"]

    raise RuntimeError(f"Unable to obtain Target Group ARN for: {target_group_name}.")


def _create_listener(
        elb_arn: str,
        elb_port: int,
        target_group_arn: str,
        order: int
    ):
    elb_listeners = elbv2_client.create_listener(
        LoadBalancerArn=elb_arn,
        Protocol='TCP',
        Port=elb_port,
        DefaultActions=[
            {
                'Type': 'forward',
                'TargetGroupArn': target_group_arn,
                'Order': order,
                'ForwardConfig': {
                    'TargetGroups': [
                        {
                            'TargetGroupArn': target_group_arn,
                        }
                    ]
                }
            }
        ]
    )

    assert "Listeners" in elb_listeners
    assert len(elb_listeners["Listeners"]) > 0
    return elb_listeners["Listeners"][0]['ListenerArn']


def lambda_handler(event, context):
    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # grab state machine inputs
        secure_proxy_vpc_id = event['secure_proxy_event']['input']["secure_proxy_vpc_id"]
        secure_proxy_iam_instance_profile = event['secure_proxy_event']['input']['secure_proxy_ec2_instance_profile_arn']
        secure_proxy_vpc_private_subnet_id = event['secure_proxy_event']['input']["secure_proxy_vpc_private_subnet_id"]
        secure_proxy_elb_arn = event['secure_proxy_event']['input']["secure_proxy_elb_arn"]
        wss_nlb_port = int(event['secure_proxy_event']['input']['secure_proxy_elb_wss_port'])
        oauth_nlb_port = int(event['secure_proxy_event']['input']['secure_proxy_elb_oauth_port'])
        mock_servers_security_group = event['secure_proxy_event']['input']["mock_servers_security_group_id"]
        mock_servers_ami_id = event['secure_proxy_event']['output']['ami_ids']['mock_servers']

        # create the launch configuration
        _create_launch_configuration(
            ami_id=mock_servers_ami_id,
            security_group_id=mock_servers_security_group,
            iam_instance_profile=secure_proxy_iam_instance_profile
        )

        # create the target group
        wss_target_group_arn = _create_target_group(
            target_group_name=MOCK_SERVERS_WSS_TARGET_GROUP,
            elb_port=wss_nlb_port,
            vpc_id=secure_proxy_vpc_id
        )

        oauth_target_group_arn = _create_target_group(
            target_group_name=MOCK_SERVERS_OAUTH_TARGET_GROUP,
            elb_port=oauth_nlb_port,
            vpc_id=secure_proxy_vpc_id
        )

        # create the auto scaling group using the launch configuration
        mock_server_asg_arn = _create_autoscaling_group(
            autoscaling_group_name=MOCK_SERVERS_AUTO_SCALING_GROUP_NAME,
            launch_configuration_name=MOCK_SERVERS_LAUNCH_CONFIG_NAME,
            subnet_id=secure_proxy_vpc_private_subnet_id,
            target_groups_arns=[wss_target_group_arn, oauth_target_group_arn]
        )

        # create listeners for the NLB WSS
        wss_listener_arn = _create_listener(
            elb_arn=secure_proxy_elb_arn,
            elb_port=wss_nlb_port,
            target_group_arn=wss_target_group_arn,
            order=1
        )
        
        # create listeners for the NLB oAUTH
        oauth_listener_arn = _create_listener(
            elb_arn=secure_proxy_elb_arn,
            elb_port=oauth_nlb_port,
            target_group_arn=oauth_target_group_arn,
            order=2
        )

        # add dnyamic resoure handler ids to ssm param store
        SSM_SECURE_PROXY_PREFIX = "secure-proxy"
        _add_ssm_param(
            name=f'/{SSM_SECURE_PROXY_PREFIX}/mock-servers-asg-launch-config-name',
            value=MOCK_SERVERS_LAUNCH_CONFIG_NAME,
            description="Mock Server Auto Scaling Group launch Configuration Name",
            type="String"
        )
        _add_ssm_param(
            name=f'/{SSM_SECURE_PROXY_PREFIX}/mock-servers-wss-target-group-arn',
            value=wss_target_group_arn,
            description="Mock Server WSS target Group ARN",
            type="String"
        )
        _add_ssm_param(
            name=f'/{SSM_SECURE_PROXY_PREFIX}/mock-servers-oauth-target-group-arn',
            value=oauth_target_group_arn,
            description="Mock Server OAUTH Target Group ARN",
            type="String"
        )
        _add_ssm_param(
            name=f'/{SSM_SECURE_PROXY_PREFIX}/mock-servers-asg-name',
            value=MOCK_SERVERS_AUTO_SCALING_GROUP_NAME,
            description="Mock Server Auto Scaling Group Name",
            type="String"
        )
        _add_ssm_param(
            name=f'/{SSM_SECURE_PROXY_PREFIX}/mock-servers-asg-arn',
            value=mock_server_asg_arn,
            description="Mock Server Auto Scaling Group ARN",
            type="String"
        )
        _add_ssm_param(
            name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-elb-wss-listener-arn',
            value=wss_listener_arn,
            description="Mock Server ELB WSS Listener ARN",
            type="String"
        )
        _add_ssm_param(
            name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-elb-oauth-listener-arn',
            value=oauth_listener_arn,
            description="Mock Server ELB oAuth Listener ARN",
            type="String"
        )

        # create output event data
        event['secure_proxy_event']['output']['asg'] = {}
        event['secure_proxy_event']['output']['asg']['mock_servers_launch_configuration_name'] = MOCK_SERVERS_LAUNCH_CONFIG_NAME
        event['secure_proxy_event']['output']['asg']['mock_server_auto_scaling_group_name'] = MOCK_SERVERS_AUTO_SCALING_GROUP_NAME
        event['secure_proxy_event']['output']['asg']['mock_server_auto_scaling_group_arn'] = mock_server_asg_arn
        event['secure_proxy_event']['output']['asg']['secure_proxy_elb_wss_listener_arn'] = wss_listener_arn
        event['secure_proxy_event']['output']['asg']['secure_proxy_elb_oauth_listener_arn'] = oauth_listener_arn
        event['secure_proxy_event']['output']['asg']['mock_servers_wss_target_group_arn'] = wss_target_group_arn
        event['secure_proxy_event']['output']['asg']['mock_servers_oauth_target_group_arn'] = oauth_target_group_arn
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
