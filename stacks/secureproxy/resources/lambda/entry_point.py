import boto3
import json
import logging
import traceback
import string
import random

# constants
OPERATOR = "ENTRY_POINT"

# boto 3
imagebuilder_client = boto3.client('imagebuilder')
ssm_client = boto3.client('ssm')


def _get_ssm_param_value(param_name: str) -> str:
    response = ssm_client.get_parameter(
        Name=param_name,
        WithDecryption=False
    )
    assert "Parameter" in response
    assert "Value" in response["Parameter"]
    return response["Parameter"]["Value"]


def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    # create objects for tracking task progress
    event['secure_proxy_event'] = {}
    event['secure_proxy_event']['input'] = {}
    event['secure_proxy_event']['output'] = {}

    try:

        # get ssm param store values
        SSM_SECURE_PROXY_PREFIX = "secure-proxy"
        secure_proxy_pipeline_arn = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-pipeline-arn'
        )
        mock_servers_pipeline_arn = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/mock-servers-pipeline-arn'
        )
        secure_proxy_nlb_dns_name = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-nlb-dns-name'
        )
        secure_proxy_vpc_id = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-vpc-id'
        )
        secure_proxy_elb_security_group = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-elb-security-group'
        )
        secure_proxy_elb_arn= _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-elb-arn'
        )
        secure_proxy_elb_wss_port = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-elb-wss-port'
        )
        secure_proxy_elb_oauth_port = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-elb-oauth-port'
        )
        secure_proxy_ec2_instance_profile_arn = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-ec2-instance-profile-arn'
        )
        secure_proxy_vpc_public_subnet_id = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-vpc-public-subnet-id'
        )
        secure_proxy_vpc_private_subnet_id = _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-vpc-private-subnet-id'
        )
        secure_proxy_security_group_id= _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/secure-proxy-security-group-id'
        )
        mock_servers_security_group_id= _get_ssm_param_value(
            param_name=f'/{SSM_SECURE_PROXY_PREFIX}/mock-servers-security-group-id'
        )

        # add ssm values to state machine event
        event['secure_proxy_event']['input']["secure_proxy_pipeline_arn"] = secure_proxy_pipeline_arn
        event['secure_proxy_event']['input']["mock_servers_pipeline_arn"] = mock_servers_pipeline_arn
        event['secure_proxy_event']['input']["secure_proxy_nlb_dns_name"] = secure_proxy_nlb_dns_name
        event['secure_proxy_event']['input']["secure_proxy_vpc_id"] = secure_proxy_vpc_id
        event['secure_proxy_event']['input']["secure_proxy_elb_arn"] = secure_proxy_elb_arn
        event['secure_proxy_event']['input']["secure_proxy_elb_security_group"] = secure_proxy_elb_security_group
        event['secure_proxy_event']['input']["secure_proxy_elb_wss_port"] = int(secure_proxy_elb_wss_port)
        event['secure_proxy_event']['input']["secure_proxy_elb_oauth_port"] = int(secure_proxy_elb_oauth_port)
        event['secure_proxy_event']['input']["secure_proxy_ec2_instance_profile_arn"] = secure_proxy_ec2_instance_profile_arn
        event['secure_proxy_event']['input']["secure_proxy_vpc_public_subnet_id"] = secure_proxy_vpc_public_subnet_id
        event['secure_proxy_event']['input']["secure_proxy_vpc_private_subnet_id"] = secure_proxy_vpc_private_subnet_id
        event['secure_proxy_event']['input']["secure_proxy_security_group_id"] = secure_proxy_security_group_id
        event['secure_proxy_event']['input']["mock_servers_security_group_id"] = mock_servers_security_group_id

        #  start execution of the imagebuilder pipeline to build the amis
        secure_proxy_client_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
        mock_servers_client_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
        
        secure_proxy_execution_response = imagebuilder_client.start_image_pipeline_execution(
            imagePipelineArn=secure_proxy_pipeline_arn,
            clientToken=secure_proxy_client_token
        )

        mock_servers_execution_response = imagebuilder_client.start_image_pipeline_execution(
            imagePipelineArn=mock_servers_pipeline_arn,
            clientToken=mock_servers_client_token
        )

        # create output event data
        event['secure_proxy_event']['output']['status'] = "COMPLETED"
        event['secure_proxy_event']['output']['hasError'] = False
        event['secure_proxy_event']['output']["secure_proxy_client_token"] = secure_proxy_execution_response['clientToken']
        event['secure_proxy_event']['output']["secure_proxy_image_build_version_arn"] = secure_proxy_execution_response['imageBuildVersionArn']
        event['secure_proxy_event']['output']["mock_servers_client_token"] = mock_servers_execution_response['clientToken']
        event['secure_proxy_event']['output']["mock_servers_image_build_version_arn"] = mock_servers_execution_response['imageBuildVersionArn']
        
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