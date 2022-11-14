import json
import logging
import traceback

import boto3

# constants
OPERATOR = "POLL_AMI_STATUS"
TEMPLATE_FILE = "state_machine_error.template"

# boto 3
imagebuilder_client = boto3.client('imagebuilder')


def _get_imagebuilder_ami_status(image_builder_obj: dict) -> str:
    assert 'image' in image_builder_obj
    assert 'state' in image_builder_obj['image']
    assert 'status' in image_builder_obj['image']['state']
    return image_builder_obj['image']['state']['status']


def get_ami_status(image_build_version_arn: str) -> str:
    _response = imagebuilder_client.get_image(
        imageBuildVersionArn=image_build_version_arn
    )
    return str(_get_imagebuilder_ami_status(image_builder_obj=_response)).upper()


def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # get details from previous stage
        secure_proxy_version_arn = event['secure_proxy_event']['output']['secure_proxy_image_build_version_arn']
        mock_servers_version_arn = event['secure_proxy_event']['output']['mock_servers_image_build_version_arn']

        # get the ami states
        secure_proxy_ami_state = get_ami_status(image_build_version_arn=secure_proxy_version_arn)
        mock_servers_ami_state = get_ami_status(image_build_version_arn=mock_servers_version_arn)

        # create output event data
        event['secure_proxy_event']['output']['ami_states'] = {}
        event['secure_proxy_event']['output']['ami_states']['secure_proxy'] = secure_proxy_ami_state
        event['secure_proxy_event']['output']['ami_states']['mock_servers'] = mock_servers_ami_state
        event['secure_proxy_event']['output']['status'] = "COMPLETED"
        event['secure_proxy_event']['output']['hasError'] = False
# 
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