import json
import logging
import traceback

import boto3

# constants
OPERATOR = "GET_AMI_DETAILS"
TEMPLATE_FILE = "state_machine_error.template"

# boto 3
imagebuilder_client = boto3.client('imagebuilder')
ec2_client = boto3.client('ec2')


def _get_imagebuilder_ami_id(image_builder_obj: dict) -> str:
    assert 'image' in image_builder_obj
    assert 'outputResources' in image_builder_obj['image']
    assert 'amis' in image_builder_obj['image']['outputResources']
    assert len(image_builder_obj['image']['outputResources']['amis']) == 1
    assert 'image' in image_builder_obj['image']['outputResources']['amis'][0]
    return image_builder_obj['image']['outputResources']['amis'][0]['image']


def get_ami_id(image_build_version_arn: str) -> str:
    _response = imagebuilder_client.get_image(
        imageBuildVersionArn=image_build_version_arn
    )
    return _get_imagebuilder_ami_id(
        image_builder_obj=_response
    )


def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # get details from previous stage
        secure_proxy_version_arn = event['secure_proxy_event']['output']["secure_proxy_image_build_version_arn"]
        mock_servers_version_arn = event['secure_proxy_event']['output']["mock_servers_image_build_version_arn"]

        secure_proxy_ami_id = get_ami_id(image_build_version_arn=secure_proxy_version_arn)
        mock_servers_ami_id = get_ami_id(image_build_version_arn=mock_servers_version_arn)

        # create output event data
        event['secure_proxy_event']['output']['ami_ids'] = {}
        event['secure_proxy_event']['output']['ami_ids']['secure_proxy'] = secure_proxy_ami_id
        event['secure_proxy_event']['output']['ami_ids']['mock_servers'] = mock_servers_ami_id
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