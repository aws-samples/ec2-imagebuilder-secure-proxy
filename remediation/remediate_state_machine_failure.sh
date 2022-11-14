#!/bin/bash

#################################################################################
# Script Name	: remediate_state_machine_failure.sh
# Description	: In some AWS accounts, a specific error message
#                 can be encountered during execution of the
#                 state machine:
#
#                 botocore.exceptions.ClientError: An error occurred 
#                 (AccessDenied) when calling the CreateAutoScalingGroup 
#                 operation: The default Service-Linked Role for Auto Scaling 
#                 could not be created.
#
#                 This script remdiates that failure and allows the solution
#                 to be successfully deployed and tested.
# Args          :
# Author       	: Damian McDonald
############################################################################y#####

### <START> check if AWS credential variables are correctly set
if [ -z "${AWS_ACCESS_KEY_ID}" ]
then
      echo "AWS credential variable AWS_ACCESS_KEY_ID is empty."
      echo "Please see the guide below for instructions on how to configure your AWS CLI environment."
      echo "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html"
fi

if [ -z "${AWS_SECRET_ACCESS_KEY}" ]
then
      echo "AWS credential variable AWS_SECRET_ACCESS_KEY is empty."
      echo "Please see the guide below for instructions on how to configure your AWS CLI environment."
      echo "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html"
fi

if [ -z "${AWS_DEFAULT_REGION}" ]
then
      echo "AWS credential variable AWS_DEFAULT_REGION is empty."
      echo "Please see the guide below for instructions on how to configure your AWS CLI environment."
      echo "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html"
fi
### </END> check if AWS credential variables are correctly set

### CONSTANTS ###
LAUNCH_CONFIGURATION_NAME="mock-servers-launch-config"
INSTANCE_TYPE="t2.medium"
MOCK_SERVERS_WSS_TARGET_GROUP="mock-servers-wss-tg-2"
MOCK_SERVERS_OAUTH_TARGET_GROUP="mock-servers-oauth-tg-2"
MOCK_SERVERS_AUTO_SCALING_GROUP_NAME="mock-servers-asg"

### SSM PARAM NAMES ###
SSM_PREFIX="/secure-proxy"
MOCK_SERVER_PIPELINE_ARN_KEY="${SSM_PREFIX}/mock-servers-pipeline-arn"
MOCK_SERVER_SG_KEY="${SSM_PREFIX}/mock-servers-security-group-id"
MOCK_SERVER_INST_PROF_KEY="${SSM_PREFIX}/secure-proxy-ec2-instance-profile-arn"
ELB_WSS_KEY="${SSM_PREFIX}/secure-proxy-elb-wss-port"
ELB_OAUTH_KEY="${SSM_PREFIX}/secure-proxy-elb-oauth-port"
VPC_ID_KEY="${SSM_PREFIX}/secure-proxy-vpc-id"
PRIVATE_SUBNET_ID_KEY="${SSM_PREFIX}/secure-proxy-vpc-private-subnet-id"
SECURE_PROXY_ARN_KEY="${SSM_PREFIX}/secure-proxy-elb-arn"

echo "Start remediation process ..."

### GET THE MOCK SERVER AMI ID ###
MOCK_SERVER_PIPELINE_ARN=$(aws ssm get-parameter \
                            --name "${MOCK_SERVER_PIPELINE_ARN_KEY}" \
                            --output text --query "Parameter.Value")
MOCK_SERVERS_AMI_ID=$(aws imagebuilder list-image-pipeline-images \
                            --image-pipeline-arn "${MOCK_SERVER_PIPELINE_ARN}" \
                            --output text \
                            --query "imageSummaryList[0].outputResources.amis[0].image")

echo "Retrived Mock Server AMI Id: ${MOCK_SERVERS_AMI_ID}"

### DELETE PREVIOUS RESOURCE SO WE CAN RECREATE THEM ###
echo "Attempting to delete any orphaned instances -- errors at this point can be expected."
echo "The script will continue despite any errors during deletion of non existent resources."

echo "Removing instances from autoscaling_group: ${MOCK_SERVERS_AUTO_SCALING_GROUP_NAME}"
aws autoscaling update-auto-scaling-group --auto-scaling-group-name ${MOCK_SERVERS_AUTO_SCALING_GROUP_NAME} --min-size 0 --desired-capacity 0

echo "Waiting 60 seconds for the auto scaling group instances to be removed"
sleep 60s

echo "Deleting autoscaling_group: ${MOCK_SERVERS_AUTO_SCALING_GROUP_NAME}"
aws autoscaling delete-auto-scaling-group --auto-scaling-group-name ${MOCK_SERVERS_AUTO_SCALING_GROUP_NAME} --force-delete

echo "Deleting launch_configuration: ${LAUNCH_CONFIGURATION_NAME}"
aws autoscaling delete-launch-configuration --launch-configuration-name ${LAUNCH_CONFIGURATION_NAME}

### CREATE MOCK SERVERS LAUNCH CONFIGURATIONS ###
MOCK_SERVER_SECURITY_GROUP=$(aws ssm get-parameter \
                            --name "${MOCK_SERVER_SG_KEY}" \
                            --output text \
                            --query "Parameter.Value")
MOCK_SERVER_INSTANCE_PROFILE=$(aws ssm get-parameter \
                            --name "${MOCK_SERVER_INST_PROF_KEY}" \
                            --output text \
                            --query "Parameter.Value")

aws autoscaling create-launch-configuration \
    --launch-configuration-name "${LAUNCH_CONFIGURATION_NAME}" \
    --image-id ${MOCK_SERVERS_AMI_ID} \
    --instance-type ${INSTANCE_TYPE} \
    --security-groups ${MOCK_SERVER_SECURITY_GROUP} \
    --iam-instance-profile ${MOCK_SERVER_INSTANCE_PROFILE}

echo "Created Launch Configuration: ${LAUNCH_CONFIGURATION_NAME}"

### CREATE TARGET GROUPS ###
ELB_WSS_PORT=$(aws ssm get-parameter --name "${ELB_WSS_KEY}" --output text --query "Parameter.Value")
ELB_OAUTH_PORT=$(aws ssm get-parameter --name "${ELB_OAUTH_KEY}" --output text --query "Parameter.Value")
VPC_ID=$(aws ssm get-parameter --name "${VPC_ID_KEY}" --output text --query "Parameter.Value")

echo "Creating target group ${MOCK_SERVERS_WSS_TARGET_GROUP}"
WS_TARGET_GROUP_ARN=$(aws elbv2 create-target-group \
                        --name ${MOCK_SERVERS_WSS_TARGET_GROUP} \
                        --protocol "TCP" \
                        --port ${ELB_WSS_PORT} \
                        --vpc-id ${VPC_ID} \
                        --target-type "instance" \
                        --output text \
                        --query "TargetGroups[0].TargetGroupArn")
echo "${MOCK_SERVERS_WSS_TARGET_GROUP} target group arn: ${WS_TARGET_GROUP_ARN}"

echo "Creating target group ${MOCK_SERVERS_OAUTH_TARGET_GROUP}"
OAUTH_TARGET_GROUP_ARN=$(aws elbv2 create-target-group \
                        --name ${MOCK_SERVERS_OAUTH_TARGET_GROUP} \
                        --protocol "TCP" \
                        --port ${ELB_OAUTH_PORT} \
                        --vpc-id ${VPC_ID} \
                        --target-type "instance" \
                        --output text \
                        --query "TargetGroups[0].TargetGroupArn")
echo "${MOCK_SERVERS_OAUTH_TARGET_GROUP} target group arn: ${OAUTH_TARGET_GROUP_ARN}"

### CREATE AUTOSCALING GROUP ###
PRIVATE_SUBNET_ID=$(aws ssm get-parameter \
                        --name "${PRIVATE_SUBNET_ID_KEY}" \
                        --output text \
                        --query "Parameter.Value")
aws autoscaling create-auto-scaling-group \
    --auto-scaling-group-name "${MOCK_SERVERS_AUTO_SCALING_GROUP_NAME}" \
    --launch-configuration-name "${LAUNCH_CONFIGURATION_NAME}" \
    --target-group-arns ${WS_TARGET_GROUP_ARN} ${OAUTH_TARGET_GROUP_ARN} \
    --vpc-zone-identifier ${PRIVATE_SUBNET_ID} \
    --min-size 1 \
    --max-size 1 \
    --max-instance-lifetime 2592000

MOCK_SERVERS_ASG_ARN=$(aws autoscaling describe-auto-scaling-groups \
                        --auto-scaling-group-names "${MOCK_SERVERS_AUTO_SCALING_GROUP_NAME}" \
                        --output text \
                        --query "AutoScalingGroups[0].AutoScalingGroupARN")

### CREATE ELB LISTENERS ###
SECURE_PROXY_ARN=$(aws ssm get-parameter --name "${SECURE_PROXY_ARN_KEY}" --output text --query "Parameter.Value")

echo "Creating WSS Listener"
WSS_LISTENER_ARN=$(aws elbv2 create-listener \
                        --load-balancer-arn ${SECURE_PROXY_ARN} \
                        --protocol "TCP" \
                        --port ${ELB_WSS_PORT} \
                        --default-actions "{\"Type\":\"forward\",\"TargetGroupArn\":\"${WS_TARGET_GROUP_ARN}\",\"Order\":1,\"ForwardConfig\":{\"TargetGroups\":[{\"TargetGroupArn\":\"${WS_TARGET_GROUP_ARN}\"}]}}" \
                        --output text \
                        --query "Listeners[0].ListenerArn")

echo "Creating OAUTH Listener"
OAUTH_LISTENER_ARN=$(aws elbv2 create-listener \
                        --load-balancer-arn ${SECURE_PROXY_ARN} \
                        --protocol "TCP" \
                        --port ${ELB_OAUTH_PORT} \
                        --default-actions "{\"Type\":\"forward\",\"TargetGroupArn\":\"${OAUTH_TARGET_GROUP_ARN}\",\"Order\":1,\"ForwardConfig\":{\"TargetGroups\":[{\"TargetGroupArn\":\"${OAUTH_TARGET_GROUP_ARN}\"}]}}" \
                        --output text \
                        --query "Listeners[0].ListenerArn")

### PUT DYNAMIC SSM PARAMS ###
echo "Publishing dynamic info to SSM ..."
aws ssm put-parameter --name "${SSM_PREFIX}/mock-servers-asg-launch-config-name" \
    --description "Mock Server Auto Scaling Group launch Configuration Name" \
    --value "${LAUNCH_CONFIGURATION_NAME}" \
    --type "String"

aws ssm put-parameter --name "${SSM_PREFIX}/mock-servers-wss-target-group-2-arn" \
    --description "Mock Server WSS target Group ARN" \
    --value "${WS_TARGET_GROUP_ARN}" \
    --type "String"

aws ssm put-parameter --name "${SSM_PREFIX}/mock-servers-oauth-target-group-2-arn" \
    --description "Mock Server OAUTH Target Group ARN" \
    --value "${OAUTH_TARGET_GROUP_ARN}" \
    --type "String"

aws ssm put-parameter --name "${SSM_PREFIX}/mock-servers-asg-name" \
    --description "Mock Server Auto Scaling Group Name" \
    --value "${MOCK_SERVERS_AUTO_SCALING_GROUP_NAME}" \
    --type "String"

aws ssm put-parameter --name "${SSM_PREFIX}/mock-servers-asg-arn" \
    --description "Mock Server Auto Scaling Group ARN" \
    --value "${MOCK_SERVERS_ASG_ARN}" \
    --type "String"

aws ssm put-parameter --name "${SSM_PREFIX}/secure-proxy-elb-wss-listener-2-arn" \
    --description "Mock Server ELB WSS Listener ARN" \
    --value "${WSS_LISTENER_ARN}" \
    --type "String"

aws ssm put-parameter --name "${SSM_PREFIX}/secure-proxy-elb-oauth-listener-2-arn" \
    --description "Mock Server ELB oAuth Listener ARN" \
    --value "${OAUTH_LISTENER_ARN}" \
    --type "String"


echo "End of remediation process."
echo "Please wait at least 10 minutes to allow the Autoscaling Group to spin up a Mock Server instance."
echo "After waiting 10 minutes, test the solution with the command below:"
echo ""
echo "bash execute_e2e_tests.sh"
echo ""