#!/bin/bash

###################################################################
# Script Name	  : destroy.sh
# Description	  : Destroys the CDK created and Dynamically
#                 created resources
# Args          :
# Author       	: Damian McDonald
###################################################################

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

### SSM PARAM NAMES ###
SSM_PREFIX="/secure-proxy"
SSM_SECPROXY_INSTANCE_ID_KEY="${SSM_PREFIX}/secure-proxy-instance-id"
SSM_LAUNCH_CONFIG_NAME_KEY="${SSM_PREFIX}/mock-servers-asg-launch-config-name"
SSM_WSS_TARGETGROUP_ARN_KEY="${SSM_PREFIX}/mock-servers-wss-target-group-arn"
SSM_OAUTH_TARGETGROUP_ARN_KEY="${SSM_PREFIX}/mock-servers-oauth-target-group-arn"
SSM_AUTOSCALING_GROUP_NAME_KEY="${SSM_PREFIX}/mock-servers-asg-name"
SSM_AUTOSCALING_GROUP_ARN_KEY="${SSM_PREFIX}/mock-servers-asg-arn"
SSM_WSS_LISTENER_ARN_KEY="${SSM_PREFIX}/secure-proxy-elb-wss-listener-arn"
SSM_OAUTH_LISTENER_ARN_KEY="${SSM_PREFIX}/secure-proxy-elb-oauth-listener-arn"

### DYNAMIC RESOURCE VALUES ###
SECPROXY_INSTANCE_ID=$(aws ssm get-parameter --name "${SSM_SECPROXY_INSTANCE_ID_KEY}" --output text --query "Parameter.Value")
LAUNCH_CONFIG_NAME=$(aws ssm get-parameter --name "${SSM_LAUNCH_CONFIG_NAME_KEY}" --output text --query "Parameter.Value")
WSS_TARGETGROUP_ARN=$(aws ssm get-parameter --name "${SSM_WSS_TARGETGROUP_ARN_KEY}" --output text --query "Parameter.Value")
OAUTH_TARGETGROUP_ARN=$(aws ssm get-parameter --name "${SSM_OAUTH_TARGETGROUP_ARN_KEY}" --output text --query "Parameter.Value")
AUTOSCALING_GROUP_NAME=$(aws ssm get-parameter --name "${SSM_AUTOSCALING_GROUP_NAME_KEY}" --output text --query "Parameter.Value")
AUTOSCALING_GROUP_ARN=$(aws ssm get-parameter --name "${SSM_AUTOSCALING_GROUP_ARN_KEY}" --output text --query "Parameter.Value")
WSS_LISTENER_ARN=$(aws ssm get-parameter --name "${SSM_WSS_LISTENER_ARN_KEY}" --output text --query "Parameter.Value")
OAUTH_LISTENER_ARN=$(aws ssm get-parameter --name "${SSM_OAUTH_LISTENER_ARN_KEY}" --output text --query "Parameter.Value")

### PRINT DYNAMIC RESOURCE VALUES ###
DYNAMIC_RESOURCE_VALUES=$(cat <<EOF
{
  "secure_proxy_ec2_instance_id": ${SECPROXY_INSTANCE_ID},
  "autoscaling_launch_config_name": ${LAUNCH_CONFIG_NAME},
  "wss_targetgroup_arn": ${WSS_TARGETGROUP_ARN},
  "oauth_targetgroup_arn": ${OAUTH_TARGETGROUP_ARN},
  "autoscaling_group_name": ${AUTOSCALING_GROUP_NAME},
  "autoscaling_group_arn": ${AUTOSCALING_GROUP_ARN},
  "wss_listener_arn": ${WSS_LISTENER_ARN},
  "oauth_listener_arn": ${OAUTH_LISTENER_ARN}
}
EOF
)

echo "############################"
echo ""
echo "<START> PRINT DYNAMIC RESOURCE VALUES"
echo ""
echo ${DYNAMIC_RESOURCE_VALUES}
echo ""
echo "</END> PRINT DYNAMIC RESOURCE VALUES"
echo ""

### DELETE DYNAMIC RESOURCES ###
echo "<START> DELETING DYNAMIC RESOURCE VALUES"
echo ""

echo "Deleting Secure Proxy EC2 instance: ${SECPROXY_INSTANCE_ID}"
aws ec2 terminate-instances --instance-ids ${SECPROXY_INSTANCE_ID}
aws ec2 wait instance-terminated --instance-ids ${SECPROXY_INSTANCE_ID}

echo "Deleting wss_listener: ${WSS_LISTENER_ARN}"
aws elbv2 delete-listener --listener-arn ${WSS_LISTENER_ARN}

echo "Deleting oauth_listener: ${OAUTH_LISTENER_ARN}"
aws elbv2 delete-listener --listener-arn ${OAUTH_LISTENER_ARN}

echo "Deleting wss_targetgroup: ${WSS_TARGETGROUP_ARN}"
aws elbv2 delete-target-group --target-group-arn ${WSS_TARGETGROUP_ARN}

echo "Deleting oauth_targetgroup: ${OAUTH_TARGETGROUP_ARN}"
aws elbv2 delete-target-group --target-group-arn ${OAUTH_TARGETGROUP_ARN}

echo "Removing instances from autoscaling_group: ${AUTOSCALING_GROUP_NAME}"
aws autoscaling update-auto-scaling-group --auto-scaling-group-name ${AUTOSCALING_GROUP_NAME} --min-size 0 --desired-capacity 0

echo "Waiting 60 seconds for the auto scaling group instances to be removed"
sleep 60s

echo "Deleting autoscaling_group: ${AUTOSCALING_GROUP_NAME}"
aws autoscaling delete-auto-scaling-group --auto-scaling-group-name ${AUTOSCALING_GROUP_NAME} --force-delete

echo "Deleting launch_configuration: ${LAUNCH_CONFIG_NAME}"
aws autoscaling delete-launch-configuration --launch-configuration-name ${LAUNCH_CONFIG_NAME}

echo "Deleting dynamic SSM params"
aws ssm delete-parameter --name ${SSM_SECPROXY_INSTANCE_ID_KEY}
aws ssm delete-parameter --name ${SSM_LAUNCH_CONFIG_NAME_KEY}
aws ssm delete-parameter --name ${SSM_WSS_TARGETGROUP_ARN_KEY}
aws ssm delete-parameter --name ${SSM_OAUTH_TARGETGROUP_ARN_KEY}
aws ssm delete-parameter --name ${SSM_AUTOSCALING_GROUP_NAME_KEY}
aws ssm delete-parameter --name ${SSM_AUTOSCALING_GROUP_ARN_KEY}
aws ssm delete-parameter --name ${SSM_WSS_LISTENER_ARN_KEY}
aws ssm delete-parameter --name ${SSM_OAUTH_LISTENER_ARN_KEY}

echo ""
echo "</END> DELETING DYNAMIC RESOURCE VALUES"
echo ""

echo "<START> EXECUTING CDK DESTROY"
echo ""
cdk destroy
echo ""
echo "</END> EXECUTING CDK DESTROY"
echo "############################"