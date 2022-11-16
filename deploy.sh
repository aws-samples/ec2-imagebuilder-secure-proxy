#!/bin/bash

###################################################################
# Script Name	: deploy.sh
# Description	: Deploys CDK resources and executes dynamic
#                 resource creation
# Args          :
# Author       	: Damian McDonald
###################################################################

### <START> check if AWS credential variables are correctly set
if [ -z "${AWS_ACCESS_KEY_ID}" ]
then
      echo "AWS credential variable AWS_ACCESS_KEY_ID is empty."
      echo "Please see the guide below for instructions on how to configure your AWS CLI environment."
      echo "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html"
      exit
fi

if [ -z "${AWS_SECRET_ACCESS_KEY}" ]
then
      echo "AWS credential variable AWS_SECRET_ACCESS_KEY is empty."
      echo "Please see the guide below for instructions on how to configure your AWS CLI environment."
      echo "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html"
      exit
fi

if [ -z "${AWS_DEFAULT_REGION}" ]
then
      echo "AWS credential variable AWS_DEFAULT_REGION is empty."
      echo "Please see the guide below for instructions on how to configure your AWS CLI environment."
      echo "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html"
      exit
fi
### </END> check if AWS credential variables are correctly set

echo "############################"
echo "<START> EXECUTING CDK DEPLOY"
echo ""
cdk deploy
echo ""
echo "</END> EXECUTING CDK DEPLOY"
echo ""

### SSM PARAM NAMES ###
SSM_PREFIX="/secure-proxy"
SSM_STATE_MACHINE_ARN_KEY="${SSM_PREFIX}/secure-proxy-state-machine-arn"

### STATE MACHINE EXECUTION ###
STATE_MACHINE_ARN=$(aws ssm get-parameter --name "${SSM_STATE_MACHINE_ARN_KEY}" --output text --query "Parameter.Value")

### POST DEPLOY ACTIONS
EXECUTION_ARN=$(aws stepfunctions start-execution --state-machine-arn ${STATE_MACHINE_ARN} --output text --query "executionArn")
echo "<START> POST DEPLOY ACTIONS"
echo ""
echo "State Machine Arn == ${STATE_MACHINE_ARN}"
echo "State Machine Execution Arn: ${STATE_MACHINE_ARN}"
echo ""
echo "</END> POST DEPLOY ACTIONS"
echo "############################"