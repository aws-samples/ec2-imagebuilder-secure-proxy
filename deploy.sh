#!/bin/bash

###################################################################
# Script Name	: deploy.sh
# Description	: Deploys CDK resources and executes dynamic
#                 resource creation
# Args          :
# Author       	: Damian McDonald
###################################################################

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