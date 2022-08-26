#!/bin/bash

###################################################################
# Script Name	: execute_e2e_tests.sh
# Description	: Excutes the test scenarios for the project
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
SSM_SECPROXY_PUBLIC_IP_KEY="${SSM_PREFIX}/secure-proxy-public-ip"
SSM_WSS_BIND_PORT_KEY="${SSM_PREFIX}/secure-proxy-wss-bind-port"
SSM_OAUTH_BIND_PORT_KEY="${SSM_PREFIX}/secure-proxy-oauth-bind-port"

### DYNAMIC RESOURCE VALUES ###
SECPROXY_PUBLIC_IP=$(aws ssm get-parameter --name "${SSM_SECPROXY_PUBLIC_IP_KEY}" --output text --query "Parameter.Value")
WSS_BIND_PORT=$(aws ssm get-parameter --name "${SSM_WSS_BIND_PORT_KEY}" --output text --query "Parameter.Value")
OAUTH_BIND_PORT=$(aws ssm get-parameter --name "${SSM_OAUTH_BIND_PORT_KEY}" --output text --query "Parameter.Value")

echo "############################"
echo ""
echo "<START> EXECUTING END TO END TESTS SCENARIOS"
echo ""
echo "Secure Proxy Public IP == ${SECPROXY_PUBLIC_IP}"
echo "WSS Bind Port == ${WSS_BIND_PORT}"
echo "oAuth Bind Port == ${OAUTH_BIND_PORT}"
echo ""
python3 client/secure_proxy_client.py --ec2-address ${SECPROXY_PUBLIC_IP} --wss-port ${WSS_BIND_PORT} --https-port ${OAUTH_BIND_PORT}
echo ""
echo "</END> EXECUTING END TO END TESTS SCENARIOS"