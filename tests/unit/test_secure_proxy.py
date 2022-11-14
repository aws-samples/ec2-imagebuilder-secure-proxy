import os

import aws_cdk as cdk
from aws_cdk.assertions import Match, Template

from stacks.secureproxy.secure_proxy import SecureProxyStack
from utils.CdkUtils import CdkUtils


def test_secure_proxy_stack():
    # https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.assertions-readme.html
    app = cdk.App()

    config = CdkUtils.get_project_settings()

    secure_proxy_stack = SecureProxyStack(
        app,
        "SecureProxyStack",
        env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))
    )
    template = Template.from_stack(secure_proxy_stack)

    ##################################################
    ## <START> AWS VPC element tests
    ##################################################
    template.resource_count_is("AWS::EC2::VPC", 1)
    template.resource_count_is("AWS::EC2::Subnet", 2)
    template.resource_count_is("AWS::EC2::SubnetRouteTableAssociation", 2)
    template.resource_count_is("AWS::EC2::NatGateway", 1)
    template.resource_count_is("AWS::EC2::EIP", 1)
    ##################################################
    ## </END> AWS VPC element tests
    ##################################################

    ##################################################
    ## <START> IAM and Security Group tests
    ##################################################
    template.resource_count_is('AWS::IAM::InstanceProfile', 2)
    template.resource_count_is('AWS::EC2::SecurityGroup', 3)
    template.resource_count_is('AWS::IAM::Role', 9)
    template.resource_count_is('AWS::IAM::Policy', 8)

    template.has_resource_properties(
        "AWS::IAM::Role",
        {
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Action": "sts:AssumeRole",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        }
                    }
                ],
                "Version": "2012-10-17"
            },
            "ManagedPolicyArns": [
                {
                    "Fn::Join": [
                        "",
                        [
                            "arn:",
                            {
                                "Ref": "AWS::Partition"
                            },
                            ":iam::aws:policy/AmazonSSMManagedInstanceCore"
                        ]
                    ]
                },
                {
                    "Fn::Join": [
                        "",
                        [
                            "arn:",
                            {
                                "Ref": "AWS::Partition"
                            },
                            ":iam::aws:policy/EC2InstanceProfileForImageBuilder"
                        ]
                    ]
                }
            ]
        }
    )

    template.has_resource_properties(
        "AWS::IAM::Policy",
        {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Action": "elasticloadbalancing:DescribeLoadBalancers",
                        "Effect": "Allow",
                        "Resource": "*"
                    }
                ]
            }
        }
    )

    template.has_resource_properties(
        "AWS::EC2::SecurityGroup",
        {
            "SecurityGroupEgress": [
                {
                    "CidrIp": Match.any_value(),
                    "Description": "Allow all outbound traffic by default",
                    "IpProtocol": "-1"
                }
            ],
            "SecurityGroupIngress": [
                {
                    "CidrIp": Match.any_value(),
                    "Description": "SSH traffic",
                    "FromPort": 22,
                    "IpProtocol": "tcp",
                    "ToPort": 22
                },
                {
                    "CidrIp": Match.any_value(),
                    "Description": "WSS traffic",
                    "FromPort": int(config["proxySettings"]["wssProxyBindPort"]),
                    "IpProtocol": "tcp",
                    "ToPort": int(config["proxySettings"]["wssProxyBindPort"])
                },
                {
                    "CidrIp": Match.any_value(),
                    "Description": "oAuth traffic",
                    "FromPort": int(config["proxySettings"]["oAuthProxyBindPort"]),
                    "IpProtocol": "tcp",
                    "ToPort": int(config["proxySettings"]["oAuthProxyBindPort"]),
                }
            ]
        }
    )

    template.has_resource_properties(
        "AWS::EC2::SecurityGroup",
        {
            "SecurityGroupEgress": [
                {
                    "CidrIp": Match.any_value(),
                    "Description": "Allow all outbound traffic by default",
                    "IpProtocol": "-1"
                }
                ],
                "SecurityGroupIngress": [
                {
                    "CidrIp": Match.any_value(),
                    "Description": "WSS to TCP traffic from Public subnet",
                    "FromPort": int(config["proxySettings"]["wssProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"]),
                    "IpProtocol": "tcp",
                    "ToPort": int(config["proxySettings"]["wssProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"])
                },
                {
                    "CidrIp": Match.any_value(),
                    "Description": "oAuth traffic from Public subnet",
                    "FromPort": int(config["proxySettings"]["oAuthProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"]),
                    "IpProtocol": "tcp",
                    "ToPort": int(config["proxySettings"]["oAuthProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"])
                },
                {
                    "CidrIp": Match.any_value(),
                    "Description": "WSS to TCP traffic from Private subnet",
                    "FromPort": int(config["proxySettings"]["wssProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"]),
                    "IpProtocol": "tcp",
                    "ToPort": int(config["proxySettings"]["wssProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"])
                },
                {
                    "CidrIp": Match.any_value(),
                    "Description": "oAuth traffic from Private subnet",
                    "FromPort": int(config["proxySettings"]["oAuthProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"]),
                    "IpProtocol": "tcp",
                    "ToPort": int(config["proxySettings"]["oAuthProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"])
                }
            ]
        }
    )
    ##################################################
    ## </END> IAM and Security Group tests
    ##################################################



    ##################################################
    ## <START> KMS tests
    ##################################################
    template.resource_count_is("AWS::KMS::Key", 1)

    template.has_resource_properties(
        'AWS::KMS::Key',
        {
            "EnableKeyRotation": True
        }
    )

    template.has_resource_properties(
        'AWS::KMS::Alias',
        {
            "AliasName": "alias/secure-proxy-kms-key-alias"
        }
    )
    ##################################################
    ## </END> AWS KMS tests
    ##################################################

    ##################################################
    ## <START> AWS Cloudwatch LogGroups tests
    ##################################################
    template.resource_count_is("AWS::Logs::LogGroup", 2)

    template.has_resource_properties(
        'AWS::Logs::LogGroup',
        {
            "RetentionInDays": 14,
            "KmsKeyId": Match.any_value()
        }
    )
    ##################################################
    ## </END> AWS Cloudwatch LogGroups tests
    ##################################################

    ##################################################
    ## <START> AWS Elastic Load Balancer tests
    ##################################################
    template.resource_count_is("AWS::ElasticLoadBalancingV2::LoadBalancer", 1)
    ##################################################
    ## </END> AWS Elastic Load Balancer tests
    ##################################################

    ##################################################
    ## <START> EC2 Imagebuilder tests
    ##################################################
    template.resource_count_is("AWS::ImageBuilder::InfrastructureConfiguration", 1)
    template.resource_count_is("AWS::ImageBuilder::Component", 2)
    template.resource_count_is("AWS::ImageBuilder::ImageRecipe", 2)
    template.resource_count_is("AWS::ImageBuilder::ImagePipeline", 2)
    template.resource_count_is("AWS::SNS::Topic", 1)
    template.resource_count_is("AWS::SNS::Subscription", 1)
    
    template.has_resource_properties(
        "AWS::ImageBuilder::DistributionConfiguration",
        {
            "Distributions": [
                {
                    "AmiDistributionConfiguration": {
                        "Name": {
                            "Fn::Sub": f'SecureProxy-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'
                        },
                        "AmiTags": {
                            "project": "ec2-imagebuilder-secure-proxy",
                        "Pipeline": "SecureProxyPipeline"
                        }
                    },
                    "Region": os.getenv('CDK_DEFAULT_REGION')
                }
            ],
            "Name": 'secure-proxy-distribution-config'
        }
    )

    template.has_resource_properties(
        "AWS::ImageBuilder::DistributionConfiguration",
        {
            "Distributions": [
                {
                    "AmiDistributionConfiguration": {
                        "Name": {
                            "Fn::Sub": f'MockServers-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'
                        },
                        "AmiTags": {
                            "project": "ec2-imagebuilder-secure-proxy",
                        "Pipeline": "MockServersPipeline"
                        }
                    },
                    "Region": os.getenv('CDK_DEFAULT_REGION')
                }
            ],
            "Name": 'mock-servers-distribution-config'
        }
    )

    template.has_resource_properties(
        'AWS::SNS::Topic',
        {
            "KmsMasterKeyId": Match.any_value(),
            "TopicName": "secure-proxy-imagebuilder-topic"
        }
    )

    template.has_resource_properties(
        'AWS::SNS::Subscription',
        {
            "Protocol": "email",
            "TopicArn": Match.any_value(),
            "Endpoint": Match.any_value()
        }
    )
    ##################################################
    ## </END> EC2 Imagebuilder tests
    ##################################################

    ##################################################
    ## <START> State Machine tests
    ##################################################
    template.resource_count_is("AWS::StepFunctions::StateMachine", 1)
    ##################################################
    ## </END> State Machine tests
    ##################################################


    ##################################################
    ## <START> Lambda function test
    ##################################################
    template.resource_count_is("AWS::Lambda::Function", 6)
    ##################################################
    ## </END> Lambda function test
    ##################################################


    ##################################################
    ## <START> SSM Parameter tests
    ##################################################
    template.resource_count_is("AWS::SSM::Parameter", 16)
    ##################################################
    ## </END> SSM Parameter tests
    ##################################################
