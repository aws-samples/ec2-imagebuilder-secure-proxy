import json

import pytest
from expects import expect

from aws_cdk import (
    core
)

from cdk_expects_matcher.CdkMatchers import have_resource, ANY_VALUE, contain_metadata_path
import tests.utils.base_test_case as tc
from stacks.secureproxy.secure_proxy import SecureProxyStack
from utils.CdkUtils import CdkUtils


@pytest.fixture(scope="class")
def secure_proxy_stack_main(request):
    request.cls.cfn_template = tc.BaseTestCase.load_stack_template(SecureProxyStack.__name__)


@pytest.mark.usefixtures('synth', 'secure_proxy_stack_main')
class TestSecureProxyStack(tc.BaseTestCase):
    """
        Test case for SecureProxyStack
    """

    config = CdkUtils.get_project_settings()

    ##################################################
    ## <START> AWS VPC element tests
    ##################################################
    def test_secure_proxy_vpc_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.vpc, "secure-proxy-vpc"
            )
        )

    def test_secure_proxy_vpc_subnets_count(self):
        assert json.dumps(self.cfn_template).count('\"AWS::EC2::Subnet\"') == 2

    def test_secure_proxy_vpc_subnets_rt_assoc_count(self):
        assert json.dumps(self.cfn_template).count('\"AWS::EC2::SubnetRouteTableAssociation\"') == 2

    def test_secure_proxy_vpc_subnets_nat_gw_count(self):
        assert json.dumps(self.cfn_template).count('\"AWS::EC2::NatGateway\"') == 2

    def test_secure_proxy_vpc_subnets_nat_gw_count(self):
        assert json.dumps(self.cfn_template).count('\"AWS::EC2::EIP\"') == 1
    ##################################################
    ## </END> AWS VPC element tests
    ##################################################

    ##################################################
    ## <START> EC2 Security Group tests
    ##################################################
    def test_no_admin_permissions(self):
        assert json.dumps(self.cfn_template).count(':iam::aws:policy/AdministratorAccess') == 0

    def test_secure_proxy_imagebuilder_instance_profile_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_instance_profile, "secure-proxy-imagebuilder-instance-profile"
            )
        )

    def test_secure_proxy_ec2_instance_profile_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_instance_profile, "secure-proxy-ec2-instance-profile"
            )
        )

    def test_secure_proxy_security_group_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ec2_security_group, "secure-proxy-security-group")
        )

    def test_secure_proxy_image_role_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_role, "secure-proxy-image-role")
        )

    def test_secure_proxy_ec2_role_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_role,  "secure-proxy-ec2-role")
        )

    def test_secure_proxy_image_role_policy(self):
        expect(self.cfn_template).to(have_resource(
            self.iam_role,
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
        ))

    def test_secure_proxy_ec2_role_policy(self):
        expect(self.cfn_template).to(have_resource(
            self.iam_policy,
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
        ))

    def test_secure_proxy_security_group_ingress_rules(self):
        expect(self.cfn_template).to(have_resource(
            self.ec2_security_group,
            {
                "SecurityGroupEgress": [
                    {
                        "CidrIp": ANY_VALUE,
                        "Description": "Allow all outbound traffic by default",
                        "IpProtocol": "-1"
                    }
                ],
                "SecurityGroupIngress": [
                    {
                        "CidrIp": ANY_VALUE,
                        "Description": "SSH traffic",
                        "FromPort": 22,
                        "IpProtocol": "tcp",
                        "ToPort": 22
                    },
                    {
                        "CidrIp": ANY_VALUE,
                        "Description": "WSS traffic",
                        "FromPort": int(self.config["proxySettings"]["wssProxyBindPort"]),
                        "IpProtocol": "tcp",
                        "ToPort": int(self.config["proxySettings"]["wssProxyBindPort"])
                    },
                    {
                        "CidrIp": ANY_VALUE,
                        "Description": "oAuth traffic",
                        "FromPort": int(self.config["proxySettings"]["oAuthProxyBindPort"]),
                        "IpProtocol": "tcp",
                        "ToPort": int(self.config["proxySettings"]["oAuthProxyBindPort"]),
                    }
                ]
            }
        ))

    def test_nlb_traffic_security_group_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ec2_security_group, "nlb-traffic-security-group")
        )

    def test_nlb_traffic_security_ingress_rules(self):
        expect(self.cfn_template).to(have_resource(
            self.ec2_security_group,
            {
                "SecurityGroupEgress": [
                    {
                        "CidrIp": ANY_VALUE,
                        "Description": "Allow all outbound traffic by default",
                        "IpProtocol": "-1"
                    }
                    ],
                    "SecurityGroupIngress": [
                    {
                        "CidrIp": ANY_VALUE,
                        "Description": "WSS to TCP traffic from Public subnet",
                        "FromPort": int(self.config["proxySettings"]["wssProxyBindPort"]) - int(self.config["proxySettings"]["proxyPortScaleFactor"]),
                        "IpProtocol": "tcp",
                        "ToPort": int(self.config["proxySettings"]["wssProxyBindPort"]) - int(self.config["proxySettings"]["proxyPortScaleFactor"])
                    },
                    {
                        "CidrIp": ANY_VALUE,
                        "Description": "oAuth traffic from Public subnet",
                        "FromPort": int(self.config["proxySettings"]["oAuthProxyBindPort"]) - int(self.config["proxySettings"]["proxyPortScaleFactor"]),
                        "IpProtocol": "tcp",
                        "ToPort": int(self.config["proxySettings"]["oAuthProxyBindPort"]) - int(self.config["proxySettings"]["proxyPortScaleFactor"])
                    },
                    {
                        "CidrIp": ANY_VALUE,
                        "Description": "WSS to TCP traffic from Private subnet",
                        "FromPort": int(self.config["proxySettings"]["wssProxyBindPort"]) - int(self.config["proxySettings"]["proxyPortScaleFactor"]),
                        "IpProtocol": "tcp",
                        "ToPort": int(self.config["proxySettings"]["wssProxyBindPort"]) - int(self.config["proxySettings"]["proxyPortScaleFactor"])
                    },
                    {
                        "CidrIp": ANY_VALUE,
                        "Description": "oAuth traffic from Private subnet",
                        "FromPort": int(self.config["proxySettings"]["oAuthProxyBindPort"]) - int(self.config["proxySettings"]["proxyPortScaleFactor"]),
                        "IpProtocol": "tcp",
                        "ToPort": int(self.config["proxySettings"]["oAuthProxyBindPort"]) - int(self.config["proxySettings"]["proxyPortScaleFactor"])
                    }
                ]
            }
        ))
    ##################################################
    ## </END> EC2 Security Group tests
    ##################################################

    ##################################################
    ## <START> KMS tests
    ##################################################
    def test_secure_proxy_kms_key_rotation_created(self):
        expect(self.cfn_template).to(have_resource(self.kms_key, {
            "EnableKeyRotation": True
        }))

    def test_secure_proxy_kms_key_alias_created(self):
        expect(self.cfn_template).to(have_resource(self.kms_alias, {
            "AliasName": "alias/secure-proxy-kms-key-alias"
        }))

    def test_secure_proxy_kms_key_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.kms_key, "secure-proxy-kms-key"
            )
        )
    ##################################################
    ## </END> AWS KMS tests
    ##################################################

    ##################################################
    ## <START> AWS Cloudwatch LogGroups tests
    ##################################################
    def test_secure_proxy_loggroup_exists(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.cw_log_group, "secure-proxy-logs-group"
            )
        )

    def test_secure_proxy_loggroup_retention(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "RetentionInDays": 14
    }))

    def test_secure_proxy_loggroup_encryption(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "KmsKeyId": ANY_VALUE
    }))

    def test_state_machine_loggroup_exists(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.cw_log_group, "secure-proxy-state-machine-logs-group"
            )
        )

    def test_state_machine_loggroup_retention(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "RetentionInDays": 14
    }))
    ##################################################
    ## </END> AWS Cloudwatch LogGroups tests
    ##################################################

    ##################################################
    ## <START> AWS Elastic Load Balancer tests
    ##################################################
    def test_secure_proxy_imagebuilder_instance_profile_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.elastic_load_balancer, "secure-proxy-elb"
            )
        )
    ##################################################
    ## </END> AWS Elastic Load Balancer tests
    ##################################################

    ##################################################
    ## <START> EC2 Imagebuilder tests
    ##################################################
    def test_infra_config_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
            self.imagebuilder_infrastructure_configuration, "secure-proxy-infra-config"
            )
        )

    def test_secure_proxy_component_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
                self.imagebuilder_component, f'InstallProxy'
            )
        )
    
    def test_secure_proxy_recipe_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
            self.imagebuilder_recipe, "secure-proxy-image-recipe"
            )
        )

    def test_secure_proxy_pipeline_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.imagebuilder_image_pipeline, "secure-proxy-pipeline"
            )
        )

    def test_secure_proxy_distribution_config(self):
        expect(self.cfn_template).to(
            have_resource(self.imagebuilder_distribution_config, {
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
                        "Region": core.Aws.REGION
                    }
                ],
                "Name": f'secure-proxy-distribution-config'
            }))

    def test_mock_servers_component_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
                self.imagebuilder_component, f'InstallServers'
            )
        )
    
    def test_mock_servers_recipe_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
            self.imagebuilder_recipe, "mock-servers-image-recipe"
            )
        )

    def test_mock_servers_pipeline_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.imagebuilder_image_pipeline, "mock-servers-pipeline"
            )
        )

    def test_mock_servers_distribution_config(self):
        expect(self.cfn_template).to(
            have_resource(self.imagebuilder_distribution_config, {
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
                        "Region": core.Aws.REGION
                    }
                ],
                "Name": f'mock-servers-distribution-config'
            }))

    def test_sns_topic_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.sns_topic, "secure-proxy-imagebuilder-topic"))

    def test_sns_subscription_created(self):
        expect(self.cfn_template).to(
            have_resource(self.sns_subscription,
                          {
                              "Protocol": "email",
                              "TopicArn": {
                                  "Ref": ANY_VALUE
                              },
                              "Endpoint": ANY_VALUE
                          },
                          )
        )
    ##################################################
    ## </END> EC2 Imagebuilder tests
    ##################################################

    ##################################################
    ## <START> State Machine tests
    ##################################################

    def test_ami_share_state_machine(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.state_machine, "secure-proxy-state-machine"))

    ##################################################
    ## </END> State Machine tests
    ##################################################

    ##################################################
    ## <START> Lambda function test
    ##################################################

    def test_entry_point_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, "secure-proxy-entry-point-role"))

    def test_entry_point_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, "secure-proxy-entry-point-lambda"))

    def test_poll_ami_status_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, "secure-proxy-poll-ami-status-role"))

    def test_poll_ami_status_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, "secure-proxy-poll-ami-status-lambda"))

    def test_get_ami_details_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, "secure-proxy-get-ami-details-role"))

    def test_get_ami_details_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, "secure-proxy-get-ami-details-lambda"))

    def test_create_secure_proxy_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, "secure-proxy-create-secure-proxy-role"))

    def test_create_secure_proxy_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, "secure-proxy-create-secure-proxy-lambda"))

    def test_create_mock_servers_asg_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, "secure-proxy-create-mock-servers-asg-role"))

    def test_create_mock_servers_asg_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, "secure-proxy-create-mock-servers-asg-lambda"))

    ##################################################
    ## </START> Lambda function test
    ##################################################


    ##################################################
    ## </START> SSM Parameter tests
    ##################################################
    def test_secure_proxy_pipeline_arn_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-pipeline-arn-ssm"))

    def test_mock_servers_pipeline_arn_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "mock-servers-pipeline-arn-ssm"))

    def test_secure_proxy_nlb_dns_name_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-nlb-dns-name-ssm"))

    def test_secure_proxy_vpc_id_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-vpc-id-ssm"))

    def test_secure_proxy_elb_security_group_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-elb-security-group-ssm"))

    def test_secure_proxy_elb_arn_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-elb-arn-ssm"))

    def test_secure_proxy_elb_wss_port_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-elb-wss-port-ssm"))

    def test_secure_proxy_elb_oauth_port_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-elb-oauth-port-ssm"))

    def test_secure_proxy_ec2_instance_profile_arn_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-ec2-instance-profile-arn-ssm"))

    def test_secure_proxy_vpc_public_subnet_id_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-vpc-public-subnet-id-ssm"))

    def test_secure_proxy_vpc_private_subnet_id_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-vpc-private-subnet-id-ssm"))

    def test_secure_proxy_security_group_id_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-security-group-id-ssm"))

    def test_mock_servers_security_group_id_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "mock-servers-security-group-id-ssm"))

    def test_secure_proxy_wss_bind_port_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-wss-bind-port-ssm"))

    def test_secure_proxy_oauth_bind_port_ssm(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ssm_parameter, "secure-proxy-oauth-bind-port-ssm"))