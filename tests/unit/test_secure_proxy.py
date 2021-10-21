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
            contain_metadata_path(self.vpc, f"secure-proxy-vpc-{CdkUtils.stack_tag}"
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
            contain_metadata_path(self.iam_instance_profile, f"secure-proxy-imagebuilder-instance-profile-{CdkUtils.stack_tag}"
            )
        )

    def test_secure_proxy_ec2_instance_profile_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_instance_profile, f"secure-proxy-ec2-instance-profile-{CdkUtils.stack_tag}"
            )
        )

    def test_secure_proxy_security_group_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ec2_security_group, f"secure-proxy-security-group-{CdkUtils.stack_tag}")
        )

    def test_secure_proxy_image_role_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_role, f"secure-proxy-image-role-{CdkUtils.stack_tag}")
        )

    def test_secure_proxy_ec2_role_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_role,  f"secure-proxy-ec2-role-{CdkUtils.stack_tag}")
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
                        "CidrIp": "0.0.0.0/0",
                        "Description": "Allow all outbound traffic by default",
                        "IpProtocol": "-1"
                    }
                ],
                "SecurityGroupIngress": [
                    {
                        "CidrIp": "0.0.0.0/0",
                        "Description": "SSH traffic",
                        "FromPort": 22,
                        "IpProtocol": "tcp",
                        "ToPort": 22
                    },
                    {
                        "CidrIp": "0.0.0.0/0",
                        "Description": "WSS traffic",
                        "FromPort": int(self.config["proxySettings"]["wssProxyBindPort"]),
                        "IpProtocol": "tcp",
                        "ToPort": int(self.config["proxySettings"]["wssProxyBindPort"])
                    },
                    {
                        "CidrIp": "0.0.0.0/0",
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
            contain_metadata_path(self.ec2_security_group, f"nlb-traffic-security-group-{CdkUtils.stack_tag}")
        )

    def test_nlb_traffic_security_ingress_rules(self):
        expect(self.cfn_template).to(have_resource(
            self.ec2_security_group,
            {
                "SecurityGroupEgress": [
                    {
                        "CidrIp": "0.0.0.0/0",
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
            "AliasName": f"alias/secure-proxy-kms-key-alias-{CdkUtils.stack_tag}"
        }))

    def test_secure_proxy_kms_key_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.kms_key, f"secure-proxy-kms-key-{CdkUtils.stack_tag}"
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
            contain_metadata_path(self.cw_log_group, f"secure-proxy-logs-group-{CdkUtils.stack_tag}"
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
    ##################################################
    ## </END> AWS Cloudwatch LogGroups tests
    ##################################################

    ##################################################
    ## <START> AWS Elastic Load Balancer tests
    ##################################################
    def test_secure_proxy_imagebuilder_instance_profile_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.elastic_load_balancer, f"secure-proxy-elb-{CdkUtils.stack_tag}"
            )
        )

    def test_wss_elb_listener_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.elastic_load_balancer_listener, f"wss-elb-listener-{CdkUtils.stack_tag}"
            )
        )

    def test_wss_elb_listener_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.elastic_load_balancer_listener, f"oauth-elb-listener-{CdkUtils.stack_tag}"
            )
        )

    def test_secure_proxy_asg_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.autoscaling_group, f"secure-proxy-asg-{CdkUtils.stack_tag}"
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
            self.imagebuilder_infrastructure_configuration, f"secure-proxy-infra-config-{CdkUtils.stack_tag}"
            )
        )

    def test_secure_proxy_component_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
                self.imagebuilder_component, f'InstallProxy'
            )
        )
    
    def test_secure_proxy_recipe_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
            self.imagebuilder_recipe, f"secure-proxy-image-recipe-{CdkUtils.stack_tag}"
            )
        )

    def test_secure_proxy_pipeline_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.imagebuilder_image_pipeline, f"secure-proxy-pipeline-{CdkUtils.stack_tag}"
            )
        )

    def test_secure_proxy_distribution_config(self):
        expect(self.cfn_template).to(
            have_resource(self.imagebuilder_distribution_config, {
                "Distributions": [
                    {
                        "AmiDistributionConfiguration": {
                            "Name": {
                                "Fn::Sub": f'SecureProxy-{CdkUtils.stack_tag}-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'
                            },
                            "AmiTags": {
                                "project": "ec2-imagebuilder-secure-proxy",
                            "Pipeline": f"SecureProxyPipeline-{CdkUtils.stack_tag}"
                            }
                        },
                        "Region": core.Aws.REGION
                    }
                ],
                "Name": f'secure-proxy-distribution-config-{CdkUtils.stack_tag}'
            }))

    def test_mock_servers_component_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
                self.imagebuilder_component, f'InstallServers'
            )
        )
    
    def test_mock_servers_recipe_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
            self.imagebuilder_recipe, f"mock-servers-image-recipe-{CdkUtils.stack_tag}"
            )
        )

    def test_mock_servers_pipeline_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.imagebuilder_image_pipeline, f"mock-servers-pipeline-{CdkUtils.stack_tag}"
            )
        )

    def test_mock_servers_distribution_config(self):
        expect(self.cfn_template).to(
            have_resource(self.imagebuilder_distribution_config, {
                "Distributions": [
                    {
                        "AmiDistributionConfiguration": {
                            "Name": {
                                "Fn::Sub": f'MockServers-{CdkUtils.stack_tag}-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'
                            },
                            "AmiTags": {
                                "project": "ec2-imagebuilder-secure-proxy",
                            "Pipeline": f"MockServersPipeline-{CdkUtils.stack_tag}"
                            }
                        },
                        "Region": core.Aws.REGION
                    }
                ],
                "Name": f'mock-servers-distribution-config-{CdkUtils.stack_tag}'
            }))

    def test_sns_topic_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.sns_topic, f"secure-proxy-imagebuilder-topic-{CdkUtils.stack_tag}"))

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