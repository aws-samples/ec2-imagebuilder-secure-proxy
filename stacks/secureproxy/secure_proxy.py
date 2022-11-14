#!/usr/bin/env python

"""
    secure_proxy.py:
    CDK stack which creates the AWS network infrastructure
    required by the ec2-imagebuilder-secure-proxy project.
"""

import os

import requests
import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_elasticloadbalancingv2 as elb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_imagebuilder as imagebuilder
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_assets as assets
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm
from aws_cdk import aws_stepfunctions as stepfunctions
from aws_cdk import aws_stepfunctions_tasks as stepfunctions_tasks
from constructs import Construct
from utils.CdkUtils import CdkUtils
from utils.FileUtils import FileUtils


class SecureProxyStack(cdk.Stack):
    """
        CDK stack which creates the AWS network infrastructure
        required by the ec2-imagebuilder-secure-proxy project.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        config = CdkUtils.get_project_settings()

        ##################################################
        ## <START> Network prequisites
        ## VPC, Subnets, ELB, NACLS, Security Groups
        ##################################################

        # Calculate NLB listening ports using a port scaling factor
        wss_nlb_port = int(config["proxySettings"]["wssProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"])
        oauth_nlb_port = int(config["proxySettings"]["oAuthProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"])

        # create the secure proxy VPC
        secure_proxy_vpc = ec2.Vpc(
            self,
            "secure-proxy-vpc",
            cidr=config["vpc"]["cidr"],
            max_azs=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="secure-proxy-subnet-public",
                    cidr_mask=config["vpc"]["subnets"]["mask"],
                    subnet_type=ec2.SubnetType.PUBLIC
                ),
                ec2.SubnetConfiguration(
                    name="secure-proxy-subnet-private",
                    cidr_mask=config["vpc"]["subnets"]["mask"],
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT
                )
            ]
        )

        # Security Group for the Secure Proxy EC2 instance
        secure_proxy_sg = ec2.SecurityGroup(
            self, "secure-proxy-security-group",
            vpc=secure_proxy_vpc,
            allow_all_outbound=True,
            description="Security group for the Secure Proxy traffic",
            security_group_name="secure-proxy"
        )

        # get the external ip to be used as the accepted incoming
        # ip address for the EC2 Secure Proxy Instance security group.
        # if externalIp.autoDetect is set to True in the cdk.json file
        # then the external ip will be auto detected via the service
        # https://checkip.amazonaws.com
        # if externalIp.autoDetect is set to False in the cdk.json file
        # then an explcit external Ip Address value must be set in the
        # externalIp.iPAddress property in the cdk.json file.
        auto_detect_external_ip = config['externalIp']['autoDetect']
        external_ip = config['externalIp']['iPAddress']
        if auto_detect_external_ip:
            external_ip = f"{requests.get('https://checkip.amazonaws.com').text.strip()}/32"
        
        secure_proxy_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(external_ip),
            connection=ec2.Port.tcp(22),
            description="SSH traffic"
        )

        secure_proxy_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(external_ip),
            connection=ec2.Port.tcp(int(config["proxySettings"]["wssProxyBindPort"])),
            description="WSS traffic"
        )

        secure_proxy_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(external_ip),
            connection=ec2.Port.tcp(int(config["proxySettings"]["oAuthProxyBindPort"])),
            description="oAuth traffic"
        )

        # Security Group for the ELB
        nlb_traffic_sg = ec2.SecurityGroup(
            self, "nlb-traffic-security-group",
            vpc=secure_proxy_vpc,
            allow_all_outbound=True,
            description="Security group for the NLB traffic",
            security_group_name="nlb-traffic"
        )

        nlb_traffic_sg.add_ingress_rule(
            peer=secure_proxy_sg,
            connection=ec2.Port.tcp(22),
            description="SSH traffic from Secure Proxy instances"
        )

        nlb_traffic_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(secure_proxy_vpc.public_subnets[0].ipv4_cidr_block),
            connection=ec2.Port.tcp(wss_nlb_port),
            description="WSS to TCP traffic from Public subnet"
        )

        nlb_traffic_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(secure_proxy_vpc.public_subnets[0].ipv4_cidr_block),
            connection=ec2.Port.tcp(oauth_nlb_port),
            description="oAuth traffic from Public subnet"
        )

        nlb_traffic_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(secure_proxy_vpc.private_subnets[0].ipv4_cidr_block),
            connection=ec2.Port.tcp(wss_nlb_port),
            description="WSS to TCP traffic from Private subnet"
        )

        nlb_traffic_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(secure_proxy_vpc.private_subnets[0].ipv4_cidr_block),
            connection=ec2.Port.tcp(oauth_nlb_port),
            description="oAuth traffic from Private subnet"
        )

        # secure proxy NLB
        secure_proxy_elb = elb.NetworkLoadBalancer(
            self, 
            "secure-proxy-elb",
            load_balancer_name=f"{config['elb']['namePrefix']}",
            vpc=secure_proxy_vpc,
            internet_facing=False,
            vpc_subnets=ec2.SubnetSelection(subnets=secure_proxy_vpc.private_subnets),
            cross_zone_enabled=False,
            deletion_protection=False
        )

        nlb_access_logs_bucket = s3.Bucket(
            self,
            "NlbAccessLogsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            public_read_access=False,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True
        )

        secure_proxy_elb.log_access_logs(
            bucket=nlb_access_logs_bucket,
            prefix="nlb-access-logs"
        )

        ##################################################
        ## </END> Network prerequisites
        ##################################################

        ##################################################
        ## <START> EC2 ImageBuilder generic resources
        ##################################################

        # create a KMS key to encrypt project contents
        secure_proxy_kms_key = kms.Key(
            self, 
            "secure-proxy-kms-key",
            admins=[iam.AccountPrincipal(account_id=cdk.Aws.ACCOUNT_ID)],
            enable_key_rotation=True,
            enabled=True,
            description="KMS key used with EC2 Imagebuilder Secure Proxy project",
            removal_policy=cdk.RemovalPolicy.DESTROY,
            alias="secure-proxy-kms-key-alias"
        )

        secure_proxy_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal(service=f'imagebuilder.{cdk.Aws.URL_SUFFIX}'))

        # below role is assumed by the ImageBuilder ec2 instance
        secure_proxy_image_role = iam.Role(self, "secure-proxy-image-role", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        secure_proxy_image_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))
        secure_proxy_image_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("EC2InstanceProfileForImageBuilder"))
        secure_proxy_kms_key.grant_encrypt_decrypt(secure_proxy_image_role)
        secure_proxy_kms_key.grant(secure_proxy_image_role, "kms:Describe*")
        secure_proxy_image_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "logs:CreateLogStream",
                "logs:CreateLogGroup",
                "logs:PutLogEvents"
            ],
            resources=[
                cdk.Arn.format(components=cdk.ArnComponents(
                    service="logs",
                    resource="log-group",
                    resource_name="aws/imagebuilder/*"
                ), stack=self)
            ],
        ))

        # create an instance profile to attach the role
        instance_profile = iam.CfnInstanceProfile(
            self, "secure-proxy-imagebuilder-instance-profile",
            instance_profile_name=f"secure-proxy-imagebuilder-instance-profile-{cdk.Aws.REGION}",
            roles=[secure_proxy_image_role.role_name]
        )

        sns_topic = sns.Topic(
            self, "secure-proxy-imagebuilder-topic",
            topic_name="secure-proxy-imagebuilder-topic",
            master_key=secure_proxy_kms_key
        )

        sns.Subscription(
            self, "secure-proxy-imagebuilder-subscription",
            topic=sns_topic,
            endpoint=config["imagebuilder"]["imageBuilderEmailAddress"],
            protocol=sns.SubscriptionProtocol.EMAIL
        )

        sns_topic.grant_publish(secure_proxy_image_role)
        secure_proxy_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal(service=f'sns.{cdk.Aws.URL_SUFFIX}'))

        # SG for the image build
        secure_proxy_imagebuilder_sg = ec2.SecurityGroup(
            self, "secure-proxy-imagebuilder-sg",
            vpc=secure_proxy_vpc,
            allow_all_outbound=True,
            description="Security group for the EC2 Image Builder Pipeline: " + self.stack_name + "-Pipeline",
            security_group_name="secure-proxy-imagebuilder-sg"
        )

        # create infrastructure configuration to supply instance type
        infra_config = imagebuilder.CfnInfrastructureConfiguration(
            self, "secure-proxy-infra-config",
            name="secure-proxy-infra-config",
            instance_types=config["imagebuilder"]["instanceTypes"],
            instance_profile_name=instance_profile.instance_profile_name,
            subnet_id=secure_proxy_vpc.private_subnets[0].subnet_id,
            security_group_ids=[secure_proxy_imagebuilder_sg.security_group_id],
            resource_tags={
                "project": "ec2-imagebuilder-secure-proxy"
            },
            terminate_instance_on_failure=True,
            sns_topic_arn=sns_topic.topic_arn
        )
        # infrastructure need to wait for instance profile to complete before beginning deployment.
        infra_config.add_depends_on(instance_profile)

        ##################################################
        ## </END> EC2 ImageBuilder generic resources
        ##################################################


        ##################################################
        ## <START> SecureProxy ImageBuilder
        ## LogGroup, Components, Recipie, Pipeline
        ##################################################

        secure_proxy_logs_group = logs.LogGroup(
            self,
            "secure-proxy-logs-group",
            retention=logs.RetentionDays.TWO_WEEKS,
            encryption_key=secure_proxy_kms_key,
            log_group_name=config["proxySettings"]["proxyCloudwatchLogGroup"],
            removal_policy=cdk.RemovalPolicy.DESTROY
        )

        secure_proxy_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal(service=f'logs.{cdk.Aws.URL_SUFFIX}'))

        # grab the values for the Secure Proxy component from cdk.json
        secure_proxy_substitutions = {
            "AWS_NLB_NAME": f"{config['elb']['namePrefix']}",
            "JAIL_BASE_DIR": config["proxySettings"]["jailBaseDir"],
            "PROXY_BASE_DIR": config["proxySettings"]["proxyBaseDir"],
            "PROXY_WORKER_PROCESSES": config["proxySettings"]["proxyWorkerProcesses"],
            "PROXY_WORKER_CONNECTIONS": config["proxySettings"]["proxyWorkerConnections"],
            "PROXY_CLOUDWATCH_LOGGROUP": config["proxySettings"]["proxyCloudwatchLogGroup"],
            "KEEPALIVE_TIMEOUT": config["proxySettings"]["keepaliveTimeout"],
            "WSS_PROXY_BIND_PORT": config["proxySettings"]["wssProxyBindPort"],
            "OAUTH_PROXY_BIND_PORT": config["proxySettings"]["oAuthProxyBindPort"],
            "PROXY_PORT_SCALE_FACTOR": config["proxySettings"]["proxyPortScaleFactor"],
            "WEBSOCKIFY_CONNECT_TIMEOUT": config["proxySettings"]["websockifyConnectTimeout"],
            "WEBSOCKIFY_READ_TIMEOUT": config["proxySettings"]["websockifyReadTimeout"],
            "WEBSOCKIFY_SEND_TIMEOUT": config["proxySettings"]["websockifySendTimeout"],
            "KERNEL_PORTS_RANGE_START": config["proxySettings"]["kernel_ports_range_start"],
            "KERNEL_PORTS_RANGE_END": config["proxySettings"]["kernel_ports_range_end"]
        }

        # generate secure proxy component file with the injected values
        FileUtils.inject_stack_value_to_component(
            template=os.path.abspath("stacks/secureproxy/components/secureproxy/install_secure_proxy.template"),
            substitutions=secure_proxy_substitutions,
            component=os.path.abspath("stacks/secureproxy/components/secureproxy/install_secure_proxy.yml")
        )

        secure_proxy_asset = assets.Asset(self, "SecureProxyAsset",
                path=os.path.abspath("stacks/secureproxy/components/secureproxy/install_secure_proxy.yml"))

        # create component to install secure proxy
        secure_proxy_component = imagebuilder.CfnComponent(
            self, "InstallProxy",
            name=self.stack_name + "-InstallProxy",
            platform="Linux",
            version=config["imagebuilder"]["secure_proxy_component_version"],
            uri=secure_proxy_asset.s3_object_url,
            kms_key_id=secure_proxy_kms_key.key_arn,
            tags={
                "imagePipeline": "AMIBuilder",
                "project": "ec2-imagebuilder-secure-proxy"
            }
        )

         # recipe that installs the secure proxy components together with a Amazon Linux 2 base image
        secure_proxy_recipe = imagebuilder.CfnImageRecipe(
            self, "secure-proxy-image-recipe",
            name="secure-proxy-image-recipe",
            version=config["imagebuilder"]["secure_proxy_recipe_version"],
            components=[
                {
                    "componentArn": secure_proxy_component.attr_arn
                },
                {
                    "componentArn": cdk.Arn.format(components=cdk.ArnComponents(
                        service="imagebuilder",
                        resource="component",
                        resource_name="amazon-cloudwatch-agent-linux/x.x.x",
                        account="aws"
                    ), stack=self)
                },
                {
                    "componentArn": cdk.Arn.format(components=cdk.ArnComponents(
                        service="imagebuilder",
                        resource="component",
                        resource_name="aws-cli-version-2-linux/x.x.x",
                        account="aws"
                    ), stack=self)
                }
            ],
            parent_image=f"arn:aws:imagebuilder:{self.region}:aws:image/{config['imagebuilder']['baseImageArn']}",
            block_device_mappings=[
                imagebuilder.CfnImageRecipe.InstanceBlockDeviceMappingProperty(
                    device_name="/dev/xvda",
                    ebs=imagebuilder.CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                        delete_on_termination=True,
                        # Encryption is disabled, because the export VM doesn't support encrypted ebs
                        encrypted=False,
                        volume_size=config["imagebuilder"]["ebsVolumeSize"],
                        volume_type="gp2"
                    )
                )],
            description="Recipe to build and validate SecureProxyImageRecipe",
            tags={
                "project": "ec2-imagebuilder-secure-proxy"
            },
            working_directory="/imagebuilder"
        )      

        # Distribution configuration for AMIs
        secure_proxy_distribution_config = imagebuilder.CfnDistributionConfiguration(
            self, f'secure-proxy-distribution-config',
            name=f'secure-proxy-distribution-config',
            distributions=[
                imagebuilder.CfnDistributionConfiguration.DistributionProperty(
                    region=self.region,
                    ami_distribution_configuration={
                        'Name': cdk.Fn.sub(f'SecureProxy-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'),
                        'AmiTags': {
                            "project": "ec2-imagebuilder-secure-proxy",
                            'Pipeline': "SecureProxyPipeline"
                        }
                    }
                )
            ]
        )

        # build the imagebuilder pipeline
        secure_proxy_pipeline = imagebuilder.CfnImagePipeline(
            self, "secure-proxy-pipeline",
            name="secure-proxy-pipeline",
            image_recipe_arn=secure_proxy_recipe.attr_arn,
            infrastructure_configuration_arn=infra_config.attr_arn,
            tags={
                "project": "ec2-imagebuilder-secure-proxy"
            },
            description="Image Pipeline for: SecureProxyPipeline",
            enhanced_image_metadata_enabled=False,
            image_tests_configuration=imagebuilder.CfnImagePipeline.ImageTestsConfigurationProperty(
                image_tests_enabled=True,
                timeout_minutes=90
            ),
            distribution_configuration_arn=secure_proxy_distribution_config.attr_arn,
            status="ENABLED"
        )
        secure_proxy_pipeline.add_depends_on(infra_config)

        # role to be assumed by the public Secure Proxy instances
        # this role is required to get the private IP of the AWS NLB
        secure_proxy_ec2_role = iam.Role(
            self,
            "secure-proxy-ec2-role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )
        secure_proxy_ec2_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "elasticloadbalancing:DescribeLoadBalancers"
            ],
            resources=["*"],
        ))

        # create an instance profile to attach the secure proxy ec2 role
        secure_proxy_ec2_instance_profile = iam.CfnInstanceProfile(
            self, "secure-proxy-ec2-instance-profile",
            instance_profile_name="secure-proxy-ec2-instance-profile",
            roles=[secure_proxy_ec2_role.role_name]
        )

        ##################################################
        ## </END> SecureProxy ImageBuilder
        ##################################################

        ##################################################
        ## <START> MockServers ImageBuilder
        ## Components, Recipie, Pipeline
        ##################################################

        # grab the values for the Mock Servers component from cdk.json
        secure_proxy_substitutions = {
            "TCP_SERVER_PORT": config['mockServers']['tcpServerPort'],
            "OAUTH_SERVER_PORT": config['mockServers']['oAuthServerPort']
        }
        
        # generate mock servers component file with the injected values
        FileUtils.inject_stack_value_to_component(
            template=os.path.abspath("stacks/secureproxy/components/mockservers/install_mock_servers.template"),
            substitutions=secure_proxy_substitutions,
            component=os.path.abspath("stacks/secureproxy/components/mockservers/install_mock_servers.yml")
        )

        mock_servers_asset = assets.Asset(self, "MockServersAsset",
                path=os.path.abspath("stacks/secureproxy/components/mockservers/install_mock_servers.yml"))

        # create component to install mock servers
        mock_servers_component = imagebuilder.CfnComponent(
            self, "InstallServers",
            name=self.stack_name + "-InstallServers",
            platform="Linux",
            version=config["imagebuilder"]["mock_servers_component_version"],
            uri=mock_servers_asset.s3_object_url,
            kms_key_id=secure_proxy_kms_key.key_arn,
            tags={
                "imagePipeline": "AMIBuilder",
                "project": "ec2-imagebuilder-secure-proxy"
            }
        )

         # recipe that installs the mock servers components together with a Amazon Linux 2 base image
        mock_servers_recipe = imagebuilder.CfnImageRecipe(
            self, "mock-servers-image-recipe",
            name="mock-servers-image-recipe",
            version=config["imagebuilder"]["mock_servers_recipe_version"],
            components=[
                {
                    "componentArn": mock_servers_component.attr_arn
                },
                {
                    "componentArn": cdk.Arn.format(components=cdk.ArnComponents(
                        service="imagebuilder",
                        resource="component",
                        resource_name="amazon-cloudwatch-agent-linux/x.x.x",
                        account="aws"
                    ), stack=self)
                },
                {
                    "componentArn": cdk.Arn.format(components=cdk.ArnComponents(
                        service="imagebuilder",
                        resource="component",
                        resource_name="aws-cli-version-2-linux/x.x.x",
                        account="aws"
                    ), stack=self)
                }
            ],
            parent_image=f"arn:aws:imagebuilder:{self.region}:aws:image/{config['imagebuilder']['baseImageArn']}",
            block_device_mappings=[
                imagebuilder.CfnImageRecipe.InstanceBlockDeviceMappingProperty(
                    device_name="/dev/xvda",
                    ebs=imagebuilder.CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                        delete_on_termination=True,
                        # Encryption is disabled, because the export VM doesn't support encrypted ebs
                        encrypted=False,
                        volume_size=config["imagebuilder"]["ebsVolumeSize"],
                        volume_type="gp2"
                    )
                )],
            description="Recipe to build and validate MockServersImageRecipe",
            tags={
                "project": "ec2-imagebuilder-secure-proxy"
            },
            working_directory="/imagebuilder"
        )      

        # Distribution configuration for AMIs
        mock_servers_distribution_config = imagebuilder.CfnDistributionConfiguration(
            self, f'mock-servers-distribution-config',
            name=f'mock-servers-distribution-config',
            distributions=[
                imagebuilder.CfnDistributionConfiguration.DistributionProperty(
                    region=self.region,
                    ami_distribution_configuration={
                        'Name': cdk.Fn.sub(f'MockServers-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'),
                        'AmiTags': {
                            "project": "ec2-imagebuilder-secure-proxy",
                            "Pipeline": "MockServersPipeline"
                        }
                    }
                )
            ]
        )

        # build the imagebuilder pipeline
        mock_servers_pipeline = imagebuilder.CfnImagePipeline(
            self, "mock-servers-pipeline",
            name="mock-servers-pipeline",
            image_recipe_arn=mock_servers_recipe.attr_arn,
            infrastructure_configuration_arn=infra_config.attr_arn,
            tags={
                "project": "ec2-imagebuilder-secure-proxy"
            },
            description="Image Pipeline for: MockServersPipeline",
            enhanced_image_metadata_enabled=False,
            image_tests_configuration=imagebuilder.CfnImagePipeline.ImageTestsConfigurationProperty(
                image_tests_enabled=True,
                timeout_minutes=90
            ),
            distribution_configuration_arn=mock_servers_distribution_config.attr_arn,
            status="ENABLED"
        )
        mock_servers_pipeline.add_depends_on(infra_config)

        ##################################################
        ## </END> MockServers ImageBuilder
        ##################################################


        ##################################################
        ## <START> Lambda definitions
        ##################################################

        dirname = os.path.dirname(__file__)

        dead_letter_queue = sqs.Queue(
            self,
            'DeadLetterQueue',
            encryption_master_key=secure_proxy_kms_key
        )

        ## ENTRY_POINT lambda and role ##
        entry_point_role = iam.Role(
            self, "secure-proxy-entry-point-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        entry_point_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:ssm:{self.region}:{self.account}:parameter/{config['ssm']['projectPrefix']}/*"],
            actions=[
                "ssm:GetParameter"
            ]
        ))

        entry_point_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                f"arn:aws:imagebuilder:{self.region}:{self.account}:image/*/*/*",
                f"arn:aws:imagebuilder:{self.region}:{self.account}:image-pipeline/*"
            ],
            actions=[
                "imagebuilder:GetImage",
                "imagebuilder:ListImagePipelineImages",
                "imagebuilder:StartImagePipelineExecution"
            ]
        ))

        entry_point_lambda = _lambda.Function(
            scope=self,
            id="secure-proxy-entry-point-lambda",
            code=_lambda.Code.from_asset(f"{dirname}/resources/lambda"),
            handler="entry_point.lambda_handler",
            role=entry_point_role,
            runtime=_lambda.Runtime.PYTHON_3_9,
            timeout=cdk.Duration.minutes(1),
            dead_letter_queue=dead_letter_queue
        )

        ## POLL AMI STATUS lambda and role ##
        poll_ami_status_role = iam.Role(
            self, "secure-proxy-poll-ami-status-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        poll_ami_status_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                f"arn:aws:imagebuilder:{self.region}:{self.account}:image/*/*/*",
                f"arn:aws:imagebuilder:{self.region}:{self.account}:image-pipeline/*"
            ],
            actions=[
                "imagebuilder:GetImage",
                "imagebuilder:ListImagePipelineImages",
                "imagebuilder:StartImagePipelineExecution"
            ]
        ))

        poll_ami_status_lambda = _lambda.Function(
            scope=self,
            id="secure-proxy-poll-ami-status-lambda",
            code=_lambda.Code.from_asset(f"{dirname}/resources/lambda"),
            handler="poll_ami_status.lambda_handler",
            role=poll_ami_status_role,
            runtime=_lambda.Runtime.PYTHON_3_9,
            timeout=cdk.Duration.minutes(1),
            dead_letter_queue=dead_letter_queue
        )

        ## GET AMI DETAILS lambda and role ##
        get_ami_details_role = iam.Role(
            self, "secure-proxy-get-ami-details-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        get_ami_details_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                f"arn:aws:imagebuilder:{self.region}:{self.account}:image/*/*/*",
                f"arn:aws:imagebuilder:{self.region}:{self.account}:image-pipeline/*"
            ],
            actions=[
                "imagebuilder:GetImage",
                "imagebuilder:ListImagePipelineImages",
                "imagebuilder:StartImagePipelineExecution"
            ]
        ))

        get_ami_details_lambda = _lambda.Function(
            scope=self,
            id="secure-proxy-get-ami-details-lambda",
            code=_lambda.Code.from_asset(f"{dirname}/resources/lambda"),
            handler="get_ami_details.lambda_handler",
            role=get_ami_details_role,
            runtime=_lambda.Runtime.PYTHON_3_9,
            timeout=cdk.Duration.minutes(1),
            dead_letter_queue=dead_letter_queue
        )

        ## CREATE SECURE PROXY lambda and role ##
        create_secure_proxy_role = iam.Role(
            self, "secure-proxy-create-secure-proxy-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        create_secure_proxy_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:ssm:{self.region}:{self.account}:parameter/{config['ssm']['projectPrefix']}/*"],
            actions=[
                "ssm:PutParameter"
            ]
        ))

        create_secure_proxy_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                f"arn:aws:ec2:{self.region}:{self.account}:network-insights-access-scope/*",
                f"arn:aws:ec2:{self.region}:{self.account}:subnet/*",
                f"arn:aws:ec2:{self.region}:{self.account}:transit-gateway-route-table-announcement/*",
                f"arn:aws:ec2::{self.account}:ipam-scope/*",
                f"arn:aws:ec2:{self.region}:{self.account}:capacity-reservation-fleet/*",
                f"arn:aws:ec2:{self.region}:{self.account}:vpn-connection-device-type/*",
                f"arn:aws:ec2:{self.region}:{self.account}:spot-fleet-request/*",
                f"arn:aws:ec2:{self.region}:{self.account}:reserved-instances/*",
                f"arn:aws:ec2:{self.region}:{self.account}:vpn-connection/*",
                f"arn:aws:ec2:{self.region}:{self.account}:export-instance-task/*",
                f"arn:aws:ec2:{self.region}:{self.account}:elastic-ip/*",
                f"arn:aws:ec2:{self.region}:{self.account}:security-group-rule/*",
                f"arn:aws:ec2:{self.region}:{self.account}:replace-root-volume-task/*",
                f"arn:aws:ec2:{self.region}:{self.account}:launch-template/*",
                f"arn:aws:ec2:{self.region}:{self.account}:client-vpn-endpoint/*",
                f"arn:aws:ec2::{self.account}:ipam/*",
                f"arn:aws:ec2:{self.region}:{self.account}:transit-gateway-policy-table/*",
                f"arn:aws:ec2:{self.region}:{self.account}:transit-gateway-connect-peer/*",
                f"arn:aws:ec2:{self.region}:{self.account}:network-insights-access-scope-analysis/*",
                f"arn:aws:ec2:{self.region}:{self.account}:transit-gateway-route-table/*",
                f"arn:aws:ec2:{self.region}:{self.account}:dhcp-options/*",
                f"arn:aws:ec2:{self.region}:{self.account}:instance-event-window/*",
                f"arn:aws:ec2:{self.region}:{self.account}:dedicated-host/*",
                f"arn:aws:ec2:{self.region}:{self.account}:export-image-task/*",
                f"arn:aws:ec2:{self.region}:{self.account}:local-gateway-route-table/*",
                f"arn:aws:license-manager:{self.region}:{self.account}:license-configuration/*",
                f"arn:aws:ec2:{self.region}:{self.account}:carrier-gateway/*",
                f"arn:aws:ec2:{self.region}:{self.account}:prefix-list/*",
                f"arn:aws:ec2:{self.region}:{self.account}:ipv4pool-ec2/*",
                f"arn:aws:ec2:{self.region}:{self.account}:egress-only-internet-gateway/*",
                f"arn:aws:ec2:{self.region}:{self.account}:traffic-mirror-session/*",
                f"arn:aws:ec2:{self.region}:{self.account}:transit-gateway-multicast-domain/*",
                f"arn:aws:ec2:{self.region}:{self.account}:vpc-endpoint-service/*",
                f"arn:aws:ec2:{self.region}:{self.account}:placement-group/*",
                f"arn:aws:ec2:{self.region}:{self.account}:local-gateway-route-table-vpc-association/*",
                f"arn:aws:ec2:{self.region}:{self.account}:natgateway/*",
                f"arn:aws:ec2:{self.region}:{self.account}:traffic-mirror-filter/*",
                f"arn:aws:ec2:{self.region}:{self.account}:network-insights-path/*",
                f"arn:aws:ec2:{self.region}:{self.account}:elastic-gpu/*",
                f"arn:aws:ec2:{self.region}:{self.account}:transit-gateway-attachment/*",
                f"arn:aws:ec2:{self.region}:{self.account}:fleet/*",
                f"arn:aws:ec2:{self.region}:{self.account}:local-gateway/*",
                f"arn:aws:ec2:{self.region}:{self.account}:security-group/*",
                f"arn:aws:ec2:{self.region}:{self.account}:local-gateway-virtual-interface/*",
                f"arn:aws:ec2:{self.region}:{self.account}:ipv6pool-ec2/*",
                f"arn:aws:ec2:{self.region}:{self.account}:volume/*",
                f"arn:aws:ec2:{self.region}:{self.account}:vpc-flow-log/*",
                f"arn:aws:ec2:{self.region}:{self.account}:vpc-peering-connection/*",
                f"arn:aws:ec2:{self.region}:{self.account}:network-insights-analysis/*",
                "arn:aws:ec2:*::snapshot/*",
                f"arn:aws:acm:{self.region}:{self.account}:certificate/*",
                f"arn:aws:ec2:{self.region}:{self.account}:customer-gateway/*",
                f"arn:aws:ec2:{self.region}:{self.account}:transit-gateway/*",
                f"arn:aws:ec2:{self.region}:{self.account}:traffic-mirror-target/*",
                f"arn:aws:ec2:{self.region}:{self.account}:network-acl/*",
                f"arn:aws:resource-groups:{self.region}:{self.account}:group/*",
                f"arn:aws:ec2:{self.region}:{self.account}:local-gateway-virtual-interface-group/*",
                f"arn:aws:ec2:{self.region}:{self.account}:import-image-task/*",
                f"arn:aws:ec2:{self.region}:{self.account}:vpc-endpoint/*",
                "arn:aws:ec2:*::image/*",
                f"arn:aws:ec2:{self.region}:{self.account}:capacity-reservation/*",
                f"arn:aws:ec2:{self.region}:{self.account}:vpc/*",
                f"arn:aws:ec2:{self.region}:{self.account}:subnet-cidr-reservation/*",
                f"arn:aws:elastic-inference:{self.region}:{self.account}:elastic-inference-accelerator/*",
                f"arn:aws:ec2:{self.region}:{self.account}:network-interface/*",
                f"arn:aws:ec2:{self.region}:{self.account}:key-pair/*",
                f"arn:aws:ec2:{self.region}:{self.account}:vpn-gateway/*",
                f"arn:aws:ec2:{self.region}:{self.account}:internet-gateway/*",
                f"arn:aws:ec2:{self.region}:{self.account}:spot-instances-request/*",
                f"arn:aws:ec2:{self.region}:{self.account}:route-table/*",
                f"arn:aws:ec2::{self.account}:ipam-pool/*",
                f"arn:aws:ec2:{self.region}:{self.account}:import-snapshot-task/*",
                f"arn:aws:ec2:{self.region}:{self.account}:host-reservation/*",
                f"arn:aws:ec2:{self.region}:{self.account}:instance/*",
                "arn:aws:ec2:*::fpga-image/*",
                f"arn:aws:ec2:{self.region}:{self.account}:local-gateway-route-table-virtual-interface-group-association/*"
            ],
            actions=[
                "ec2:Describe*",
                "ec2:Search*",
                "ec2:List*",
                "ec2:CreateTags",
                "ec2:RunInstances",
                "ec2:Get*"
            ]
        ))

        create_secure_proxy_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=["*"],
            actions=[
                "ec2:DescribeInstances",
                "ec2:GetEbsEncryptionByDefault",
                "ec2:DescribeCoipPools",
                "ec2:DescribeSnapshots",
                "ec2:DescribeLocalGatewayVirtualInterfaces",
                "ec2:DescribeNetworkInsightsPaths",
                "ec2:DescribeHostReservationOfferings",
                "ec2:DescribeTrafficMirrorSessions",
                "ec2:DescribeExportImageTasks",
                "ec2:DescribeTrafficMirrorFilters",
                "ec2:DescribeVolumeStatus",
                "ec2:DescribeLocalGatewayRouteTableVpcAssociations",
                "ec2:DescribeScheduledInstanceAvailability",
                "ec2:DescribeVolumes",
                "ec2:GetEbsDefaultKmsKeyId",
                "ec2:DescribeExportTasks",
                "ec2:DescribeTransitGatewayMulticastDomains",
                "ec2:DescribeManagedPrefixLists",
                "ec2:DescribeKeyPairs",
                "ec2:DescribeReservedInstancesListings",
                "ec2:DescribeCapacityReservations",
                "ec2:DescribeVpcClassicLinkDnsSupport",
                "ec2:DescribeIdFormat",
                "ec2:DescribeFastSnapshotRestores",
                "ec2:DescribeInstanceEventWindows",
                "ec2:DescribeImportSnapshotTasks",
                "ec2:DescribeLocalGatewayVirtualInterfaceGroups",
                "ec2:DescribeVpcEndpointServicePermissions",
                "ec2:DescribeTransitGatewayAttachments",
                "ec2:GetAssociatedIpv6PoolCidrs",
                "ec2:DescribeScheduledInstances",
                "ec2:DescribeTrunkInterfaceAssociations",
                "ec2:GetSpotPlacementScores",
                "ec2:DescribeIpv6Pools",
                "ec2:DescribeReservedInstancesModifications",
                "ec2:DescribeSubnets",
                "ec2:DescribeMovingAddresses",
                "ec2:DescribeCapacityReservationFleets",
                "ec2:DescribePrincipalIdFormat",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeRegions",
                "ec2:GetNetworkInsightsAccessScopeAnalysisFindings",
                "ec2:DescribeTransitGateways",
                "ec2:DescribeVpcEndpointServices",
                "ec2:DescribeSpotInstanceRequests",
                "ec2:DescribeInstanceTypeOfferings",
                "ec2:DescribeTrafficMirrorTargets",
                "ec2:DescribeTransitGatewayRouteTables",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeNetworkInterfaceAttribute",
                "ec2:DescribeLocalGatewayRouteTables",
                "ec2:DescribeVpcEndpointConnections",
                "ec2:SearchTransitGatewayMulticastGroups",
                "ec2:DescribeInstanceStatus",
                "ec2:DescribeHostReservations",
                "ec2:DescribeBundleTasks",
                "ec2:DescribeIdentityIdFormat",
                "ec2:DescribeClassicLinkInstances",
                "ec2:DescribeTransitGatewayConnects",
                "ec2:DescribeIpamPools",
                "ec2:DescribeVpcEndpointConnectionNotifications",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeFpgaImages",
                "ec2:DescribeVpcs",
                "ec2:DescribeIpams",
                "ec2:DescribeStaleSecurityGroups",
                "ec2:DescribeAggregateIdFormat",
                "ec2:DescribeVolumesModifications",
                "ec2:DescribeTransitGatewayRouteTableAnnouncements",
                "ec2:GetHostReservationPurchasePreview",
                "ec2:DescribeTransitGatewayConnectPeers",
                "ec2:DescribeByoipCidrs",
                "ec2:DescribeNetworkInsightsAnalyses",
                "ec2:DescribePlacementGroups",
                "ec2:DescribeInternetGateways",
                "ec2:GetSerialConsoleAccessStatus",
                "ec2:DescribeSpotDatafeedSubscription",
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeNetworkInterfacePermissions",
                "ec2:DescribeReservedInstances",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeRouteTables",
                "ec2:DescribeEgressOnlyInternetGateways",
                "ec2:DescribeLaunchTemplates",
                "ec2:DescribeVpnConnections",
                "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeReservedInstancesOfferings",
                "ec2:GetTransitGatewayAttachmentPropagations",
                "ec2:GetNetworkInsightsAccessScopeContent",
                "ec2:DescribeSnapshotTierStatus",
                "ec2:DescribeVpcEndpointServiceConfigurations",
                "ec2:DescribePrefixLists",
                "ec2:GetReservedInstancesExchangeQuote",
                "ec2:DescribeInstanceCreditSpecifications",
                "ec2:DescribeVpcClassicLink",
                "ec2:DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations",
                "ec2:GetInstanceTypesFromInstanceRequirements",
                "ec2:DescribeSecurityGroupRules",
                "ec2:GetTransitGatewayRouteTablePropagations",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeElasticGpus",
                "ec2:DescribeVpnGateways",
                "ec2:DescribeTransitGatewayPolicyTables",
                "ec2:DescribeTransitGatewayPeeringAttachments",
                "ec2:GetDefaultCreditSpecification",
                "ec2:DescribeAddresses",
                "ec2:DescribeIpamScopes",
                "ec2:DescribeDhcpOptions",
                "ec2:GetSubnetCidrReservations",
                "ec2:DescribeSpotPriceHistory",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeNetworkInsightsAccessScopeAnalyses",
                "ec2:DescribeCarrierGateways",
                "ec2:GetTransitGatewayRouteTableAssociations",
                "ec2:DescribeLocalGatewayRouteTablePermissions",
                "ec2:DescribeIamInstanceProfileAssociations",
                "ec2:DescribeNetworkInsightsAccessScopes",
                "ec2:DescribeTags",
                "ec2:GetCoipPoolUsage",
                "ec2:DescribeReplaceRootVolumeTasks",
                "ec2:DescribeLaunchTemplateVersions",
                "ec2:GetVpnConnectionDeviceTypes",
                "ec2:DescribeImportImageTasks",
                "ec2:GetTransitGatewayPrefixListReferences",
                "ec2:DescribeNatGateways",
                "ec2:DescribeCustomerGateways",
                "ec2:DescribeInstanceEventNotificationAttributes",
                "ec2:DescribeLocalGateways",
                "ec2:DescribeSpotFleetRequests",
                "ec2:DescribeHosts",
                "ec2:DescribeImages",
                "ec2:DescribeSecurityGroupReferences",
                "ec2:DescribePublicIpv4Pools",
                "ec2:DescribeTransitGatewayVpcAttachments",
                "ec2:GetTransitGatewayMulticastDomainAssociations",
                "ec2:DescribeConversionTasks"
            ]
        ))
        
        create_secure_proxy_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.DENY,
            resources=["*"],
            actions=[
                "ec2:GetPasswordData"
            ]
        ))

        create_secure_proxy_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[f"arn:aws:iam::{self.account}:role/*"],
            actions=[
                "iam:PassRole"
            ]
        ))

        create_secure_proxy_lambda = _lambda.Function(
            scope=self,
            id="secure-proxy-create-secure-proxy-lambda",
            code=_lambda.Code.from_asset(f"{dirname}/resources/lambda"),
            handler="create_secure_proxy.lambda_handler",
            role=create_secure_proxy_role,
            runtime=_lambda.Runtime.PYTHON_3_9,
            timeout=cdk.Duration.minutes(15),
            dead_letter_queue=dead_letter_queue
        )


        ## CREATE MOCK SERVER ASG lambda and role ##
        create_mock_servers_asg_role = iam.Role(
            self, "secure-proxy-create-mock-servers-asg-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        create_mock_servers_asg_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:ssm:{self.region}:{self.account}:parameter/{config['ssm']['projectPrefix']}/*"],
            actions=[
                "ssm:PutParameter"
            ]
        ))

        create_mock_servers_asg_role.add_to_policy(iam.PolicyStatement(
            resources=[
                "*"
            ],
            actions=[
                "autoscaling:CreateLaunchConfiguration"
            ]
        ))

        create_mock_servers_asg_role.add_to_policy(iam.PolicyStatement(
            resources=[
                f"arn:aws:elasticloadbalancing:{self.region}:{self.account}:targetgroup/*",
            ],
            actions=[
                "elasticloadbalancing:CreateTargetGroup"
            ]
        ))

        create_mock_servers_asg_role.add_to_policy(iam.PolicyStatement(
            resources=[
                f"arn:aws:autoscaling:{self.region}:{self.account}:autoScalingGroup:*:autoScalingGroupName/*"
            ],
            actions=[
                "autoscaling:CreateAutoScalingGroup"
            ]
        ))

        create_mock_servers_asg_role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=[
                "autoscaling:DescribeAutoScalingGroups",
                "ec2:Describe*"
            ]
        ))

        create_mock_servers_asg_role.add_to_policy(iam.PolicyStatement(
            resources=[
                f"arn:aws:elasticloadbalancing:{self.region}:{self.account}:loadbalancer/app/*/*",
                f"arn:aws:elasticloadbalancing:{self.region}:{self.account}:loadbalancer/net/*/*",
                f"arn:aws:elasticloadbalancing:{self.region}:{self.account}:listener/app/*/*"
            ],
            actions=[
                "elasticloadbalancing:CreateListener"
            ]
        ))

        create_mock_servers_asg_role.add_to_policy(iam.PolicyStatement(
            resources=[
                f"arn:aws:elasticloadbalancing:{self.region}:{self.account}:targetgroup/*/*"
            ],
            actions=[
                "elasticloadbalancing:RegisterTargets"
            ]
        ))

        create_mock_servers_asg_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[f"arn:aws:iam::{self.account}:role/*"],
            actions=[
                "iam:PassRole",
                "iam:CreateServiceLinkedRole"
            ]
        ))

        create_mock_servers_asg_lambda = _lambda.Function(
            scope=self,
            id="secure-proxy-create-mock-servers-asg-lambda",
            code=_lambda.Code.from_asset(f"{dirname}/resources/lambda"),
            handler="create_mock_servers_asg.lambda_handler",
            role=create_mock_servers_asg_role,
            runtime=_lambda.Runtime.PYTHON_3_9,
            timeout=cdk.Duration.minutes(15),
            dead_letter_queue=dead_letter_queue
        )

        ##################################################
        ## </END> Lambda definitions
        ##################################################

        ##################################################
        ## <START> StepFunctions definition
        ##################################################

        secure_proxy_logs_group = logs.LogGroup(
            self,
            "secure-proxy-state-machine-logs-group",
            retention=logs.RetentionDays.TWO_WEEKS,
            encryption_key=secure_proxy_kms_key,
            log_group_name=f'/aws/vendedlogs/states/secureproxy',
            removal_policy=cdk.RemovalPolicy.DESTROY
        )

        entry_point_step_01 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Start EC2 ImageBuilder pipeline execution",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=entry_point_lambda
        )

        entry_point_step_01_result_choice = stepfunctions.Choice(
            self,
            "Was EC2 Image Builder pipeline execution successfull?",
            input_path="$",
            output_path="$"
        )

        poll_ami_status_step_02 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Poll AMI Statuses until status is AVAILABLE",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=poll_ami_status_lambda
        )

        poll_ami_status_step_02_result_choice = stepfunctions.Choice(
            self,
            "Did AMI statuses request complete successfully?",
            input_path="$",
            output_path="$"
        )

        poll_ami_status_step_02_poll_choice = stepfunctions.Choice(
            self,
            "Are AMI statuses AVAILABLE?",
            input_path="$",
            output_path="$"
        )

        poll_ami_status_step_02_wait = stepfunctions.Wait(
            self,
            "Wait to recheck AMI statuses are AVAILABLE",
            time=stepfunctions.WaitTime.duration(cdk.Duration.minutes(3))
        )

        get_ami_details_step_03 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Get AMI Details",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=get_ami_details_lambda
        )

        get_ami_details_step_03_result_choice = stepfunctions.Choice(
            self,
            "Were AMI details obtained successfully?",
            input_path="$",
            output_path="$"
        )

        create_secure_proxy_step_04 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Create Secure Proxy EC2 Instance",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=create_secure_proxy_lambda
        )

        create_secure_proxy_step_04_result_choice = stepfunctions.Choice(
            self,
            "Was Secure Proxy EC2 Instance created successfully?",
            input_path="$",
            output_path="$"
        )

        create_mock_servers_asg_step_05 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Create Mock Servers AutoScaling Group",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=create_mock_servers_asg_lambda
        )

        create_mock_servers_asg_step_05_result_choice = stepfunctions.Choice(
            self,
            "Was Mock Servers AutoScaling Group created successfully?",
            input_path="$",
            output_path="$"
        )

        secure_proxy_step_success = stepfunctions.Succeed(
            self,
            "Secure Proxy event success."
        )

        secure_proxy_step_fail = stepfunctions.Fail(
            self,
            "Secure Proxy event failure."
        )

        entry_point_step_01_result_choice.when(stepfunctions.Condition.string_equals('$.secure_proxy_event.output.status', "ERROR"),
                                    secure_proxy_step_fail).otherwise(poll_ami_status_step_02)

        poll_ami_status_step_02.next(poll_ami_status_step_02_result_choice)

        poll_ami_status_step_02_result_choice.when(stepfunctions.Condition.string_equals('$.secure_proxy_event.output.status', "ERROR"),
            secure_proxy_step_fail).otherwise(poll_ami_status_step_02_poll_choice)

        poll_ami_status_step_02_poll_choice.when(
            stepfunctions.Condition.and_(
                stepfunctions.Condition.string_equals('$.secure_proxy_event.output.ami_states.secure_proxy', "AVAILABLE"),
                stepfunctions.Condition.string_equals('$.secure_proxy_event.output.ami_states.mock_servers', "AVAILABLE")
            ),
            get_ami_details_step_03).otherwise(poll_ami_status_step_02_wait)

        poll_ami_status_step_02_wait.next(poll_ami_status_step_02)

        get_ami_details_step_03.next(get_ami_details_step_03_result_choice)

        get_ami_details_step_03_result_choice.when(stepfunctions.Condition.string_equals('$.secure_proxy_event.output.status', "ERROR"),
                                    secure_proxy_step_fail).otherwise(create_secure_proxy_step_04)

        create_secure_proxy_step_04.next(create_secure_proxy_step_04_result_choice)

        create_secure_proxy_step_04_result_choice.when(stepfunctions.Condition.string_equals('$.secure_proxy_event.output.status', "ERROR"),
                                    secure_proxy_step_fail).otherwise(create_mock_servers_asg_step_05)

        create_mock_servers_asg_step_05.next(create_mock_servers_asg_step_05_result_choice)

        create_mock_servers_asg_step_05_result_choice.when(stepfunctions.Condition.string_equals('$.secure_proxy_event.output.status', "ERROR"),
                                    secure_proxy_step_fail).otherwise(secure_proxy_step_success)

        # step functions state machine
        secure_proxy_state_machine = stepfunctions.StateMachine(
            self, 
            "secure-proxy-state-machine",
            timeout=cdk.Duration.hours(3),
            definition=entry_point_step_01.next(entry_point_step_01_result_choice),
            logs=stepfunctions.LogOptions(
                destination=secure_proxy_logs_group,
                level=stepfunctions.LogLevel.ALL
            )
        )

        ##################################################
        ## </END> StepFunctions definition
        ##################################################


        ##################################################
        ## <START> Create SSM Param Store keys
        ##################################################

        secure_proxy_ssm_prefix = config['ssm']['projectPrefix']

        ssm.StringParameter(
            self, "secure-proxy-pipeline-arn-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-pipeline-arn',
            string_value=secure_proxy_pipeline.attr_arn,
            description="Secure Proxy EC2 ImageBuilder Pipeline cdk.Arn"
        )

        ssm.StringParameter(
            self, "mock-servers-pipeline-arn-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/mock-servers-pipeline-arn',
            string_value=mock_servers_pipeline.attr_arn,
            description="Mock Servers EC2 ImageBuilder Pipeline cdk.Arn"
        )

        ssm.StringParameter(
            self, "secure-proxy-nlb-dns-name-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-nlb-dns-name',
            string_value=secure_proxy_elb.load_balancer_dns_name,
            description="Secure Proxy NLB DNS Name"
        )

        ssm.StringParameter(
            self, "secure-proxy-vpc-id-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-vpc-id',
            string_value=secure_proxy_vpc.vpc_id,
            description="Secure Proxy VPC Id"
        )

        ssm.StringParameter(
            self, "secure-proxy-elb-security-group-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-elb-security-group',
            string_value=nlb_traffic_sg.security_group_id,
            description="NLB Traffic Security Group Id"
        )

        ssm.StringParameter(
            self, "secure-proxy-elb-arn-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-elb-arn',
            string_value=secure_proxy_elb.load_balancer_arn,
            description="NLB ARN"
        )

        ssm.StringParameter(
            self, "secure-proxy-elb-wss-port-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-elb-wss-port',
            string_value=str(wss_nlb_port),
            description="NLB WSS Traffic Port"
        )

        ssm.StringParameter(
            self, "secure-proxy-elb-oauth-port-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-elb-oauth-port',
            string_value=str(oauth_nlb_port),
            description="NLB OAuth Traffic Port"
        )

        ssm.StringParameter(
            self, "secure-proxy-ec2-instance-profile-arn-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-ec2-instance-profile-arn',
            string_value=secure_proxy_ec2_instance_profile.attr_arn,
            description="Secure Proxy EC2 Instance Profile ARN"
        )

        ssm.StringParameter(
            self, "secure-proxy-vpc-public-subnet-id-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-vpc-public-subnet-id',
            string_value=secure_proxy_vpc.public_subnets[0].subnet_id,
            description="Secure Proxy VPC Public Subnet Id"
        )

        ssm.StringParameter(
            self, "secure-proxy-vpc-private-subnet-id-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-vpc-private-subnet-id',
            string_value=secure_proxy_vpc.private_subnets[0].subnet_id,
            description="Secure Proxy VPC Private Subnet Id"
        )

        ssm.StringParameter(
            self, "secure-proxy-security-group-id-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-security-group-id',
            string_value=secure_proxy_sg.security_group_id,
            description="Secure Proxy Security Group Id"
        )

        ssm.StringParameter(
            self, "mock-servers-security-group-id-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/mock-servers-security-group-id',
            string_value=nlb_traffic_sg.security_group_id,
            description="Mock Servers Security Group Id"
        )

        ssm.StringParameter(
            self, "secure-proxy-state-machine-arn-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-state-machine-arn',
            string_value=secure_proxy_state_machine.state_machine_arn,
            description="Secure Proxy State Machine ARN"
        )

        ssm.StringParameter(
            self, "secure-proxy-wss-bind-port-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-wss-bind-port',
            string_value=str(config["proxySettings"]["wssProxyBindPort"]),
            description="Secure Proxy WSS Bind Port"
        )

        ssm.StringParameter(
            self, "secure-proxy-oauth-bind-port-ssm",
            parameter_name=f'/{secure_proxy_ssm_prefix}/secure-proxy-oauth-bind-port',
            string_value=str(config["proxySettings"]["oAuthProxyBindPort"]),
            description="Secure Proxy oAuth Bind Port"
        )

        ##################################################
        ## </END> Create SSM Param Store keys
        ##################################################


        ##################################################
        ## <START> CDK Outputs
        ##################################################

        cdk.CfnOutput(
            self, 
            id="secure-proxy-pipeline-arn-output", 
            value=secure_proxy_pipeline.attr_arn,
            description="Secure Proxy EC2 ImageBuilder Pipeline cdk.Arn"
        ).override_logical_id("secureProxyPipelineArn")

        cdk.CfnOutput(
            self, 
            id="mock-servers-pipeline-arn-output", 
            value=mock_servers_pipeline.attr_arn,
            description="Mock Servers EC2 ImageBuilder Pipeline cdk.Arn"
        ).override_logical_id("mockServersPipelineArn")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-nlb-dns-name-output", 
            value=mock_servers_pipeline.attr_arn,
            description="Secure Proxy NLB DNS Name"
        ).override_logical_id("secureProxyNlbDnsName")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-vpc-id-output", 
            value=mock_servers_pipeline.attr_arn,
            description="Secure Proxy VPC Id"
        ).override_logical_id("secureProxyVpcId")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-elb-security-group-output", 
            value=nlb_traffic_sg.security_group_id,
            description="NLB Traffic Security Group Id"
        ).override_logical_id("secureProxyElbSecurityGroup")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-elb-arn-output", 
            value=secure_proxy_elb.load_balancer_arn,
            description="NLB ARN"
        ).override_logical_id("secureProxyElbArn")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-elb-wss-port-output", 
            value=str(wss_nlb_port),
            description="NLB WSS Traffic Port"
        ).override_logical_id("secureProxyElbWssPort")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-elb-oauth-port-output", 
            value=str(oauth_nlb_port),
            description="NLB OAuth Traffic Port"
        ).override_logical_id("secureProxyElbOauthPort")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-ec2-instance-profile-arn-output", 
            value=secure_proxy_ec2_instance_profile.attr_arn,
            description="Secure Proxy EC2 Instance Profile ARN"
        ).override_logical_id("secureProxyEc2InstanceProfileArn")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-vpc-public-subnet-id-output", 
            value=secure_proxy_vpc.public_subnets[0].subnet_id,
            description="Secure Proxy VPC Public Subnet Id"
        ).override_logical_id("secureProxyVpcPublicSubnetId")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-vpc-private-subnet-id-output", 
            value=secure_proxy_vpc.private_subnets[0].subnet_id,
            description="Secure Proxy VPC Private Subnet Id"
        ).override_logical_id("secureProxyVpcPrivateSubnetId")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-security-group-id-output", 
            value=secure_proxy_sg.security_group_id,
            description="Secure Proxy Security Group Id"
        ).override_logical_id("secureProxySecurityGroupId")

        cdk.CfnOutput(
            self, 
            id="mock-servers-security-group-id-output", 
            value=nlb_traffic_sg.security_group_id,
            description="Mock Servers Security Group Id"
        ).override_logical_id("mockServersSecurityGroupId")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-state-machine-arn-output", 
            value=secure_proxy_state_machine.state_machine_arn,
            description="Secure Proxy State Machine ARN"
        ).override_logical_id("secureProxyStateMachineArn")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-wss-bind-port-output", 
            value=str(config["proxySettings"]["wssProxyBindPort"]),
            description="Secure Proxy WSS Bind Port"
        ).override_logical_id("secureProxyWssBindPort")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-oauth-bind-port-output", 
            value=str(config["proxySettings"]["oAuthProxyBindPort"]),
            description="Secure Proxy oAuth Bind Port"
        ).override_logical_id("secureProxyOauthBindPort")

        cdk.CfnOutput(
            self, 
            id="secure-proxy-ec2-role-output",
            value=secure_proxy_ec2_role.role_name,
            description="Secure Proxy EC2 Role Name"
        ).override_logical_id("secureProxyEc2RoleName")
        
        ##################################################
        ## </END> CDK Outputs
        ##################################################
