import os

from aws_cdk import (
    core,
    aws_imagebuilder as imagebuilder,
    aws_iam as iam,
    aws_s3_assets as assets,
    aws_sns as sns,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elb,
    aws_autoscaling as autoscaling,
    aws_ssm as ssm,
    aws_kms as kms,
    aws_logs as logs
)

from utils.CdkUtils import CdkUtils
from utils.FileUtils import FileUtils


class SecureProxyStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        config = CdkUtils.get_project_settings()

        ##################################################
        ## <START> Network prequisites
        ## VPC, Subnets, ELB, NACLS, Security Groups
        ##################################################

        # NLB listening ports
        wss_nlb_port = int(config["proxySettings"]["wssProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"])
        oauth_nlb_port = int(config["proxySettings"]["oAuthProxyBindPort"]) - int(config["proxySettings"]["proxyPortScaleFactor"])

        # create the VPC
        secure_proxy_vpc = ec2.Vpc(
            self,
            f"secure-proxy-vpc-{CdkUtils.stack_tag}",
            cidr=config["vpc"]["cidr"],
            max_azs=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name=f"secure-proxy-subnet-public-{CdkUtils.stack_tag}",
                    cidr_mask=config["vpc"]["subnets"]["mask"],
                    subnet_type=ec2.SubnetType.PUBLIC
                ),
                ec2.SubnetConfiguration(
                    name=f"secure-proxy-subnet-private-{CdkUtils.stack_tag}",
                    cidr_mask=config["vpc"]["subnets"]["mask"],
                    subnet_type=ec2.SubnetType.PRIVATE
                )
            ]
        )

        # SG for the Secure Proxy EC2 instance
        secure_proxy_sg = ec2.SecurityGroup(
            self, f"secure-proxy-security-group-{CdkUtils.stack_tag}",
            vpc=secure_proxy_vpc,
            allow_all_outbound=True,
            description="Security group for the Secure Proxy traffic",
            security_group_name=f"secure-proxy-{CdkUtils.stack_tag}"
        )

        secure_proxy_sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(22),
            description="SSH traffic"
        )

        secure_proxy_sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(int(config["proxySettings"]["wssProxyBindPort"])),
            description="WSS traffic"
        )

        secure_proxy_sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(int(config["proxySettings"]["oAuthProxyBindPort"])),
            description="oAuth traffic"
        )

        # SG for the ELB
        nlb_traffic_sg = ec2.SecurityGroup(
            self, f"nlb-traffic-security-group-{CdkUtils.stack_tag}",
            vpc=secure_proxy_vpc,
            allow_all_outbound=True,
            description="Security group for the NLB traffic",
            security_group_name=f"nlb-traffic-{CdkUtils.stack_tag}"
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

        # secure proxy ELB
        secure_proxy_elb = elb.NetworkLoadBalancer(
            self, 
            f"secure-proxy-elb-{CdkUtils.stack_tag}",
            load_balancer_name=f"{config['elb']['namePrefix']}-{CdkUtils.stack_tag}",
            vpc=secure_proxy_vpc,
            internet_facing=False,
            vpc_subnets=ec2.SubnetSelection(subnets=secure_proxy_vpc.private_subnets),
            cross_zone_enabled=False,
            deletion_protection=False
        )

        wss_elb_listener = secure_proxy_elb.add_listener(
            f"wss-elb-listener-{CdkUtils.stack_tag}",
            port=wss_nlb_port
        )

        oauth_elb_listener = secure_proxy_elb.add_listener(
            f"oauth-elb-listener-{CdkUtils.stack_tag}",
            port=oauth_nlb_port
        )

        secure_proxy_asg = autoscaling.AutoScalingGroup(
            self,
            id=f"secure-proxy-asg-{CdkUtils.stack_tag}",
            vpc=secure_proxy_vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=secure_proxy_vpc.private_subnets),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE2,
                ec2.InstanceSize.MEDIUM
            ),
            machine_image=ec2.AmazonLinuxImage(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            ),
            desired_capacity=1,
            min_capacity=1,
            max_capacity=2,
            security_group=nlb_traffic_sg
        )

        wss_elb_listener.add_targets(
            f"wss-elb-listener-targets-{CdkUtils.stack_tag}",
            port=wss_nlb_port,
            targets=[secure_proxy_asg]
        )

        oauth_elb_listener.add_targets(
            f"oauth-elb-listener-targets-{CdkUtils.stack_tag}",
            port=oauth_nlb_port,
            targets=[secure_proxy_asg]
        )

        ##################################################
        ## </END> Network prequisites
        ##################################################

        ##################################################
        ## <START> EC2 ImageBuilder generic resources
        ##################################################

        # create a KMS key to encrypt project contents
        secure_proxy_kms_key = kms.Key(
            self, 
            f"secure-proxy-kms-key-{CdkUtils.stack_tag}",
            admins=[iam.AccountPrincipal(account_id=core.Aws.ACCOUNT_ID)],
            enable_key_rotation=True,
            enabled=True,
            description="KMS key used with EC2 Imagebuilder Secure Proxy project",
            removal_policy=core.RemovalPolicy.DESTROY,
            alias=f"secure-proxy-kms-key-alias-{CdkUtils.stack_tag}"
        )

        secure_proxy_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal(service=f'imagebuilder.{core.Aws.URL_SUFFIX}'))

        # below role is assumed by the ImageBuilder ec2 instance
        secure_proxy_image_role = iam.Role(self, f"secure-proxy-image-role-{CdkUtils.stack_tag}", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
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
                core.Arn.format(components=core.ArnComponents(
                    service="logs",
                    resource="log-group",
                    resource_name="aws/imagebuilder/*"
                ), stack=self)
            ],
        ))

        # create an instance profile to attach the role
        instance_profile = iam.CfnInstanceProfile(
            self, f"secure-proxy-imagebuilder-instance-profile-{CdkUtils.stack_tag}",
            instance_profile_name=f"secure-proxy-imagebuilder-instance-profile-{CdkUtils.stack_tag}",
            roles=[secure_proxy_image_role.role_name]
        )

        ssm.StringListParameter(
            self, f"secure-proxy-distribution-list-{CdkUtils.stack_tag}",
            parameter_name=f'/{CdkUtils.stack_tag}-SecureProxyPipeline/DistributionList',
            string_list_value=config["imagebuilder"]['distributionList']
        )

        sns_topic = sns.Topic(
            self, f"secure-proxy-imagebuilder-topic-{CdkUtils.stack_tag}",
            topic_name=f"secure-proxy-imagebuilder-topic-{CdkUtils.stack_tag}",
            master_key=secure_proxy_kms_key
        )

        sns.Subscription(
            self, f"secure-proxy-imagebuilder-subscription-{CdkUtils.stack_tag}",
            topic=sns_topic,
            endpoint=config["imagebuilder"]["imageBuilderEmailAddress"],
            protocol=sns.SubscriptionProtocol.EMAIL
        )

        sns_topic.grant_publish(secure_proxy_image_role)
        secure_proxy_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal(service=f'sns.{core.Aws.URL_SUFFIX}'))

        # SG for the image build
        secure_proxy_imagebuilder_sg = ec2.SecurityGroup(
            self, f"secure-proxy-imagebuilder-sg-{CdkUtils.stack_tag}",
            vpc=secure_proxy_vpc,
            allow_all_outbound=True,
            description="Security group for the EC2 Image Builder Pipeline: " + self.stack_name + "-Pipeline",
            security_group_name=f"secure-proxy-imagebuilder-sg-{CdkUtils.stack_tag}"
        )

        # create infrastructure configuration to supply instance type
        infra_config = imagebuilder.CfnInfrastructureConfiguration(
            self, f"secure-proxy-infra-config-{CdkUtils.stack_tag}",
            name=f"secure-proxy-infra-config-{CdkUtils.stack_tag}",
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
            f"secure-proxy-logs-group-{CdkUtils.stack_tag}",
            retention=logs.RetentionDays.TWO_WEEKS,
            encryption_key=secure_proxy_kms_key,
            log_group_name=config["proxySettings"]["proxyCloudwatchLogGroup"] + f"/{CdkUtils.stack_tag}",
            removal_policy=core.RemovalPolicy.DESTROY
        )

        secure_proxy_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal(service=f'logs.{core.Aws.URL_SUFFIX}'))

        # grab the values for the Secure Proxy component from cdk.json
        secure_proxy_substitutions = {
            "AWS_NLB_NAME": f"{config['elb']['namePrefix']}-{CdkUtils.stack_tag}",
            "JAIL_BASE_DIR": config["proxySettings"]["jailBaseDir"],
            "PROXY_BASE_DIR": config["proxySettings"]["proxyBaseDir"],
            "PROXY_WORKER_PROCESSES": config["proxySettings"]["proxyWorkerProcesses"],
            "PROXY_WORKER_CONNECTIONS": config["proxySettings"]["proxyWorkerConnections"],
            "PROXY_CLOUDWATCH_LOGGROUP": config["proxySettings"]["proxyCloudwatchLogGroup"] + f"/{CdkUtils.stack_tag}",
            "KEEPALIVE_TIMEOUT": config["proxySettings"]["keepaliveTimeout"],
            "WSS_PROXY_BIND_PORT": config["proxySettings"]["wssProxyBindPort"],
            "OAUTH_PROXY_BIND_PORT": config["proxySettings"]["oAuthProxyBindPort"],
            "PROXY_PORT_SCALE_FACTOR": config["proxySettings"]["proxyPortScaleFactor"],
            "WEBSOCKIFY_CONNECT_TIMEOUT": config["proxySettings"]["websockifyConnectTimeout"],
            "WEBSOCKIFY_READ_TIMEOUT": config["proxySettings"]["websockifyReadTimeout"],
            "WEBSOCKIFY_SEND_TIMEOUT": config["proxySettings"]["websockifySendTimeout"]
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
            version="1.0.0",
            uri=secure_proxy_asset.s3_object_url,
            kms_key_id=secure_proxy_kms_key.key_arn,
            tags={
                "imagePipeline": "AMIBuilder",
                "project": "ec2-imagebuilder-secure-proxy"
            }
        )

         # recipe that installs the secure proxy components together with a Amazon Linux 2 base image
        secure_proxy_recipe = imagebuilder.CfnImageRecipe(
            self, f"secure-proxy-image-recipe-{CdkUtils.stack_tag}",
            name=f"secure-proxy-image-recipe-{CdkUtils.stack_tag}",
            version=config["imagebuilder"]["version"],
            components=[
                {
                    "componentArn": secure_proxy_component.attr_arn
                },
                {
                    "componentArn": core.Arn.format(components=core.ArnComponents(
                        service="imagebuilder",
                        resource="component",
                        resource_name="amazon-cloudwatch-agent-linux/x.x.x",
                        account="aws"
                    ), stack=self)
                },
                {
                    "componentArn": core.Arn.format(components=core.ArnComponents(
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
            description=f"Recipe to build and validate SecureProxyImageRecipe-{CdkUtils.stack_tag}",
            tags={
                "project": "ec2-imagebuilder-secure-proxy"
            },
            working_directory="/imagebuilder"
        )      

        # Distribution configuration for AMIs
        secure_proxy_distribution_config = imagebuilder.CfnDistributionConfiguration(
            self, f'secure-proxy-distribution-config-{CdkUtils.stack_tag}',
            name=f'secure-proxy-distribution-config-{CdkUtils.stack_tag}',
            distributions=[
                imagebuilder.CfnDistributionConfiguration.DistributionProperty(
                    region=self.region,
                    ami_distribution_configuration={
                        'Name': core.Fn.sub(f'SecureProxy-{CdkUtils.stack_tag}-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'),
                        'AmiTags': {
                            "project": "ec2-imagebuilder-secure-proxy",
                            'Pipeline': f"SecureProxyPipeline-{CdkUtils.stack_tag}"
                        }
                    }
                )
            ]
        )

        # build the imagebuilder pipeline
        secure_proxy_pipeline = imagebuilder.CfnImagePipeline(
            self, f"secure-proxy-pipeline-{CdkUtils.stack_tag}",
            name=f"secure-proxy-pipeline-{CdkUtils.stack_tag}",
            image_recipe_arn=secure_proxy_recipe.attr_arn,
            infrastructure_configuration_arn=infra_config.attr_arn,
            tags={
                "project": "ec2-imagebuilder-secure-proxy"
            },
            description=f"Image Pipeline for: SecureProxyPipeline-{CdkUtils.stack_tag}",
            enhanced_image_metadata_enabled=True,
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
            f"secure-proxy-ec2-role-{CdkUtils.stack_tag}",
            role_name=f"secure-proxy-ec2-role-{CdkUtils.stack_tag}",
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
            self, f"secure-proxy-ec2-instance-profile-{CdkUtils.stack_tag}",
            instance_profile_name=f"secure-proxy-ec2-instance-profile-{CdkUtils.stack_tag}",
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
            version="1.0.0",
            uri=mock_servers_asset.s3_object_url,
            kms_key_id=secure_proxy_kms_key.key_arn,
            tags={
                "imagePipeline": "AMIBuilder",
                "project": "ec2-imagebuilder-secure-proxy"
            }
        )

         # recipe that installs the mock servers components together with a Amazon Linux 2 base image
        mock_servers_recipe = imagebuilder.CfnImageRecipe(
            self, f"mock-servers-image-recipe-{CdkUtils.stack_tag}",
            name=f"mock-servers-image-recipe-{CdkUtils.stack_tag}",
            version=config["imagebuilder"]["version"],
            components=[
                {
                    "componentArn": mock_servers_component.attr_arn
                },
                {
                    "componentArn": core.Arn.format(components=core.ArnComponents(
                        service="imagebuilder",
                        resource="component",
                        resource_name="amazon-cloudwatch-agent-linux/x.x.x",
                        account="aws"
                    ), stack=self)
                },
                {
                    "componentArn": core.Arn.format(components=core.ArnComponents(
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
            description=f"Recipe to build and validate MockServersImageRecipe-{CdkUtils.stack_tag}",
            tags={
                "project": "ec2-imagebuilder-secure-proxy"
            },
            working_directory="/imagebuilder"
        )      

        # Distribution configuration for AMIs
        mock_servers_distribution_config = imagebuilder.CfnDistributionConfiguration(
            self, f'mock-servers-distribution-config-{CdkUtils.stack_tag}',
            name=f'mock-servers-distribution-config-{CdkUtils.stack_tag}',
            distributions=[
                imagebuilder.CfnDistributionConfiguration.DistributionProperty(
                    region=self.region,
                    ami_distribution_configuration={
                        'Name': core.Fn.sub(f'MockServers-{CdkUtils.stack_tag}-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'),
                        'AmiTags': {
                            "project": "ec2-imagebuilder-secure-proxy",
                            "Pipeline": f"MockServersPipeline-{CdkUtils.stack_tag}"
                        }
                    }
                )
            ]
        )

        # build the imagebuilder pipeline
        mock_servers_pipeline = imagebuilder.CfnImagePipeline(
            self, f"mock-servers-pipeline-{CdkUtils.stack_tag}",
            name=f"mock-servers-pipeline-{CdkUtils.stack_tag}",
            image_recipe_arn=mock_servers_recipe.attr_arn,
            infrastructure_configuration_arn=infra_config.attr_arn,
            tags={
                "project": "ec2-imagebuilder-secure-proxy"
            },
            description=f"Image Pipeline for: MockServersPipeline-{CdkUtils.stack_tag}",
            enhanced_image_metadata_enabled=True,
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
        ## <START> CDK Outputs
        ##################################################

        core.CfnOutput(
            self,
            id=f"export-secure-proxy-sns-topic-arn-{CdkUtils.stack_tag}",
            export_name=f"SecureProxy-SnsTopicArn-{CdkUtils.stack_tag}", 
            value=sns_topic.topic_arn,
            description="Secure Proxy Sns Topic"
        )
        
        core.CfnOutput(
            self,
            id=f"export-secure-proxy-kms-key-arn-{CdkUtils.stack_tag}",
            export_name=f"SecureProxy-KmsKeyArn-{CdkUtils.stack_tag}", 
            value=secure_proxy_kms_key.key_arn,
            description="Secure Proxy KMS Key ARN"
        )

        core.CfnOutput(
            self,
            id=f"export-secure-proxy-pipeline-arn-{CdkUtils.stack_tag}",
            export_name=f"SecureProxy-PipelineArn-{CdkUtils.stack_tag}",
            value=secure_proxy_pipeline.attr_arn,
            description="Secure Proxy Pipeline Arn"
        )

        core.CfnOutput(
            self,
            id=f"export-mock-servers-pipeline-arn-{CdkUtils.stack_tag}",
            export_name=f"MockServer-PipelineArn-{CdkUtils.stack_tag}",
            value=mock_servers_pipeline.attr_arn,
            description="Mock Servers Pipeline Arn"
        )

        core.CfnOutput(
            self,
            id=f"export-secure-proxy-elb-dns-name-{CdkUtils.stack_tag}",
            export_name=f"SecureProxy-ELB-DNS-Name-{CdkUtils.stack_tag}", 
            value=secure_proxy_elb.load_balancer_dns_name,
            description="Secure Proxy ELB DNS Name"
        )

        ##################################################
        ## </END> CDK Outputs
        ##################################################