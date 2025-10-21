"""CDK stack defining the IaC scanner CodeCommit/CodeBuild workflow."""
from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import Duration
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_codecommit as codecommit
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from constructs import Construct


class PipelineStack(cdk.Stack):
    """Provision a CodeCommit repository, CodeBuild project, and trigger rule."""

    def __init__(self, scope: Construct, construct_id: str, *, env: cdk.Environment | None = None) -> None:
        super().__init__(scope, construct_id, env=env)

        repository = codecommit.Repository(
            self,
            "IaCScannerRepository",
            repository_name="IaCScanner",
            description="Infrastructure-as-code security scanner repository",
        )

        artifacts_bucket = s3.Bucket(
            self,
            "ScannerArtifactsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            auto_delete_objects=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        project_role = iam.Role(
            self,
            "CodeBuildRole",
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
        )
        project_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "codecommit:BatchGet*",
                    "codecommit:BatchDescribe*",
                    "codecommit:Get*",
                    "codecommit:List*",
                    "codecommit:GitPull",
                    "codecommit:PostCommentForPullRequest",
                ],
                resources=[repository.repository_arn],
            )
        )
        project_role.add_to_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                resources=[artifacts_bucket.arn_for_objects("*")],
            )
        )
        project_role.add_to_policy(
            iam.PolicyStatement(actions=["s3:ListBucket"], resources=[artifacts_bucket.bucket_arn])
        )
        project_role.add_to_policy(
            iam.PolicyStatement(
                actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                resources=["*"]
            )
        )

        environment_variables = {
            "FAIL_ON": codebuild.BuildEnvironmentVariable(value="MEDIUM"),
            "COMMENT_TARGET": codebuild.BuildEnvironmentVariable(value="codecommit"),
            "BASELINE_MODE": codebuild.BuildEnvironmentVariable(value="strict"),
        }

        project = codebuild.Project(
            self,
            "IaCScannerBuild",
            project_name="IaCScannerBuild",
            source=codebuild.Source.code_commit(repository=repository),
            role=project_role,
            build_spec=codebuild.BuildSpec.from_source_filename("pipeline/buildspec.yml"),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                compute_type=codebuild.ComputeType.SMALL,
            ),
            environment_variables=environment_variables,
            artifacts=codebuild.Artifacts.s3(bucket=artifacts_bucket, include_build_id=True, package_zip=False),
            timeout=Duration.minutes(30),
        )

        rule = events.Rule(
            self,
            "PullRequestTriggerRule",
            event_pattern=events.EventPattern(
                source=["aws.codecommit"],
                detail_type=["CodeCommit Pull Request State Change"],
                detail={
                    "repositoryName": [repository.repository_name],
                    "event": ["pullRequestCreated", "pullRequestSourceBranchUpdated"],
                },
            ),
        )
        rule.add_target(targets.CodeBuildProject(project))

        cdk.CfnOutput(
            self,
            "CodeBuildConsoleUrl",
            value=cdk.Fn.sub(
                "https://console.aws.amazon.com/codesuite/codebuild/${AWS::Region}/${AWS::AccountId}/projects/${ProjectName}/build",
                {"ProjectName": project.project_name},
            ),
        )
        cdk.CfnOutput(self, "ArtifactsBucket", value=artifacts_bucket.bucket_name)
