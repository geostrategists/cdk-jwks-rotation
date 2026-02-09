import { Duration, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import * as s3 from "aws-cdk-lib/aws-s3";
import { describe, expect, it } from "vitest";
import { JwksRotation } from "../src/jwks-rotation";

describe("JwksRotation Construct", () => {
  it("should create resources with default props", () => {
    const stack = new Stack();
    const construct = new JwksRotation(stack, "TestJwksRotation", {
      secretName: "test-secret-name",
      maxTokenValidityDuration: Duration.hours(1),
      keySpec: { algorithm: "RS256" },
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties("AWS::S3::Bucket", {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
      },
    });

    template.hasResourceProperties("AWS::SecretsManager::Secret", {
      Name: "test-secret-name",
    });

    template.hasResourceProperties("AWS::Lambda::Function", {
      Runtime: "nodejs24.x",
      Handler: "rotation-handler.handler",
    });

    template.hasResourceProperties("AWS::Events::Rule", {
      ScheduleExpression: "rate(1 day)",
    });

    template.hasResourceProperties("AWS::SecretsManager::RotationSchedule", {
      RotationRules: { ScheduleExpression: "rate(60 days)" },
    });

    expect(construct.bucket).toBeDefined();
    expect(construct.secret).toBeDefined();
    expect(construct.rotationLambda).toBeDefined();
  });

  it("should use existing bucket when provided", () => {
    const stack = new Stack();
    const existingBucket = new s3.Bucket(stack, "ExistingBucket");

    const construct = new JwksRotation(stack, "TestJwksRotation", {
      secretName: "test-secret-name",
      bucket: existingBucket,
      maxTokenValidityDuration: Duration.hours(1),
      keySpec: { algorithm: "RS256" },
    });

    expect(construct.bucket).toBe(existingBucket);
  });

  it("should create resources with custom props", () => {
    const stack = new Stack();
    new JwksRotation(stack, "TestJwksRotation", {
      secretName: "custom-secret",
      bucketPath: "custom/path/jwks.json",
      rotationInterval: Duration.days(30),
      minActivationGracePeriod: Duration.days(3),
      cleanupCheckInterval: Duration.hours(12),
      maxTokenValidityDuration: Duration.hours(2),
      keySpec: { algorithm: "ES256", crv: "P-256" },
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties("AWS::SecretsManager::Secret", {
      Name: "custom-secret",
    });

    template.hasResourceProperties("AWS::SecretsManager::RotationSchedule", {
      RotationRules: { ScheduleExpression: "rate(30 days)" },
    });

    template.hasResourceProperties("AWS::Events::Rule", {
      ScheduleExpression: "rate(12 hours)",
    });

    template.hasResourceProperties("AWS::Lambda::Function", {
      Environment: {
        Variables: {
          BUCKET_PATH: "custom/path/jwks.json",
          MIN_ACTIVATION_GRACE_PERIOD_SECONDS: "259200",
          MAX_TOKEN_VALIDITY_DURATION_SECONDS: "7200",
          KEY_SPEC: JSON.stringify({ algorithm: "ES256", crv: "P-256" }),
        },
      },
    });
  });

  it("should grant proper IAM permissions", () => {
    const stack = new Stack();
    new JwksRotation(stack, "TestJwksRotation", {
      secretName: "test-secret-name",
      maxTokenValidityDuration: Duration.hours(1),
      keySpec: { algorithm: "RS256" },
    });

    const template = Template.fromStack(stack);

    template.resourceCountIs("AWS::IAM::Policy", 1);
  });

  it("should create EventBridge rule for cleanup", () => {
    const stack = new Stack();
    new JwksRotation(stack, "TestJwksRotation", {
      secretName: "test-secret-name",
      maxTokenValidityDuration: Duration.hours(1),
      keySpec: { algorithm: "RS256" },
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties("AWS::Events::Rule", {
      ScheduleExpression: "rate(1 day)",
    });

    template.resourceCountIs("AWS::Events::Rule", 1);
  });
});
