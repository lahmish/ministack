"""Unit tests for SCP per-service resource-ARN extraction (ministack.core.scp_resources).

Pure / in-process — no running server. Account + region come from the request
contextvars, which the autouse fixture pins to deterministic values.
"""

import pytest

from ministack.core import scp_resources as r
from ministack.core.responses import set_request_account_id, set_request_region

_JSON = {"content-type": "application/x-amz-json-1.0"}
_FORM = {"content-type": "application/x-www-form-urlencoded"}


@pytest.fixture(autouse=True)
def _ctx():
    set_request_account_id("123456789012")
    set_request_region("us-west-2")
    yield
    set_request_account_id("000000000000")
    set_request_region("us-east-1")


# --- s3 (path-based) -------------------------------------------------------

def test_s3_bucket_and_key():
    assert r.extract_resource_arn(
        "s3", "GET", "/my-bucket/some/key.txt", {}, b"", {}, "s3:GetObject"
    ) == "arn:aws:s3:::my-bucket/some/key.txt"


def test_s3_bucket_only():
    assert r.extract_resource_arn(
        "s3", "PUT", "/my-bucket", {}, b"", {}, "s3:CreateBucket"
    ) == "arn:aws:s3:::my-bucket"


def test_s3_list_buckets_has_no_specific_resource():
    assert r.extract_resource_arn("s3", "GET", "/", {}, b"", {}, "s3:ListBuckets") is None


# --- dynamodb (json body) --------------------------------------------------

def test_dynamodb_table_from_json_body():
    arn = r.extract_resource_arn(
        "dynamodb", "POST", "/", _JSON, b'{"TableName":"Orders"}', {}, "dynamodb:PutItem")
    assert arn == "arn:aws:dynamodb:us-west-2:123456789012:table/Orders"


def test_dynamodb_missing_table():
    assert r.extract_resource_arn(
        "dynamodb", "POST", "/", _JSON, b"{}", {}, "dynamodb:ListTables") is None


# --- sqs (body QueueUrl or path tail) --------------------------------------

def test_sqs_queue_from_queue_url():
    body = b'{"QueueUrl":"http://localhost:4566/123456789012/my-queue"}'
    arn = r.extract_resource_arn("sqs", "POST", "/", _JSON, body, {}, "sqs:SendMessage")
    assert arn == "arn:aws:sqs:us-west-2:123456789012:my-queue"


def test_sqs_queue_from_path():
    arn = r.extract_resource_arn(
        "sqs", "POST", "/123456789012/path-queue", {}, b"", {}, "sqs:SendMessage")
    assert arn == "arn:aws:sqs:us-west-2:123456789012:path-queue"


def test_sqs_missing():
    assert r.extract_resource_arn("sqs", "POST", "/", {}, b"", {}, "sqs:ListQueues") is None


# --- sns (TopicArn passthrough) --------------------------------------------

def test_sns_topic_arn_passthrough_form():
    body = b"Action=Publish&TopicArn=arn:aws:sns:us-east-1:111122223333:alerts"
    arn = r.extract_resource_arn("sns", "POST", "/", _FORM, body, {}, "sns:Publish")
    assert arn == "arn:aws:sns:us-east-1:111122223333:alerts"


def test_sns_without_arn_returns_none():
    arn = r.extract_resource_arn("sns", "POST", "/", _FORM, b"Action=ListTopics", {}, "sns:ListTopics")
    assert arn is None


# --- lambda (path or body, arn passthrough) --------------------------------

def test_lambda_function_from_path():
    arn = r.extract_resource_arn(
        "lambda", "POST", "/2015-03-31/functions/my-fn/invocations", {}, b"", {}, "lambda:Invoke")
    assert arn == "arn:aws:lambda:us-west-2:123456789012:function:my-fn"


def test_lambda_function_from_body():
    arn = r.extract_resource_arn(
        "lambda", "POST", "/", {"content-type": "application/json"},
        b'{"FunctionName":"body-fn"}', {}, "lambda:GetFunction")
    assert arn == "arn:aws:lambda:us-west-2:123456789012:function:body-fn"


def test_lambda_arn_passthrough():
    full = "arn:aws:lambda:eu-west-1:111122223333:function:explicit"
    body = ('{"FunctionName":"%s"}' % full).encode()
    arn = r.extract_resource_arn(
        "lambda", "POST", "/", {"content-type": "application/json"}, body, {}, "lambda:Invoke")
    assert arn == full


# --- secretsmanager (SecretId name or arn) ---------------------------------

def test_secretsmanager_name_built_into_arn():
    arn = r.extract_resource_arn(
        "secretsmanager", "POST", "/", _JSON, b'{"SecretId":"prod/db"}', {},
        "secretsmanager:GetSecretValue")
    assert arn == "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/db"


def test_secretsmanager_arn_passthrough():
    full = "arn:aws:secretsmanager:us-east-1:111122223333:secret:thing-AbCdEf"
    body = ('{"SecretId":"%s"}' % full).encode()
    arn = r.extract_resource_arn("secretsmanager", "POST", "/", _JSON, body, {},
                                 "secretsmanager:GetSecretValue")
    assert arn == full


# --- kinesis / firehose / ecr ----------------------------------------------

def test_kinesis_stream_name():
    arn = r.extract_resource_arn("kinesis", "POST", "/", _JSON, b'{"StreamName":"events"}', {},
                                 "kinesis:PutRecord")
    assert arn == "arn:aws:kinesis:us-west-2:123456789012:stream/events"


def test_kinesis_stream_arn_passthrough():
    full = "arn:aws:kinesis:eu-west-1:111122223333:stream/explicit"
    arn = r.extract_resource_arn("kinesis", "POST", "/", _JSON,
                                 ('{"StreamARN":"%s"}' % full).encode(), {}, "kinesis:PutRecord")
    assert arn == full


def test_firehose_delivery_stream():
    arn = r.extract_resource_arn("firehose", "POST", "/", _JSON,
                                 b'{"DeliveryStreamName":"logs-fh"}', {}, "firehose:PutRecord")
    assert arn == "arn:aws:firehose:us-west-2:123456789012:deliverystream/logs-fh"


def test_ecr_repository():
    arn = r.extract_resource_arn("ecr", "POST", "/", _JSON,
                                 b'{"repositoryName":"app/api"}', {}, "ecr:PutImage")
    assert arn == "arn:aws:ecr:us-west-2:123456789012:repository/app/api"


# --- ssm / kms -------------------------------------------------------------

def test_ssm_parameter_strips_leading_slash():
    arn = r.extract_resource_arn("ssm", "POST", "/", _JSON, b'{"Name":"/app/db/password"}', {},
                                 "ssm:GetParameter")
    assert arn == "arn:aws:ssm:us-west-2:123456789012:parameter/app/db/password"


def test_ssm_document_resource_type():
    arn = r.extract_resource_arn("ssm", "POST", "/", _JSON, b'{"Name":"MyDoc"}', {},
                                 "ssm:CreateDocument")
    assert arn == "arn:aws:ssm:us-west-2:123456789012:document/MyDoc"


def test_kms_key_id():
    arn = r.extract_resource_arn("kms", "POST", "/", _JSON,
                                 b'{"KeyId":"1234abcd-12ab-34cd-56ef-1234567890ab"}', {},
                                 "kms:Decrypt")
    assert arn == "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"


def test_kms_alias_and_arn():
    assert r.extract_resource_arn("kms", "POST", "/", _JSON, b'{"KeyId":"alias/prod"}', {},
                                  "kms:Encrypt") == "arn:aws:kms:us-west-2:123456789012:alias/prod"
    full = "arn:aws:kms:eu-west-1:111122223333:key/abc"
    assert r.extract_resource_arn("kms", "POST", "/", _JSON,
                                  ('{"KeyId":"%s"}' % full).encode(), {}, "kms:Decrypt") == full


# --- logs / states ---------------------------------------------------------

def test_logs_log_group():
    arn = r.extract_resource_arn("logs", "POST", "/", _JSON,
                                 b'{"logGroupName":"/aws/lambda/fn"}', {}, "logs:PutLogEvents")
    assert arn == "arn:aws:logs:us-west-2:123456789012:log-group:/aws/lambda/fn:*"


def test_states_arn_passthrough():
    full = "arn:aws:states:us-east-1:111122223333:stateMachine:Orders"
    arn = r.extract_resource_arn("states", "POST", "/", _JSON,
                                 ('{"stateMachineArn":"%s"}' % full).encode(), {},
                                 "states:StartExecution")
    assert arn == full


def test_states_name_builds_state_machine():
    arn = r.extract_resource_arn("states", "POST", "/", _JSON, b'{"name":"Orders"}', {},
                                 "states:CreateStateMachine")
    assert arn == "arn:aws:states:us-west-2:123456789012:stateMachine:Orders"


def test_states_activity_name():
    arn = r.extract_resource_arn("states", "POST", "/", _JSON, b'{"name":"work"}', {},
                                 "states:CreateActivity")
    assert arn == "arn:aws:states:us-west-2:123456789012:activity:work"


# --- fallback / safety -----------------------------------------------------

def test_unknown_service_returns_none():
    assert r.extract_resource_arn("ec2", "POST", "/", {}, b"", {}, "ec2:RunInstances") is None
    assert r.extract_resource_arn("iam", "POST", "/", {}, b"", {}, "iam:CreateUser") is None


def test_garbage_body_is_safe():
    # Invalid bytes must not raise — extractor returns None (-> engine treats as '*').
    assert r.extract_resource_arn(
        "dynamodb", "POST", "/", _JSON, b"\xff\xfe not json", {}, "dynamodb:PutItem") is None
