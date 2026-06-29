"""Service Control Policy tests: management API (parallel-safe) + enforcement.

The management-API tests use a distinct 12-digit master account id per test so
they are isolated and parallel-safe. The enforcement tests flip the global
``organizations.SCP_ENFORCEMENT`` flag via /_ministack/config and reset it in a
``finally`` block; they are registered in conftest ``_SERIAL_TESTS`` so they run
in the dedicated sequential phase (the flag is process-global while on).
"""

import json
import os
import urllib.request

import boto3
import pytest
from botocore.exceptions import ClientError

ENDPOINT = os.environ.get("MINISTACK_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"

_DENY_S3 = {"Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}


def _client(service, account, region=REGION):
    return boto3.client(service, endpoint_url=ENDPOINT, region_name=region,
                        aws_access_key_id=account, aws_secret_access_key="test")


def _org(account):
    return _client("organizations", account)


def _code(exc):
    return exc.value.response["Error"]["Code"]


def _set_enforcement(on):
    data = json.dumps({"organizations.SCP_ENFORCEMENT": bool(on)}).encode()
    req = urllib.request.Request(
        f"{ENDPOINT}/_ministack/config", data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=5)


# ===========================================================================
# Management API (parallel-safe)
# ===========================================================================

def test_scp_full_access_default_present():
    o = _org("910000000001")
    pols = o.list_policies(Filter="SERVICE_CONTROL_POLICY")["Policies"]
    fa = [p for p in pols if p["Id"] == "p-FullAWSAccess"]
    assert fa and fa[0]["AwsManaged"] is True
    assert fa[0]["Name"] == "FullAWSAccess"


def test_scp_create_and_describe():
    o = _org("910000000002")
    content = json.dumps(_DENY_S3)
    summary = o.create_policy(Name="deny-s3", Description="no s3",
                              Type="SERVICE_CONTROL_POLICY", Content=content)["Policy"]["PolicySummary"]
    pid = summary["Id"]
    assert pid.startswith("p-")
    assert summary["AwsManaged"] is False
    desc = o.describe_policy(PolicyId=pid)["Policy"]
    assert desc["PolicySummary"]["Name"] == "deny-s3"
    assert json.loads(desc["Content"])["Statement"][0]["Effect"] == "Deny"


def test_scp_create_duplicate_name():
    o = _org("910000000003")
    content = json.dumps(_DENY_S3)
    o.create_policy(Name="dup", Description="scp test", Type="SERVICE_CONTROL_POLICY", Content=content)
    with pytest.raises(ClientError) as e:
        o.create_policy(Name="dup", Description="scp test", Type="SERVICE_CONTROL_POLICY", Content=content)
    assert _code(e) == "DuplicatePolicyException"


def test_scp_create_malformed_document():
    o = _org("910000000004")
    with pytest.raises(ClientError) as e:
        o.create_policy(Name="bad", Description="scp test", Type="SERVICE_CONTROL_POLICY", Content="not json")
    assert _code(e) == "MalformedPolicyDocumentException"


def test_scp_update_custom_and_managed():
    o = _org("910000000005")
    pid = o.create_policy(Name="upd", Description="scp test", Type="SERVICE_CONTROL_POLICY",
                          Content=json.dumps(_DENY_S3))["Policy"]["PolicySummary"]["Id"]
    o.update_policy(PolicyId=pid, Description="changed")
    assert o.describe_policy(PolicyId=pid)["Policy"]["PolicySummary"]["Description"] == "changed"
    with pytest.raises(ClientError) as e:
        o.update_policy(PolicyId="p-FullAWSAccess", Description="x")
    assert _code(e) == "ConstraintViolationException"


def test_scp_delete_attached_then_detach():
    o = _org("910000000006")
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
    pid = o.create_policy(Name="del-me", Description="scp test", Type="SERVICE_CONTROL_POLICY",
                          Content=json.dumps(_DENY_S3))["Policy"]["PolicySummary"]["Id"]
    o.attach_policy(PolicyId=pid, TargetId=root)
    with pytest.raises(ClientError) as e:
        o.delete_policy(PolicyId=pid)
    assert _code(e) == "PolicyInUseException"
    with pytest.raises(ClientError) as e2:
        o.delete_policy(PolicyId="p-FullAWSAccess")
    assert _code(e2) == "ConstraintViolationException"
    o.detach_policy(PolicyId=pid, TargetId=root)
    o.delete_policy(PolicyId=pid)
    with pytest.raises(ClientError) as e3:
        o.describe_policy(PolicyId=pid)
    assert _code(e3) == "PolicyNotFoundException"


def test_scp_enable_disable_type():
    o = _org("910000000007")
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
    pt = o.list_roots()["Roots"][0]["PolicyTypes"]
    assert any(p["Type"] == "SERVICE_CONTROL_POLICY" and p["Status"] == "ENABLED" for p in pt)
    with pytest.raises(ClientError) as e:
        o.enable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
    assert _code(e) == "PolicyTypeAlreadyEnabledException"
    o.disable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
    assert not any(p["Type"] == "SERVICE_CONTROL_POLICY"
                   for p in o.list_roots()["Roots"][0]["PolicyTypes"])
    with pytest.raises(ClientError) as e2:
        o.disable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
    assert _code(e2) == "PolicyTypeNotEnabledException"


def test_scp_attach_requires_type_enabled():
    o = _org("910000000008")
    root = o.list_roots()["Roots"][0]["Id"]
    pid = o.create_policy(Name="p", Description="scp test", Type="SERVICE_CONTROL_POLICY",
                          Content=json.dumps(_DENY_S3))["Policy"]["PolicySummary"]["Id"]
    with pytest.raises(ClientError) as e:
        o.attach_policy(PolicyId=pid, TargetId=root)
    assert _code(e) == "PolicyTypeNotEnabledException"


def test_scp_attach_detach_roundtrip():
    o = _org("910000000009")
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
    pid = o.create_policy(Name="rt", Description="scp test", Type="SERVICE_CONTROL_POLICY",
                          Content=json.dumps(_DENY_S3))["Policy"]["PolicySummary"]["Id"]
    o.attach_policy(PolicyId=pid, TargetId=root)
    target_pols = {p["Id"] for p in
                   o.list_policies_for_target(TargetId=root, Filter="SERVICE_CONTROL_POLICY")["Policies"]}
    assert {pid, "p-FullAWSAccess"} <= target_pols
    targets = {t["TargetId"] for t in o.list_targets_for_policy(PolicyId=pid)["Targets"]}
    assert root in targets
    with pytest.raises(ClientError) as e:
        o.attach_policy(PolicyId=pid, TargetId=root)
    assert _code(e) == "DuplicatePolicyAttachmentException"
    o.detach_policy(PolicyId=pid, TargetId=root)
    with pytest.raises(ClientError) as e2:
        o.detach_policy(PolicyId=pid, TargetId=root)
    assert _code(e2) == "PolicyNotAttachedException"


def test_scp_detach_last_policy_blocked():
    o = _org("910000000010")
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
    # root has only FullAWSAccess attached -> detaching it is the last policy.
    with pytest.raises(ClientError) as e:
        o.detach_policy(PolicyId="p-FullAWSAccess", TargetId=root)
    assert _code(e) == "ConstraintViolationException"


def test_scp_not_found_errors():
    o = _org("910000000011")
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
    with pytest.raises(ClientError) as e:
        o.describe_policy(PolicyId="p-doesnotexist")
    assert _code(e) == "PolicyNotFoundException"
    pid = o.create_policy(Name="nf", Description="scp test", Type="SERVICE_CONTROL_POLICY",
                          Content=json.dumps(_DENY_S3))["Policy"]["PolicySummary"]["Id"]
    with pytest.raises(ClientError) as e2:
        o.attach_policy(PolicyId=pid, TargetId="r-zzzzzz")
    assert _code(e2) == "TargetNotFoundException"


def test_scp_tag_untag_list():
    o = _org("910000000012")
    pid = o.create_policy(Name="tagged", Description="scp test",
                          Type="SERVICE_CONTROL_POLICY", Content=json.dumps(_DENY_S3),
                          Tags=[{"Key": "team", "Value": "platform"}])["Policy"]["PolicySummary"]["Id"]
    # tag at creation is reflected
    tags = {t["Key"]: t["Value"] for t in o.list_tags_for_resource(ResourceId=pid)["Tags"]}
    assert tags == {"team": "platform"}
    # add more, overwrite one
    o.tag_resource(ResourceId=pid, Tags=[{"Key": "env", "Value": "dev"},
                                         {"Key": "team", "Value": "infra"}])
    tags = {t["Key"]: t["Value"] for t in o.list_tags_for_resource(ResourceId=pid)["Tags"]}
    assert tags == {"team": "infra", "env": "dev"}
    # untag
    o.untag_resource(ResourceId=pid, TagKeys=["env"])
    tags = {t["Key"]: t["Value"] for t in o.list_tags_for_resource(ResourceId=pid)["Tags"]}
    assert tags == {"team": "infra"}


def test_scp_tag_unknown_resource():
    o = _org("910000000013")
    with pytest.raises(ClientError) as e:
        o.tag_resource(ResourceId="p-doesnotexist", Tags=[{"Key": "k", "Value": "v"}])
    assert _code(e) == "InvalidInputException"


def test_scp_list_policies_pagination():
    o = _org("910000000014")
    # FullAWSAccess already exists; add 4 more -> 5 total.
    for i in range(4):
        o.create_policy(Name=f"p{i}", Description="scp test",
                        Type="SERVICE_CONTROL_POLICY", Content=json.dumps(_DENY_S3))
    seen, token, pages = [], None, 0
    while True:
        kwargs = {"Filter": "SERVICE_CONTROL_POLICY", "MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        resp = o.list_policies(**kwargs)
        seen.extend(p["Id"] for p in resp["Policies"])
        pages += 1
        token = resp.get("NextToken")
        if not token:
            break
    assert pages == 3                      # 5 policies / 2 per page -> 3 pages
    assert len(seen) == len(set(seen)) == 5
    assert "p-FullAWSAccess" in seen


# ===========================================================================
# Enforcement (serial — registered in conftest._SERIAL_TESTS)
# ===========================================================================

def _make_member(master_id):
    """Create + materialise a member account under master; return (orgs_client, root, member_id)."""
    o = _org(master_id)
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
    car = o.create_account(Email=f"member+{master_id}@ministack.local",
                           AccountName="Member")["CreateAccountStatus"]
    member = o.describe_create_account_status(
        CreateAccountRequestId=car["Id"])["CreateAccountStatus"]["AccountId"]
    return o, root, member


def test_scp_enf_blocks_member_but_exempts_management():
    _set_enforcement(True)
    try:
        o, root, member = _make_member("920000000001")
        pid = o.create_policy(Name="enf-deny-s3", Description="scp test", Type="SERVICE_CONTROL_POLICY",
                              Content=json.dumps(_DENY_S3))["Policy"]["PolicySummary"]["Id"]
        o.attach_policy(PolicyId=pid, TargetId=root)

        with pytest.raises(ClientError) as e:
            _client("s3", member).list_buckets()
        assert _code(e) == "AccessDenied"

        # The management (master) account is never restricted by SCPs.
        _client("s3", "920000000001").list_buckets()
    finally:
        _set_enforcement(False)


def test_scp_enf_default_full_access_allows():
    _set_enforcement(True)
    try:
        _o, _root, member = _make_member("920000000002")
        # Only FullAWSAccess is attached -> the member is allowed.
        _client("s3", member).list_buckets()
    finally:
        _set_enforcement(False)


def test_scp_enf_implicit_deny_allow_list():
    _set_enforcement(True)
    try:
        o, _root, member = _make_member("920000000003")
        allow_ddb = {"Version": "2012-10-17",
                     "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}]}
        pid = o.create_policy(Name="allow-ddb-only", Description="scp test", Type="SERVICE_CONTROL_POLICY",
                              Content=json.dumps(allow_ddb))["Policy"]["PolicySummary"]["Id"]
        o.attach_policy(PolicyId=pid, TargetId=member)
        # Remove the FullAWSAccess baseline from the member; now only dynamodb is allowed there.
        o.detach_policy(PolicyId="p-FullAWSAccess", TargetId=member)

        with pytest.raises(ClientError) as e:
            _client("s3", member).list_buckets()
        assert _code(e) == "AccessDenied"
        # dynamodb is still permitted at every level.
        _client("dynamodb", member).list_tables()
    finally:
        _set_enforcement(False)


def test_scp_enf_region_condition():
    _set_enforcement(True)
    try:
        o, root, member = _make_member("920000000004")
        deny_outside = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}}}]}
        pid = o.create_policy(Name="region-lock", Description="scp test", Type="SERVICE_CONTROL_POLICY",
                              Content=json.dumps(deny_outside))["Policy"]["PolicySummary"]["Id"]
        o.attach_policy(PolicyId=pid, TargetId=root)

        with pytest.raises(ClientError) as e:
            _client("s3", member, region="eu-west-1").list_buckets()
        assert _code(e) == "AccessDenied"
        # Same member, allowed region -> succeeds.
        _client("s3", member, region="us-east-1").list_buckets()
    finally:
        _set_enforcement(False)


def test_scp_enf_resource_scoped_deny_kinesis():
    _set_enforcement(True)
    try:
        o, root, member = _make_member("920000000006")
        # Deny only one specific stream; a resource-scoped SCP using the new
        # kinesis extractor. Wildcards cover the member's region/account.
        deny = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Action": "kinesis:*",
            "Resource": "arn:aws:kinesis:*:*:stream/blocked"}]}
        pid = o.create_policy(Name="deny-one-stream", Description="scp test",
                              Type="SERVICE_CONTROL_POLICY",
                              Content=json.dumps(deny))["Policy"]["PolicySummary"]["Id"]
        o.attach_policy(PolicyId=pid, TargetId=root)
        k = _client("kinesis", member)
        # the blocked stream -> denied by the resource-scoped SCP. kinesis is a
        # JSON-protocol service, so the denial surfaces as AccessDeniedException.
        with pytest.raises(ClientError) as e:
            k.describe_stream(StreamName="blocked")
        assert _code(e) == "AccessDeniedException"
        # a different stream is outside the SCP's Resource -> NOT an SCP denial
        # (it reaches the handler and fails for an unrelated reason, e.g. not-found)
        try:
            k.describe_stream(StreamName="allowed")
        except ClientError as e2:
            assert e2.response["Error"]["Code"] not in ("AccessDenied", "AccessDeniedException")
    finally:
        _set_enforcement(False)


def test_scp_enf_principal_org_paths_condition():
    _set_enforcement(True)
    try:
        o, root, member = _make_member("920000000005")
        # Every member has an aws:PrincipalOrgPaths entry starting with the org id
        # ("o-..."); deny when ForAnyValue:StringLike matches it -> proves the key
        # is populated and the set operator is wired end-to-end.
        deny = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": ["o-*"]}}}]}
        pid = o.create_policy(Name="org-path-deny", Description="scp test",
                              Type="SERVICE_CONTROL_POLICY",
                              Content=json.dumps(deny))["Policy"]["PolicySummary"]["Id"]
        o.attach_policy(PolicyId=pid, TargetId=root)
        with pytest.raises(ClientError) as e:
            _client("s3", member).list_buckets()
        assert _code(e) == "AccessDenied"
    finally:
        _set_enforcement(False)
