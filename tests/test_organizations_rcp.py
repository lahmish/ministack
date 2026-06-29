"""Resource Control Policy tests: management API (parallel-safe) + enforcement.

RCPs reuse the SCP policy machinery (now type-generalized). Management tests use a
distinct master account id per test. Enforcement tests flip the global
`organizations.RCP_ENFORCEMENT` flag via /_ministack/config and reset it in a
`finally`; they are registered in conftest `_SERIAL_TESTS`.
"""

import json
import os
import urllib.request

import boto3
import pytest
from botocore.exceptions import ClientError

ENDPOINT = os.environ.get("MINISTACK_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"
_SCP = "SERVICE_CONTROL_POLICY"
_RCP = "RESOURCE_CONTROL_POLICY"


def _client(service, account, region=REGION):
    return boto3.client(service, endpoint_url=ENDPOINT, region_name=region,
                        aws_access_key_id=account, aws_secret_access_key="test")


def _org(account):
    return _client("organizations", account)


def _code(exc):
    return exc.value.response["Error"]["Code"]


def _rcp_doc(action="s3:*", **extra):
    stmt = {"Effect": "Deny", "Principal": "*", "Action": action, "Resource": "*"}
    stmt.update(extra)
    return json.dumps({"Version": "2012-10-17", "Statement": [stmt]})


def _set_flag(key, on):
    data = json.dumps({key: bool(on)}).encode()
    req = urllib.request.Request(f"{ENDPOINT}/_ministack/config", data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=5)


# ===========================================================================
# Management API (parallel-safe)
# ===========================================================================

def test_rcp_full_access_default_present():
    o = _org("930000000001")
    fa = [p for p in o.list_policies(Filter=_RCP)["Policies"] if p["Id"] == "p-RCPFullAWSAccess"]
    assert fa and fa[0]["AwsManaged"] is True and fa[0]["Type"] == _RCP


def test_rcp_list_filtered_by_type():
    o = _org("930000000002")
    scp_ids = {p["Id"] for p in o.list_policies(Filter=_SCP)["Policies"]}
    rcp_ids = {p["Id"] for p in o.list_policies(Filter=_RCP)["Policies"]}
    assert "p-FullAWSAccess" in scp_ids and "p-RCPFullAWSAccess" not in scp_ids
    assert "p-RCPFullAWSAccess" in rcp_ids and "p-FullAWSAccess" not in rcp_ids


def test_rcp_create_and_describe():
    o = _org("930000000003")
    pid = o.create_policy(Name="deny-s3-rcp", Description="d", Type=_RCP,
                          Content=_rcp_doc())["Policy"]["PolicySummary"]["Id"]
    desc = o.describe_policy(PolicyId=pid)["Policy"]
    assert desc["PolicySummary"]["Type"] == _RCP
    assert json.loads(desc["Content"])["Statement"][0]["Principal"] == "*"


def test_rcp_attach_requires_type_enabled():
    o = _org("930000000004")
    root = o.list_roots()["Roots"][0]["Id"]
    pid = o.create_policy(Name="r", Description="d", Type=_RCP,
                          Content=_rcp_doc())["Policy"]["PolicySummary"]["Id"]
    with pytest.raises(ClientError) as e:
        o.attach_policy(PolicyId=pid, TargetId=root)
    assert _code(e) == "PolicyTypeNotEnabledException"


def test_rcp_enable_attach_list_roundtrip():
    o = _org("930000000005")
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType=_RCP)
    pid = o.create_policy(Name="rt-rcp", Description="d", Type=_RCP,
                          Content=_rcp_doc())["Policy"]["PolicySummary"]["Id"]
    o.attach_policy(PolicyId=pid, TargetId=root)
    rcp_on = {p["Id"] for p in o.list_policies_for_target(TargetId=root, Filter=_RCP)["Policies"]}
    assert {pid, "p-RCPFullAWSAccess"} <= rcp_on
    # the SCP filter on the same target shows only SCPs (not the RCP we attached)
    scp_on = {p["Id"] for p in o.list_policies_for_target(TargetId=root, Filter=_SCP)["Policies"]}
    assert "p-FullAWSAccess" in scp_on and pid not in scp_on


def test_rcp_detach_last_blocked():
    o = _org("930000000006")
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType=_RCP)
    with pytest.raises(ClientError) as e:
        o.detach_policy(PolicyId="p-RCPFullAWSAccess", TargetId=root)
    assert _code(e) == "ConstraintViolationException"


def test_scp_and_rcp_coexist_on_target():
    o = _org("930000000007")
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType=_SCP)
    o.enable_policy_type(RootId=root, PolicyType=_RCP)
    scp_pid = o.create_policy(Name="co-scp", Description="d", Type=_SCP,
                              Content=json.dumps({"Statement": [{"Effect": "Deny", "Action": "s3:*",
                                                                 "Resource": "*"}]}))["Policy"]["PolicySummary"]["Id"]
    rcp_pid = o.create_policy(Name="co-rcp", Description="d", Type=_RCP,
                              Content=_rcp_doc())["Policy"]["PolicySummary"]["Id"]
    o.attach_policy(PolicyId=scp_pid, TargetId=root)
    o.attach_policy(PolicyId=rcp_pid, TargetId=root)
    scp_ids = {p["Id"] for p in o.list_policies_for_target(TargetId=root, Filter=_SCP)["Policies"]}
    rcp_ids = {p["Id"] for p in o.list_policies_for_target(TargetId=root, Filter=_RCP)["Policies"]}
    assert scp_pid in scp_ids and rcp_pid not in scp_ids
    assert rcp_pid in rcp_ids and scp_pid not in rcp_ids


def test_rcp_same_name_as_scp_allowed():
    o = _org("930000000008")
    o.create_policy(Name="dual", Description="d", Type=_SCP,
                    Content=json.dumps({"Statement": [{"Effect": "Deny", "Action": "s3:*",
                                                       "Resource": "*"}]}))
    # same name, different type -> allowed (uniqueness is per type)
    o.create_policy(Name="dual", Description="d", Type=_RCP, Content=_rcp_doc())


def test_rcp_full_access_not_detachable():
    o = _org("930000000009")
    root = o.list_roots()["Roots"][0]["Id"]
    o.enable_policy_type(RootId=root, PolicyType=_RCP)
    # attach a second RCP so RCPFullAWSAccess is not the "last" policy of its type
    pid = o.create_policy(Name="extra-rcp", Description="d", Type=_RCP,
                          Content=_rcp_doc())["Policy"]["PolicySummary"]["Id"]
    o.attach_policy(PolicyId=pid, TargetId=root)
    # RCPFullAWSAccess can never be detached (real-AWS rule), even with another RCP present
    with pytest.raises(ClientError) as e:
        o.detach_policy(PolicyId="p-RCPFullAWSAccess", TargetId=root)
    assert _code(e) == "ConstraintViolationException"


@pytest.mark.parametrize("stmt, label", [
    ({"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "*"}, "allow-effect"),
    ({"Effect": "Deny", "Principal": {"AWS": "111122223333"}, "Action": "s3:*", "Resource": "*"}, "non-star-principal"),
    ({"Effect": "Deny", "Principal": "*", "NotAction": "s3:*", "Resource": "*"}, "notaction"),
    ({"Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*"}, "bare-star-action"),
])
def test_rcp_rejects_invalid_documents(stmt, label):
    # Real AWS: customer RCPs must be Deny, Principal must be "*", no NotPrincipal/
    # NotAction, and Action must be service-scoped.
    o = _org("930000000020")
    content = json.dumps({"Version": "2012-10-17", "Statement": [stmt]})
    with pytest.raises(ClientError) as e:
        o.create_policy(Name=f"bad-{label}", Description="d", Type=_RCP, Content=content)
    assert _code(e) == "MalformedPolicyDocumentException"


# ===========================================================================
# Enforcement (serial — registered in conftest._SERIAL_TESTS)
# ===========================================================================

def _org_with_member(master):
    o = _org(master)
    root = o.list_roots()["Roots"][0]["Id"]
    org_id = o.describe_organization()["Organization"]["Id"]
    o.enable_policy_type(RootId=root, PolicyType=_RCP)
    car = o.create_account(Email=f"m+{master}@x.local", AccountName="Member")["CreateAccountStatus"]
    member = o.describe_create_account_status(
        CreateAccountRequestId=car["Id"])["CreateAccountStatus"]["AccountId"]
    return o, root, org_id, member


def test_rcp_enf_blocks_out_of_org_principal_on_kms():
    _set_flag("organizations.RCP_ENFORCEMENT", True)
    try:
        o, root, org_id, member = _org_with_member("940000000001")
        # Data-perimeter RCP: deny KMS access to this org's resources from outside the org.
        rcp = _rcp_doc(action="kms:*", Condition={"StringNotEquals": {"aws:PrincipalOrgID": org_id}})
        pid = o.create_policy(Name="kms-perimeter", Description="d", Type=_RCP,
                              Content=rcp)["Policy"]["PolicySummary"]["Id"]
        o.attach_policy(PolicyId=pid, TargetId=root)
        key_arn = f"arn:aws:kms:{REGION}:{member}:key/11111111-2222-3333-4444-555555555555"

        # out-of-org caller -> denied by the RCP
        with pytest.raises(ClientError) as e:
            _client("kms", "980000000999").describe_key(KeyId=key_arn)
        assert _code(e) == "AccessDeniedException"

        # in-org caller (the member itself) -> not an RCP denial (reaches the handler)
        try:
            _client("kms", member).describe_key(KeyId=key_arn)
        except ClientError as e2:
            assert e2.response["Error"]["Code"] != "AccessDeniedException"
    finally:
        _set_flag("organizations.RCP_ENFORCEMENT", False)


def test_rcp_enf_management_account_resource_exempt():
    _set_flag("organizations.RCP_ENFORCEMENT", True)
    try:
        master = "940000000002"
        o, root, org_id, _member = _org_with_member(master)
        rcp = _rcp_doc(action="kms:*", Condition={"StringNotEquals": {"aws:PrincipalOrgID": org_id}})
        pid = o.create_policy(Name="kms-perimeter2", Description="d", Type=_RCP,
                              Content=rcp)["Policy"]["PolicySummary"]["Id"]
        o.attach_policy(PolicyId=pid, TargetId=root)
        # resource owned by the MANAGEMENT account -> exempt, even for an outsider
        mgmt_key = f"arn:aws:kms:{REGION}:{master}:key/99999999-8888-7777-6666-555555555555"
        try:
            _client("kms", "980000000998").describe_key(KeyId=mgmt_key)
        except ClientError as e:
            assert e.response["Error"]["Code"] != "AccessDeniedException"
    finally:
        _set_flag("organizations.RCP_ENFORCEMENT", False)


def test_rcp_enf_applies_to_dynamodb():
    # DynamoDB is one of the services AWS added to RCP support beyond the launch five;
    # confirm RCP enforcement actually fires for it.
    _set_flag("organizations.RCP_ENFORCEMENT", True)
    try:
        o, root, _org_id, member = _org_with_member("940000000003")
        rcp = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Principal": "*", "Action": "dynamodb:*", "Resource": "*"}]})
        pid = o.create_policy(Name="deny-ddb-rcp", Description="d", Type=_RCP,
                              Content=rcp)["Policy"]["PolicySummary"]["Id"]
        o.attach_policy(PolicyId=pid, TargetId=root)
        with pytest.raises(ClientError) as e:
            _client("dynamodb", member).describe_table(TableName="anytable")
        assert _code(e) == "AccessDeniedException"
    finally:
        _set_flag("organizations.RCP_ENFORCEMENT", False)
