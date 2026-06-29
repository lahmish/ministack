"""Pure unit tests for the SCP evaluation engine (ministack.core.scp).

No running server required — these import the engine directly.
"""

from ministack.core import scp

FULL = {"Effect": "Allow", "Action": "*", "Resource": "*"}


def _p(*statements):
    return scp.parse_policy({"Version": "2012-10-17", "Statement": list(statements)})


# --- action matching -------------------------------------------------------

def test_action_matches_wildcard_service():
    assert scp.action_matches(["s3:*"], "s3:PutObject")
    assert not scp.action_matches(["s3:*"], "ec2:RunInstances")


def test_action_matches_bare_star():
    assert scp.action_matches(["*"], "anything:Goes")


def test_action_matches_case_insensitive():
    assert scp.action_matches(["S3:putobject"], "s3:PutObject")


def test_action_matches_prefix_glob():
    assert scp.action_matches(["iam:Delete*"], "iam:DeleteRole")
    assert not scp.action_matches(["iam:Delete*"], "iam:GetRole")


# --- resource matching -----------------------------------------------------

def test_resource_matches_exact_and_wildcard():
    assert scp.resource_matches(["arn:aws:s3:::b/*"], "arn:aws:s3:::b/key")
    assert not scp.resource_matches(["arn:aws:s3:::b/*"], "arn:aws:s3:::other/key")


def test_resource_unknown_allow_specific_matches():
    # A specific-resource Allow with an unknown ARN is treated as matching, so it
    # does not cause a false implicit-deny.
    st = _p({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"})[0]
    assert scp.statement_applies(st, "s3:PutObject", None, {})


def test_resource_unknown_deny_specific_skipped():
    # A specific-resource Deny with an unknown ARN is treated as non-matching, so
    # it does not over-deny unrelated calls.
    st = _p({"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"})[0]
    assert not scp.statement_applies(st, "s3:PutObject", None, {})


def test_resource_unknown_star_matches():
    st = _p({"Effect": "Deny", "Action": "s3:*", "Resource": "*"})[0]
    assert scp.statement_applies(st, "s3:PutObject", None, {})


def test_resource_known_arn_full_match():
    deny = _p({"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::secret/*"})[0]
    assert scp.statement_applies(deny, "s3:GetObject", "arn:aws:s3:::secret/k", {})
    assert not scp.statement_applies(deny, "s3:GetObject", "arn:aws:s3:::public/k", {})


# --- conditions ------------------------------------------------------------

def _cond(operator, predicates, effect="Deny"):
    return _p({"Effect": effect, "Action": "*", "Resource": "*",
               "Condition": {operator: predicates}})[0]


def test_condition_string_equals():
    st = _cond("StringEquals", {"aws:RequestedRegion": "us-east-1"})
    assert scp.statement_applies(st, "s3:x", None, {"aws:RequestedRegion": "us-east-1"})
    assert not scp.statement_applies(st, "s3:x", None, {"aws:RequestedRegion": "eu-west-1"})


def test_condition_string_not_equals_multivalue():
    st = _cond("StringNotEquals", {"aws:RequestedRegion": ["us-east-1", "us-west-2"]})
    # Not in the allowed set -> condition true.
    assert scp.statement_applies(st, "s3:x", None, {"aws:RequestedRegion": "eu-west-1"})
    # In the allowed set -> condition false (negated op is all-values).
    assert not scp.statement_applies(st, "s3:x", None, {"aws:RequestedRegion": "us-west-2"})


def test_condition_string_like():
    st = _cond("StringLike", {"aws:PrincipalArn": "arn:aws:iam::*:role/Admin*"})
    assert scp.statement_applies(st, "s3:x", None,
                                 {"aws:PrincipalArn": "arn:aws:iam::1:role/AdminX"})
    assert not scp.statement_applies(st, "s3:x", None,
                                     {"aws:PrincipalArn": "arn:aws:iam::1:role/User"})


def test_condition_missing_key_does_not_apply():
    # Absent key: StringEquals -> False, so a Deny gated on it silently no-ops.
    st = _cond("StringEquals", {"aws:username": "bob"})
    assert not scp.statement_applies(st, "s3:x", None, {})


def test_condition_if_exists_missing_key_true():
    st = _cond("StringEqualsIfExists", {"aws:username": "bob"})
    assert scp.statement_applies(st, "s3:x", None, {})


def test_condition_null_absent_and_present():
    absent = _cond("Null", {"aws:username": "true"})
    assert scp.statement_applies(absent, "s3:x", None, {})
    assert not scp.statement_applies(absent, "s3:x", None, {"aws:username": "x"})
    present = _cond("Null", {"aws:username": "false"})
    assert scp.statement_applies(present, "s3:x", None, {"aws:username": "x"})
    assert not scp.statement_applies(present, "s3:x", None, {})


def test_condition_bool():
    st = _cond("Bool", {"aws:SecureTransport": "false"})
    assert scp.statement_applies(st, "s3:x", None, {"aws:SecureTransport": "false"})
    assert not scp.statement_applies(st, "s3:x", None, {"aws:SecureTransport": "true"})


def test_condition_ip_address():
    st = _cond("NotIpAddress", {"aws:SourceIp": "10.0.0.0/8"})
    assert scp.statement_applies(st, "s3:x", None, {"aws:SourceIp": "192.168.1.1"})
    assert not scp.statement_applies(st, "s3:x", None, {"aws:SourceIp": "10.1.2.3"})


def test_condition_numeric_and_date():
    num = _cond("NumericLessThan", {"k": "100"})
    assert scp.statement_applies(num, "s3:x", None, {"k": "50"})
    assert not scp.statement_applies(num, "s3:x", None, {"k": "150"})
    dt = _cond("DateGreaterThan", {"aws:CurrentTime": "2020-01-01T00:00:00Z"})
    assert scp.statement_applies(dt, "s3:x", None, {"aws:CurrentTime": "2026-01-01T00:00:00Z"})
    assert not scp.statement_applies(dt, "s3:x", None, {"aws:CurrentTime": "2019-01-01T00:00:00Z"})


def test_condition_unknown_operator_is_safe_nonmatch():
    st = _cond("MadeUpOperator", {"k": "v"})
    assert not scp.statement_applies(st, "s3:x", None, {"k": "v"})


def test_condition_for_any_value():
    st = _cond("ForAnyValue:StringEquals", {"aws:PrincipalOrgPaths": ["o-x/r-y/111/"]})
    # at least one of the request's values matches
    assert scp.statement_applies(st, "s3:x", None,
                                 {"aws:PrincipalOrgPaths": ["o-x/r-y/ou-z/999/", "o-x/r-y/111/"]})
    # none match
    assert not scp.statement_applies(st, "s3:x", None,
                                     {"aws:PrincipalOrgPaths": ["o-x/r-y/ou-z/999/"]})
    # absent key -> ForAnyValue is false
    assert not scp.statement_applies(st, "s3:x", None, {})


def test_condition_for_all_values():
    st = _cond("ForAllValues:StringEquals", {"k": ["a", "b"]})
    assert scp.statement_applies(st, "s3:x", None, {"k": ["a", "b"]})       # every member allowed
    assert scp.statement_applies(st, "s3:x", None, {"k": ["a"]})            # subset still all-allowed
    assert not scp.statement_applies(st, "s3:x", None, {"k": ["a", "c"]})   # one member not allowed
    assert scp.statement_applies(st, "s3:x", None, {})                      # absent -> vacuously true


# --- not-action ------------------------------------------------------------

def test_not_action_inverts():
    st = _p({"Effect": "Deny", "NotAction": "s3:*", "Resource": "*"})[0]
    assert scp.statement_applies(st, "ec2:RunInstances", None, {})
    assert not scp.statement_applies(st, "s3:PutObject", None, {})


# --- evaluate_scps truth tables --------------------------------------------

def test_eval_explicit_deny_wins():
    full = _p(FULL)
    deny = _p({"Effect": "Deny", "Action": "s3:*", "Resource": "*"})
    assert scp.evaluate_scps([full, full + deny], "s3:PutObject", None, {}) == "deny"


def test_eval_all_levels_allow():
    full = _p(FULL)
    assert scp.evaluate_scps([full, full], "s3:PutObject", None, {}) == "allow"


def test_eval_implicit_deny_when_level_lacks_allow():
    full = _p(FULL)
    ddb = _p({"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"})
    # Account level (first) only allows dynamodb -> s3 is implicitly denied.
    assert scp.evaluate_scps([ddb, full], "s3:GetObject", None, {}) == "deny"
    assert scp.evaluate_scps([ddb, full], "dynamodb:Query", None, {}) == "allow"


def test_eval_empty_node_is_implicit_deny():
    full = _p(FULL)
    assert scp.evaluate_scps([[], full], "s3:x", None, {}) == "deny"


def test_eval_deny_beats_allow_same_level():
    full = _p(FULL)
    deny = _p({"Effect": "Deny", "Action": "ec2:*", "Resource": "*"})
    assert scp.evaluate_scps([full + deny], "ec2:RunInstances", None, {}) == "deny"
    assert scp.evaluate_scps([full + deny], "s3:PutObject", None, {}) == "allow"
