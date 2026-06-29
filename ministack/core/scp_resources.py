"""
Best-effort request -> resource-ARN extraction for SCP per-resource matching.

The SCP enforcement hook knows the service, operation, account and region at
dispatch time but NOT the specific resource being acted on — that is parsed
inside each service handler. This module recovers the target ARN for a
representative set of services (reusing the same parsing the CloudTrail
``_ct_resources`` helper does) so ``Resource``-scoped SCP statements can be
evaluated.

Covered services: s3, dynamodb, sqs, sns, lambda, secretsmanager, kinesis,
firehose, ecr, ssm, kms, logs, states (Step Functions).

Coverage is **partial by design**: any service without an extractor, or any
extraction that fails, returns ``None``. The engine's unknown-resource policy
then applies (``Resource:"*"`` statements still match; specific-resource Denies
are skipped to avoid over-denying). ec2/iam/cloudformation are intentionally
deferred — their ARNs are operation-specific or need ids absent from the request.
"""

import json
import logging
from urllib.parse import parse_qs

from ministack.core.responses import get_account_id, get_region

logger = logging.getLogger("scp")

_logged_gaps: set = set()


def _json_body(body):
    try:
        return json.loads(body) if body else {}
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}


def _form_body(body):
    try:
        raw = parse_qs(body.decode("utf-8", errors="replace"))
        return {k: (v[0] if v else "") for k, v in raw.items()}
    except Exception:
        return {}


def _params(headers, body, query_params):
    """Flatten query params and merge in body params (JSON or form-encoded)."""
    params = {k: (v[0] if isinstance(v, list) else v)
              for k, v in (query_params or {}).items()}
    ct = (headers or {}).get("content-type", "")
    if "json" in ct:
        params = {**params, **_json_body(body)}
    elif "form" in ct or "urlencoded" in ct:
        params = {**params, **_form_body(body)}
    elif body:
        params = {**params, **(_json_body(body) or _form_body(body))}
    return params


# --- per-service extractors -------------------------------------------------

def _arn_s3(method, path, headers, body, query_params, action):
    parts = [p for p in path.split("/") if p]
    if not parts:
        return None  # ListBuckets etc. — account-level, no specific resource
    bucket = parts[0]
    if len(parts) >= 2:
        return f"arn:aws:s3:::{bucket}/{'/'.join(parts[1:])}"
    return f"arn:aws:s3:::{bucket}"


def _arn_dynamodb(method, path, headers, body, query_params, action):
    table = _params(headers, body, query_params).get("TableName")
    if not table:
        return None
    return f"arn:aws:dynamodb:{get_region()}:{get_account_id()}:table/{table}"


def _arn_sqs(method, path, headers, body, query_params, action):
    p = _params(headers, body, query_params)
    qurl = p.get("QueueUrl")
    if qurl:
        name = str(qurl).rstrip("/").split("/")[-1]
    else:
        parts = [seg for seg in path.split("/") if seg]
        name = parts[-1] if len(parts) >= 2 else None
    if not name:
        return None
    return f"arn:aws:sqs:{get_region()}:{get_account_id()}:{name}"


def _arn_sns(method, path, headers, body, query_params, action):
    p = _params(headers, body, query_params)
    arn = p.get("TopicArn") or p.get("TargetArn") or p.get("ResourceArn")
    return str(arn) if arn and str(arn).startswith("arn:") else None


def _arn_lambda(method, path, headers, body, query_params, action):
    fn = _params(headers, body, query_params).get("FunctionName")
    if not fn:
        parts = [seg for seg in path.split("/") if seg]
        if "functions" in parts:
            rest = parts[parts.index("functions") + 1:]
            fn = rest[0] if rest else None
    if not fn:
        return None
    if str(fn).startswith("arn:"):
        return str(fn)
    return f"arn:aws:lambda:{get_region()}:{get_account_id()}:function:{fn}"


def _arn_secrets(method, path, headers, body, query_params, action):
    p = _params(headers, body, query_params)
    sid = p.get("SecretId") or p.get("Name") or p.get("ARN")
    if not sid:
        return None
    if str(sid).startswith("arn:"):
        return str(sid)
    return f"arn:aws:secretsmanager:{get_region()}:{get_account_id()}:secret:{sid}"


def _arn_kinesis(method, path, headers, body, query_params, action):
    p = _params(headers, body, query_params)
    arn = p.get("StreamARN")
    if arn and str(arn).startswith("arn:"):
        return str(arn)
    name = p.get("StreamName")
    if not name:
        return None
    return f"arn:aws:kinesis:{get_region()}:{get_account_id()}:stream/{name}"


def _arn_firehose(method, path, headers, body, query_params, action):
    name = _params(headers, body, query_params).get("DeliveryStreamName")
    if not name:
        return None
    return f"arn:aws:firehose:{get_region()}:{get_account_id()}:deliverystream/{name}"


def _arn_ecr(method, path, headers, body, query_params, action):
    name = _params(headers, body, query_params).get("repositoryName")
    if not name:
        return None
    return f"arn:aws:ecr:{get_region()}:{get_account_id()}:repository/{name}"


def _arn_ssm(method, path, headers, body, query_params, action):
    name = _params(headers, body, query_params).get("Name")
    if not name:
        return None
    # Parameter names may be hierarchical and lead with '/'; the 'parameter/'
    # qualifier already supplies the separator.
    name = str(name).lstrip("/")
    rtype = "document" if "document" in action.lower() else "parameter"
    return f"arn:aws:ssm:{get_region()}:{get_account_id()}:{rtype}/{name}"


def _arn_kms(method, path, headers, body, query_params, action):
    p = _params(headers, body, query_params)
    kid = p.get("KeyId") or p.get("TargetKeyId") or p.get("AliasName")
    if not kid:
        return None
    kid = str(kid)
    if kid.startswith("arn:"):
        return kid
    if kid.startswith("alias/"):
        return f"arn:aws:kms:{get_region()}:{get_account_id()}:{kid}"
    return f"arn:aws:kms:{get_region()}:{get_account_id()}:key/{kid}"


def _arn_logs(method, path, headers, body, query_params, action):
    name = _params(headers, body, query_params).get("logGroupName")
    if not name:
        return None
    # log-group ARNs end with ':*' to denote the group and its streams.
    return f"arn:aws:logs:{get_region()}:{get_account_id()}:log-group:{name}:*"


def _arn_states(method, path, headers, body, query_params, action):
    p = _params(headers, body, query_params)
    arn = p.get("stateMachineArn") or p.get("activityArn") or p.get("executionArn")
    if arn and str(arn).startswith("arn:"):
        return str(arn)
    name = p.get("name")
    if not name:
        return None
    kind = "activity" if "activity" in action.lower() else "stateMachine"
    return f"arn:aws:states:{get_region()}:{get_account_id()}:{kind}:{name}"


_EXTRACTORS = {
    "s3": _arn_s3,
    "dynamodb": _arn_dynamodb,
    "sqs": _arn_sqs,
    "sns": _arn_sns,
    "lambda": _arn_lambda,
    "secretsmanager": _arn_secrets,
    "kinesis": _arn_kinesis,
    "firehose": _arn_firehose,
    "ecr": _arn_ecr,
    "ssm": _arn_ssm,
    "kms": _arn_kms,
    "logs": _arn_logs,
    "states": _arn_states,
}


def account_from_arn(arn):
    """Return the account-id field (segment 4) of an ARN, or None when absent.

    S3 ARNs (`arn:aws:s3:::bucket/key`) carry no account, so this returns None
    for them — RCP evaluation then falls back to the caller's account."""
    if not arn or not isinstance(arn, str) or not arn.startswith("arn:"):
        return None
    parts = arn.split(":")
    if len(parts) < 5:
        return None
    return parts[4] or None


def extract_resource_arn(service, method, path, headers, body, query_params, action):
    """Return the target resource ARN, or ``None`` when it cannot be determined."""
    fn = _EXTRACTORS.get(service)
    if fn is None:
        if service not in _logged_gaps:
            _logged_gaps.add(service)
            logger.debug("scp: no resource extractor for %s; matching on '*' only", service)
        return None
    try:
        return fn(method, path, headers, body, query_params, action)
    except Exception:
        return None
