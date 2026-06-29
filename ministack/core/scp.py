"""
Service Control Policy (SCP) evaluation engine.

Pure logic — NO service imports, no module-level state — so it stays trivially
unit-testable and free of circular imports. ``ministack.services.organizations``
calls :func:`parse_policy` + :func:`evaluate_scps`; the enforcement hook in
``app.py`` supplies the request context.

SCP semantics modelled here (matching real AWS):

1. An explicit ``Deny`` that applies anywhere in the root -> OU -> account chain
   wins immediately.
2. Otherwise the action must be ``Allow``-ed at *every* level of the chain (each
   level is the union of the SCPs attached to that node); a level with no
   applying ``Allow`` is an implicit deny.
3. The AWS-managed ``p-FullAWSAccess`` policy (``Allow *`` on ``*``) is the
   baseline ``Allow`` that makes step 2 pass when no allow-listing SCP is used.

Limitations are documented in the plan: SCPs are evaluated as the permission
ceiling only (IAM is not modelled), per-resource matching is best-effort when
the request's resource ARN is unknown, and condition keys that cannot be
populated from the request are treated as absent.
"""

import fnmatch
import ipaddress
import json
from datetime import datetime, timezone

_IF_EXISTS = "IfExists"


# ---------------------------------------------------------------------------
# Policy parsing
# ---------------------------------------------------------------------------

def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def parse_policy(document):
    """Normalise a policy document (JSON string or dict) into a list of statements.

    Each normalised statement is a dict with keys ``Effect``, ``Action``,
    ``NotAction``, ``Resource``, ``NotResource`` (lists, or ``None`` when the
    element is absent) and ``Condition`` (dict).
    """
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (json.JSONDecodeError, TypeError, ValueError):
            return []
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    out = []
    for st in statements:
        if not isinstance(st, dict):
            continue
        out.append({
            "Effect": st.get("Effect", "Deny"),
            "Action": _as_list(st.get("Action")) if "Action" in st else None,
            "NotAction": _as_list(st.get("NotAction")) if "NotAction" in st else None,
            "Resource": _as_list(st.get("Resource")) if "Resource" in st else None,
            "NotResource": _as_list(st.get("NotResource")) if "NotResource" in st else None,
            "Condition": st.get("Condition") if isinstance(st.get("Condition"), dict) else {},
        })
    return out


# ---------------------------------------------------------------------------
# Action / resource matching
# ---------------------------------------------------------------------------

def action_matches(patterns, action):
    """Case-insensitive wildcard match of ``service:Operation`` (and bare ``*``)."""
    a = action.lower()
    return any(fnmatch.fnmatchcase(a, p.lower()) for p in patterns)


def resource_matches(patterns, resource_arn):
    """ARN wildcard match (``*`` / ``?``). ``resource_arn`` must be a string."""
    return any(fnmatch.fnmatchcase(resource_arn, p) for p in patterns)


def _action_side(stmt, action):
    if stmt["NotAction"] is not None:
        return not action_matches(stmt["NotAction"], action)
    if stmt["Action"] is not None:
        return action_matches(stmt["Action"], action)
    return False


def _resource_side(stmt, resource_arn, effect):
    """Resource matching with best-effort handling when the ARN is unknown (None).

    When the ARN is known we do full wildcard matching. When it is None we cannot
    know the target, so: a ``*`` pattern always matches; a *specific*-resource
    Allow is treated as matching (avoids false implicit-denies) and a
    *specific*-resource Deny is treated as non-matching (avoids over-denying).
    """
    patterns = stmt["Resource"]
    not_patterns = stmt["NotResource"]
    if patterns is None and not_patterns is None:
        return True  # SCP statements default to all resources
    if resource_arn is None:
        if patterns is not None and any(p == "*" for p in patterns):
            return True
        return effect == "Allow"
    if not_patterns is not None:
        return not resource_matches(not_patterns, resource_arn)
    return resource_matches(patterns, resource_arn)


def statement_applies(stmt, action, resource_arn, ctx):
    if not _action_side(stmt, action):
        return False
    if not _resource_side(stmt, resource_arn, stmt["Effect"]):
        return False
    return evaluate_condition(stmt["Condition"], ctx)


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

def _num(x):
    return float(x)


def _bool(x):
    return str(x).lower() in ("true", "1")


def _ip_in(addr, network):
    return ipaddress.ip_address(str(addr).strip()) in ipaddress.ip_network(
        str(network).strip(), strict=False)


def _date(x):
    s = str(x).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.fromtimestamp(float(s), tz=timezone.utc)


# Positive base operators: (context_value, policy_value) -> bool.
_POSITIVE = {
    "StringEquals": lambda c, v: str(c) == str(v),
    "StringEqualsIgnoreCase": lambda c, v: str(c).lower() == str(v).lower(),
    "StringLike": lambda c, v: fnmatch.fnmatchcase(str(c), str(v)),
    "NumericEquals": lambda c, v: _num(c) == _num(v),
    "NumericLessThan": lambda c, v: _num(c) < _num(v),
    "NumericLessThanEquals": lambda c, v: _num(c) <= _num(v),
    "NumericGreaterThan": lambda c, v: _num(c) > _num(v),
    "NumericGreaterThanEquals": lambda c, v: _num(c) >= _num(v),
    "DateEquals": lambda c, v: _date(c) == _date(v),
    "DateLessThan": lambda c, v: _date(c) < _date(v),
    "DateLessThanEquals": lambda c, v: _date(c) <= _date(v),
    "DateGreaterThan": lambda c, v: _date(c) > _date(v),
    "DateGreaterThanEquals": lambda c, v: _date(c) >= _date(v),
    "Bool": lambda c, v: _bool(c) == _bool(v),
    "IpAddress": _ip_in,
    # ArnEquals and ArnLike both allow wildcards in real AWS — treat identically.
    "ArnEquals": lambda c, v: fnmatch.fnmatchcase(str(c), str(v)),
    "ArnLike": lambda c, v: fnmatch.fnmatchcase(str(c), str(v)),
}

# Negated operators map onto their positive counterpart (inverted, all-values).
_NEGATED = {
    "StringNotEquals": "StringEquals",
    "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
    "StringNotLike": "StringLike",
    "NumericNotEquals": "NumericEquals",
    "DateNotEquals": "DateEquals",
    "ArnNotEquals": "ArnEquals",
    "ArnNotLike": "ArnLike",
    "NotIpAddress": "IpAddress",
}


def _safe(fn, cv, v):
    try:
        return fn(cv, v)
    except (ValueError, TypeError):
        return False


def _key_matches(operator, key, values, ctx):
    values = values if isinstance(values, list) else [values]

    # Set-operator prefixes evaluate over the request's multivalued context key:
    # ForAnyValue -> at least one member matches; ForAllValues -> every member
    # matches (vacuously true when the key is absent/empty).
    set_op = None
    if operator.startswith("ForAnyValue:"):
        set_op, operator = "any", operator[len("ForAnyValue:"):]
    elif operator.startswith("ForAllValues:"):
        set_op, operator = "all", operator[len("ForAllValues:"):]

    # Null: presence test, independent of the value type. Null:true matches when
    # the key is ABSENT; Null:false matches when the key is PRESENT.
    if operator == "Null":
        present = key in ctx
        for v in values:
            want_absent = str(v).lower() in ("true", "1")
            if want_absent != present:
                return True
        return False

    if_exists = operator.endswith(_IF_EXISTS)
    base = operator[: -len(_IF_EXISTS)] if if_exists else operator

    negated = base in _NEGATED
    fn = _POSITIVE.get(_NEGATED[base] if negated else base)
    if fn is None:
        # Unsupported / unknown operator: safe non-match (neither grants nor denies).
        return False

    if set_op is not None:
        # Set operators use the positive comparison; negated bases are not
        # supported under a set prefix -> safe non-match.
        if negated:
            return False
        raw = ctx.get(key)
        ctx_values = [] if raw is None else (raw if isinstance(raw, list) else [raw])
        if set_op == "all":
            return all(any(_safe(fn, cv, v) for v in values) for cv in ctx_values)
        return any(_safe(fn, cv, v) for cv in ctx_values for v in values)

    if key not in ctx:
        # Missing context key: IfExists -> True, otherwise the statement does not
        # apply (a Deny gated on an unknowable key silently no-ops).
        return if_exists

    ctx_values = ctx[key] if isinstance(ctx[key], list) else [ctx[key]]
    if negated:
        # Matches only if NO (context, policy) pair is a positive match.
        return not any(_safe(fn, cv, v) for cv in ctx_values for v in values)
    return any(_safe(fn, cv, v) for cv in ctx_values for v in values)


def evaluate_condition(condition, ctx):
    """AND across operator blocks, AND across keys, OR across a key's value list
    (negated operators invert to all-values). Empty condition -> True."""
    if not condition:
        return True
    if not isinstance(condition, dict):
        return False
    for operator, predicates in condition.items():
        if not isinstance(predicates, dict):
            return False
        for key, values in predicates.items():
            if not _key_matches(operator, key, values, ctx):
                return False
    return True


# ---------------------------------------------------------------------------
# SCP decision
# ---------------------------------------------------------------------------

def evaluate_scps(node_statements, action, resource_arn, ctx):
    """Return ``"allow"`` or ``"deny"`` for an action against the chain of nodes.

    ``node_statements`` is one list of normalised statements per node in the
    chain (account, its OUs, the root), each the union of that node's SCPs.
    """
    # 1) Any applying explicit Deny anywhere in the chain wins.
    for statements in node_statements:
        for st in statements:
            if st["Effect"] == "Deny" and statement_applies(st, action, resource_arn, ctx):
                return "deny"
    # 2) Every node must contain an applying Allow, else implicit deny.
    for statements in node_statements:
        if not any(st["Effect"] == "Allow" and statement_applies(st, action, resource_arn, ctx)
                   for st in statements):
            return "deny"
    return "allow"
