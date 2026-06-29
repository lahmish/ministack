"""
AWS Organizations stub.

JSON 1.1 protocol, target prefix ``AWSOrganizationsV20161128``.

Models a single-master-account organization. The master is whatever account
the request is made under (resolved via ``get_account_id``); the org returns
itself as ALL-features by default. Accounts and OUs are stored in
account-scoped state so each tenant gets its own org.

Includes the ``Path`` field on Account and OrganizationalUnit per the
2026-03-31 AWS additive change.
"""

import copy
import json
import logging
import os
import re
import time

from ministack.core import scp, scp_resources
from ministack.core.responses import (
    AccountScopedDict,
    error_response_json,
    get_account_id,
    new_uuid,
    set_request_account_id,
)

logger = logging.getLogger("organizations")

_12_DIGITS = re.compile(r"^\d{12}$")


# Per-master-account state. Each account that calls Organizations gets its
# own org graph; that mirrors how local-emulator multi-tenancy works.
_orgs = AccountScopedDict()       # singleton "self" -> Organization dict
_accounts = AccountScopedDict()   # account_id -> Account dict
_ous = AccountScopedDict()        # ou_id -> OU dict (with ParentId)
_roots = AccountScopedDict()      # root_id -> Root dict (single root)
_create_status = AccountScopedDict()  # car-id -> CreateAccountStatus dict

# Handshakes are intentionally NOT account-scoped: an invite flow spans two
# accounts (the master creates it, the invited account accepts it), so both
# callers must be able to look up the same record by id. Visibility is enforced
# per-caller in ListHandshakesForAccount / AcceptHandshake instead.
_handshakes: dict = {}            # h-id -> handshake dict (global)

# --- Service Control Policy state ------------------------------------------
_policies = AccountScopedDict()         # policy_id -> policy record (incl internal "_Content")
_target_policies = AccountScopedDict()  # target_id -> [policy_id, ...] (attachment order, dedup)
_policy_targets = AccountScopedDict()   # policy_id -> [target_id, ...] (reverse index, in sync)
_tags = AccountScopedDict()             # resource_id (policy/root/ou/account) -> {key: value}

# GLOBAL (not account-scoped) reverse index: member_account_id -> master_account_id. Same
# rationale as _handshakes: a member's data-plane request arrives under the member's own
# account id, so SCP enforcement must be able to find the owning org graph to evaluate.
_account_org_index: dict = {}

# Toggleable enforcement flags (mirror cloudtrail._recording_enabled). Read by app.py's
# policy gates; flipped at boot via env or at runtime via POST /_ministack/config.
SCP_ENFORCEMENT = os.environ.get("SCP_ENFORCEMENT", "0") == "1"
RCP_ENFORCEMENT = os.environ.get("RCP_ENFORCEMENT", "0") == "1"

_SCP_TYPE = "SERVICE_CONTROL_POLICY"
_RCP_TYPE = "RESOURCE_CONTROL_POLICY"
_POLICY_TYPES = {_SCP_TYPE, _RCP_TYPE}
_ARN_SEGMENT = {_SCP_TYPE: "service_control_policy", _RCP_TYPE: "resource_control_policy"}

_FULL_ACCESS_ID = "p-FullAWSAccess"
_FULL_ACCESS_ARN = "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"
_FULL_ACCESS_CONTENT = (
    '{"Version": "2012-10-17", "Statement": '
    '[{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
)
# RCP default — same baseline Allow but with the Principal element RCPs require.
_RCPFULL_ID = "p-RCPFullAWSAccess"
_RCPFULL_ARN = "arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess"
_RCPFULL_CONTENT = (
    '{"Version": "2012-10-17", "Statement": '
    '[{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}'
)

# Default (AWS-managed) policy specs, indexed by policy type.
_DEFAULT_POLICIES = {
    _SCP_TYPE: (_FULL_ACCESS_ID, _FULL_ACCESS_ARN, "FullAWSAccess", _FULL_ACCESS_CONTENT),
    _RCP_TYPE: (_RCPFULL_ID, _RCPFULL_ARN, "RCPFullAWSAccess", _RCPFULL_CONTENT),
}


def reset():
    _orgs.clear()
    _accounts.clear()
    _ous.clear()
    _roots.clear()
    _create_status.clear()
    _handshakes.clear()
    _policies.clear()
    _target_policies.clear()
    _policy_targets.clear()
    _tags.clear()
    _account_org_index.clear()


def get_state():
    return {
        "orgs": copy.deepcopy(_orgs),
        "accounts": copy.deepcopy(_accounts),
        "ous": copy.deepcopy(_ous),
        "roots": copy.deepcopy(_roots),
        "create_status": copy.deepcopy(_create_status),
        "handshakes": copy.deepcopy(_handshakes),
        "policies": copy.deepcopy(_policies),
        "target_policies": copy.deepcopy(_target_policies),
        "policy_targets": copy.deepcopy(_policy_targets),
        "tags": copy.deepcopy(_tags),
        "account_org_index": copy.deepcopy(_account_org_index),
    }


def restore_state(data):
    if not data:
        return
    for store, key in (
        (_orgs, "orgs"), (_accounts, "accounts"),
        (_ous, "ous"), (_roots, "roots"),
        (_create_status, "create_status"),
        (_policies, "policies"), (_target_policies, "target_policies"),
        (_policy_targets, "policy_targets"), (_tags, "tags"),
    ):
        store.clear()
        for k, v in (data.get(key) or {}).items():
            store[k] = v
    _handshakes.clear()
    _handshakes.update(data.get("handshakes") or {})
    _account_org_index.clear()
    _account_org_index.update(data.get("account_org_index") or {})


def _json(status, body):
    return status, {"Content-Type": "application/x-amz-json-1.1"}, json.dumps(body).encode()


def _ensure_org():
    """Lazily initialise the org for the current master account."""
    if "self" in _orgs:
        return
    master = get_account_id()
    org_id = "o-" + new_uuid().replace("-", "")[:10]
    root_id = "r-" + new_uuid().replace("-", "")[:6]
    _orgs["self"] = {
        "Id": org_id,
        "Arn": f"arn:aws:organizations::{master}:organization/{org_id}",
        "FeatureSet": "ALL",
        "MasterAccountArn": f"arn:aws:organizations::{master}:account/{org_id}/{master}",
        "MasterAccountId": master,
        "MasterAccountEmail": f"master+{master}@ministack.local",
        "AvailablePolicyTypes": [
            {"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"},
            {"Type": "RESOURCE_CONTROL_POLICY", "Status": "ENABLED"},
        ],
    }
    _roots[root_id] = {
        "Id": root_id,
        "Arn": f"arn:aws:organizations::{master}:root/{org_id}/{root_id}",
        "Name": "Root",
        "PolicyTypes": [],
    }
    # Master account record
    _accounts[master] = {
        "Id": master,
        "Arn": f"arn:aws:organizations::{master}:account/{org_id}/{master}",
        "Email": f"master+{master}@ministack.local",
        "Name": "Master Account",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": int(time.time()),
        "Path": "/",
        "_ParentId": root_id,
    }
    # Every entity starts with the AWS-managed default policy of each type attached
    # (real-AWS default; enforcement stays gated on the policy type being enabled).
    _ensure_default_policies()
    _attach_default_policies(root_id)
    _attach_default_policies(master)
    _account_org_index[master] = master


def _public_account(a: dict) -> dict:
    return {k: v for k, v in a.items() if not k.startswith("_")}


def _public_ou(o: dict) -> dict:
    return {k: v for k, v in o.items() if not k.startswith("_")}


def _public_create_status(s: dict) -> dict:
    return {k: v for k, v in s.items() if not k.startswith("_")}


def _public_handshake(h: dict) -> dict:
    return {k: v for k, v in h.items() if not k.startswith("_")}


def _new_account_id() -> str:
    """Generate an unused 12-digit account id (service-assigned, like real AWS)."""
    aid = str(int(new_uuid().replace("-", ""), 16))[-12:].zfill(12)
    while aid in _accounts:
        aid = str(int(new_uuid().replace("-", ""), 16))[-12:].zfill(12)
    return aid


def _root_id() -> str:
    """Return the single root id for the current org (org is already ensured)."""
    return next(iter(_roots))


def _account_record(aid: str, *, email: str, name: str, joined_method: str,
                    parent_id: str) -> dict:
    """Build an Account record matching the master-account shape in _ensure_org."""
    org_id = _orgs["self"]["Id"]
    master = get_account_id()
    return {
        "Id": aid,
        "Arn": f"arn:aws:organizations::{master}:account/{org_id}/{aid}",
        "Email": email,
        "Name": name,
        "Status": "ACTIVE",
        "JoinedMethod": joined_method,
        "JoinedTimestamp": int(time.time()),
        "Path": "/",
        "_ParentId": parent_id,
    }


# --- SCP helpers -----------------------------------------------------------

def _policy_summary(p: dict) -> dict:
    """PolicySummary view: drop internal (_-prefixed) fields like _Content."""
    return {k: v for k, v in p.items() if not k.startswith("_")}


def _new_policy_id() -> str:
    pid = "p-" + new_uuid().replace("-", "")[:8]
    while pid in _policies:
        pid = "p-" + new_uuid().replace("-", "")[:8]
    return pid


def _ensure_default_policies():
    """Create the AWS-managed default policy of each type for the current org if absent."""
    for ptype, (pid, arn, name, content) in _DEFAULT_POLICIES.items():
        if pid not in _policies:
            _policies[pid] = {
                "Id": pid,
                "Arn": arn,
                "Name": name,
                "Description": "Allows access to every operation",
                "Type": ptype,
                "AwsManaged": True,
                "_Content": content,
            }


def _attach_default_policies(target_id: str):
    """Attach the AWS-managed default of every policy type to a target."""
    for pid, *_ in _DEFAULT_POLICIES.values():
        _attach(pid, target_id)


def _attach(policy_id: str, target_id: str):
    """Attach a policy to a target, keeping both indexes in sync. Idempotent; bypasses
    the public AttachPolicy enable-check (used for the FullAWSAccess default)."""
    pols = _target_policies.setdefault(target_id, [])
    if policy_id not in pols:
        pols.append(policy_id)
    tgts = _policy_targets.setdefault(policy_id, [])
    if target_id not in tgts:
        tgts.append(target_id)


def _detach(policy_id: str, target_id: str):
    pols = _target_policies.get(target_id) or []
    if policy_id in pols:
        pols.remove(policy_id)
    tgts = _policy_targets.get(policy_id) or []
    if target_id in tgts:
        tgts.remove(target_id)


def _resolve_target(target_id):
    """Return (record, Type) for a root/OU/account target, or (None, None)."""
    if target_id in _roots:
        return _roots[target_id], "ROOT"
    if target_id in _ous:
        return _ous[target_id], "ORGANIZATIONAL_UNIT"
    if target_id in _accounts:
        return _accounts[target_id], "ACCOUNT"
    return None, None


def _validate_policy_doc(content):
    """Return the parsed document if it is a valid policy JSON, else None."""
    if not isinstance(content, str) or not content.strip():
        return None
    try:
        doc = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(doc, dict) or "Statement" not in doc:
        return None
    return doc


def _rcp_violation(doc):
    """Return an error message if an RCP document breaks RCP-specific rules, else None.

    Real AWS: customer RCP statements must use Effect 'Deny', must set Principal to
    '*' (principals are targeted via Condition), may not use NotPrincipal/NotAction,
    and the Action must be service-scoped (a bare '*' is rejected)."""
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return "An RCP must contain at least one statement"
    for st in statements:
        if not isinstance(st, dict):
            return "Invalid RCP statement"
        if st.get("Effect") != "Deny":
            return "RCP statements must use Effect 'Deny'"
        if st.get("Principal") != "*":
            return "RCP statements must set Principal to '*'"
        if "NotPrincipal" in st or "NotAction" in st:
            return "RCPs do not support the NotPrincipal or NotAction elements"
        actions = st.get("Action")
        if actions is None:
            return "RCP statements must include an Action"
        alist = actions if isinstance(actions, list) else [actions]
        if any(a == "*" for a in alist):
            return "RCPs require a service-scoped Action; a bare '*' is not allowed"
        if "Resource" not in st and "NotResource" not in st:
            return "RCP statements must include a Resource or NotResource"
    return None


def _policy_type_enabled(ptype: str) -> bool:
    root = next(iter(_roots.values()), None)
    if not root:
        return False
    return any(pt.get("Type") == ptype and pt.get("Status") == "ENABLED"
               for pt in root.get("PolicyTypes", []))


def _scp_type_enabled() -> bool:
    return _policy_type_enabled(_SCP_TYPE)


def _resource_exists(rid) -> bool:
    """True if rid names a taggable Organizations resource (policy/root/OU/account)."""
    return bool(rid) and (
        rid in _policies or rid in _roots or rid in _ous or rid in _accounts)


def _paginate(items, payload):
    """Slice ``items`` by MaxResults/NextToken. Returns (page, next_token).

    NextToken is the integer start offset encoded as a string (opaque to callers,
    round-trips through boto3 paginators)."""
    try:
        start = int(payload.get("NextToken") or 0)
    except (ValueError, TypeError):
        start = 0
    max_results = payload.get("MaxResults")
    if max_results in (None, ""):
        return items[start:], None
    try:
        mr = int(max_results)
    except (ValueError, TypeError):
        return items[start:], None
    page = items[start:start + mr]
    nxt = start + mr
    return page, (str(nxt) if nxt < len(items) else None)


def _node_chain(account_id):
    """Walk _ParentId from an account up to (and including) the root.

    Returns ``[account_id, ou_id..., root_id]`` — one node per level whose SCPs
    must all allow the action."""
    chain = []
    node_id = account_id
    seen = set()
    while node_id and node_id not in seen:
        seen.add(node_id)
        chain.append(node_id)
        rec = _accounts.get(node_id) or _ous.get(node_id)
        if rec is None:
            break  # reached the root (no _ParentId) or an unknown node
        node_id = rec.get("_ParentId")
    return chain


def _statements_for_target(target_id, policy_type):
    """Concatenate the normalised statements of every policy of ``policy_type``
    attached to a node."""
    statements = []
    for pid in (_target_policies.get(target_id) or []):
        rec = _policies.get(pid)
        if rec and rec.get("Type") == policy_type:
            statements.extend(scp.parse_policy(rec["_Content"]))
    return statements


def scp_decision(caller_account, action, resource_arn, base_ctx):
    """Decide whether an SCP-governed request is allowed. Returns ``(allowed, reason)``.

    Org state is account-scoped to the master, but a member's data-plane request
    arrives under the member's own id; we look the master up in the global
    ``_account_org_index`` then impersonate it to read the org graph (restoring
    the caller in ``finally`` — same pattern as ``_accept_handshake``)."""
    master = _account_org_index.get(caller_account)
    if master is None:
        return True, "not-org-member"
    if master == caller_account:
        return True, "management-account-exempt"
    saved = get_account_id()
    try:
        set_request_account_id(master)
        org = _orgs.get("self")
        if not org or org.get("FeatureSet") != "ALL":
            return True, "no-all-features"
        if not _scp_type_enabled():
            return True, "scp-type-not-enabled"
        if caller_account not in _accounts:
            return True, "not-member-of-this-org"
        chain = _node_chain(caller_account)
        node_statements = [_statements_for_target(n, _SCP_TYPE) for n in chain]
        org_id = org.get("Id", "")
        # aws:PrincipalOrgPaths entry is the top-down path o-id/r-root/ou.../account/
        org_path = org_id + "/" + "/".join(reversed(chain)) + "/"
        ctx = dict(base_ctx)
        ctx["aws:PrincipalAccount"] = caller_account
        ctx["aws:PrincipalOrgID"] = org_id
        ctx["aws:PrincipalArn"] = f"arn:aws:iam::{caller_account}:root"
        ctx["aws:PrincipalOrgPaths"] = [org_path]
        ctx["aws:PrincipalType"] = "Account"
        ctx["aws:PrincipalIsAWSService"] = "false"
        ctx["aws:userid"] = caller_account
        decision = scp.evaluate_scps(node_statements, action, resource_arn, ctx)
        return decision == "allow", f"scp-{decision}"
    finally:
        set_request_account_id(saved)


def _org_id_for_master(master):
    """Return the org id for a master account via brief impersonation, or ''."""
    if not master:
        return ""
    saved = get_account_id()
    try:
        set_request_account_id(master)
        org = _orgs.get("self")
        return org.get("Id", "") if org else ""
    finally:
        set_request_account_id(saved)


def rcp_decision(caller_account, action, resource_arn, base_ctx):
    """Decide whether an RCP-governed request is allowed. Returns ``(allowed, reason)``.

    RCPs are resource-side: we evaluate the **resource owner's** RCP chain against the
    **calling** principal. The resource account comes from the resource ARN (falling
    back to the caller for account-less S3 ARNs)."""
    if not resource_arn:
        return True, "no-resource-arn"
    res_acct = scp_resources.account_from_arn(resource_arn) or caller_account
    master = _account_org_index.get(res_acct)
    if master is None:
        return True, "resource-not-in-org"
    if master == res_acct:
        return True, "management-account-resource-exempt"
    # Caller's own org id (computed before impersonating the resource master) so the
    # aws:PrincipalOrgID / aws:SourceOrgID keys reflect the CALLER, not the resource.
    caller_org_id = _org_id_for_master(_account_org_index.get(caller_account))
    saved = get_account_id()
    try:
        set_request_account_id(master)
        org = _orgs.get("self")
        if not org or org.get("FeatureSet") != "ALL":
            return True, "no-all-features"
        if not _policy_type_enabled(_RCP_TYPE):
            return True, "rcp-type-not-enabled"
        if res_acct not in _accounts:
            return True, "resource-not-member"
        chain = _node_chain(res_acct)
        node_statements = [_statements_for_target(n, _RCP_TYPE) for n in chain]
        ctx = dict(base_ctx)
        ctx["aws:PrincipalAccount"] = caller_account
        ctx["aws:PrincipalArn"] = f"arn:aws:iam::{caller_account}:root"
        ctx["aws:PrincipalOrgID"] = caller_org_id
        ctx["aws:SourceOrgID"] = caller_org_id
        ctx["aws:PrincipalIsAWSService"] = "false"
        decision = scp.evaluate_scps(node_statements, action, resource_arn, ctx)
        return decision == "allow", f"rcp-{decision}"
    finally:
        set_request_account_id(saved)


def _describe_organization(_payload):
    _ensure_org()
    return _json(200, {"Organization": dict(_orgs["self"])})


def _list_roots(_payload):
    _ensure_org()
    return _json(200, {"Roots": list(_roots.values()), "NextToken": None})


def _list_accounts(_payload):
    _ensure_org()
    return _json(200, {
        "Accounts": [_public_account(a) for a in _accounts.values()],
        "NextToken": None,
    })


def _describe_account(payload):
    _ensure_org()
    aid = payload.get("AccountId")
    if not aid:
        return error_response_json("InvalidInputException", "AccountId is required", 400)
    a = _accounts.get(aid)
    if not a:
        return error_response_json("AccountNotFoundException",
                                   f"Account {aid} not found", 400)
    return _json(200, {"Account": _public_account(a)})


def _list_organizational_units_for_parent(payload):
    _ensure_org()
    parent_id = payload.get("ParentId") or ""
    out = [_public_ou(o) for o in _ous.values() if o.get("_ParentId") == parent_id]
    return _json(200, {"OrganizationalUnits": out, "NextToken": None})


def _list_accounts_for_parent(payload):
    _ensure_org()
    parent_id = payload.get("ParentId") or ""
    out = [_public_account(a) for a in _accounts.values()
           if a.get("_ParentId") == parent_id]
    return _json(200, {"Accounts": out, "NextToken": None})


def _create_organizational_unit(payload):
    _ensure_org()
    parent_id = payload.get("ParentId")
    name = payload.get("Name")
    if not parent_id or not name:
        return error_response_json("InvalidInputException",
                                   "ParentId and Name are required", 400)
    org_id = _orgs["self"]["Id"]
    master = get_account_id()
    ou_id = f"ou-{parent_id.split('-')[-1][:4]}-{new_uuid().replace('-','')[:10]}"
    parent_ou = _ous.get(parent_id)
    parent_path = (parent_ou or {}).get("Path", "/")
    rec = {
        "Id": ou_id,
        "Arn": f"arn:aws:organizations::{master}:ou/{org_id}/{ou_id}",
        "Name": name,
        "Path": (parent_path.rstrip("/") + "/" + name + "/") if parent_path != "/" else f"/{name}/",
        "_ParentId": parent_id,
    }
    _ous[ou_id] = rec
    _attach_default_policies(ou_id)
    return _json(200, {"OrganizationalUnit": _public_ou(rec)})


def _describe_organizational_unit(payload):
    _ensure_org()
    ou_id = payload.get("OrganizationalUnitId")
    o = _ous.get(ou_id) if ou_id else None
    if not o:
        return error_response_json("OrganizationalUnitNotFoundException",
                                   f"OU {ou_id} not found", 400)
    return _json(200, {"OrganizationalUnit": _public_ou(o)})


def _delete_organizational_unit(payload):
    _ensure_org()
    ou_id = payload.get("OrganizationalUnitId")
    if not ou_id or ou_id not in _ous:
        return error_response_json("OrganizationalUnitNotFoundException",
                                   f"OU {ou_id} not found", 400)
    del _ous[ou_id]
    return _json(200, {})


def _create_account(payload):
    _ensure_org()
    email = payload.get("Email")
    name = payload.get("AccountName")
    if not email or not name:
        return error_response_json("InvalidInputException",
                                   "Email and AccountName are required", 400)
    aid = _new_account_id()
    car_id = ("car-" + new_uuid().replace("-", ""))[:36]
    rec = {
        "Id": car_id,
        "AccountName": name,
        "State": "IN_PROGRESS",
        "RequestedTimestamp": int(time.time()),
        "_Email": email,
        "_AccountId": aid,
    }
    _create_status[car_id] = rec
    return _json(200, {"CreateAccountStatus": _public_create_status(rec)})


def _describe_create_account_status(payload):
    _ensure_org()
    car_id = payload.get("CreateAccountRequestId")
    rec = _create_status.get(car_id) if car_id else None
    if not rec:
        return error_response_json("CreateAccountStatusNotFoundException",
                                   f"CreateAccountStatus {car_id} not found", 400)
    # Async create completes on first describe: place the account at the root.
    if rec["State"] == "IN_PROGRESS":
        aid = rec["_AccountId"]
        _accounts[aid] = _account_record(
            aid, email=rec["_Email"], name=rec["AccountName"],
            joined_method="CREATED", parent_id=_root_id())
        _attach_default_policies(aid)
        _account_org_index[aid] = get_account_id()
        rec["State"] = "SUCCEEDED"
        rec["AccountId"] = aid
        rec["CompletedTimestamp"] = int(time.time())
    return _json(200, {"CreateAccountStatus": _public_create_status(rec)})


def _move_account(payload):
    _ensure_org()
    aid = payload.get("AccountId")
    source = payload.get("SourceParentId")
    dest = payload.get("DestinationParentId")
    if not aid or not source or not dest:
        return error_response_json(
            "InvalidInputException",
            "AccountId, SourceParentId and DestinationParentId are required", 400)
    account = _accounts.get(aid)
    if not account:
        return error_response_json("AccountNotFoundException",
                                   f"Account {aid} not found", 400)
    if (source not in _roots and source not in _ous) or account.get("_ParentId") != source:
        return error_response_json("SourceParentNotFoundException",
                                   f"Account {aid} is not in source parent {source}", 400)
    if dest not in _roots and dest not in _ous:
        return error_response_json("DestinationParentNotFoundException",
                                   f"Destination parent {dest} not found", 400)
    account["_ParentId"] = dest
    return _json(200, {})


def _list_parents(payload):
    _ensure_org()
    child_id = payload.get("ChildId")
    rec = (_accounts.get(child_id) or _ous.get(child_id)) if child_id else None
    if not rec:
        return error_response_json("ChildNotFoundException",
                                   f"Child {child_id} not found", 400)
    parent_id = rec.get("_ParentId")
    ptype = "ROOT" if parent_id in _roots else "ORGANIZATIONAL_UNIT"
    return _json(200, {"Parents": [{"Id": parent_id, "Type": ptype}], "NextToken": None})


def _list_children(payload):
    _ensure_org()
    parent_id = payload.get("ParentId")
    child_type = payload.get("ChildType")
    if not parent_id or (parent_id not in _roots and parent_id not in _ous):
        return error_response_json("ParentNotFoundException",
                                   f"Parent {parent_id} not found", 400)
    if child_type == "ACCOUNT":
        children = [{"Id": a["Id"], "Type": "ACCOUNT"}
                    for a in _accounts.values() if a.get("_ParentId") == parent_id]
    elif child_type == "ORGANIZATIONAL_UNIT":
        children = [{"Id": o["Id"], "Type": "ORGANIZATIONAL_UNIT"}
                    for o in _ous.values() if o.get("_ParentId") == parent_id]
    else:
        return error_response_json("InvalidInputException",
                                   "ChildType must be ACCOUNT or ORGANIZATIONAL_UNIT", 400)
    return _json(200, {"Children": children, "NextToken": None})


def _invite_account_to_organization(payload):
    _ensure_org()
    target = payload.get("Target") or {}
    target_id = target.get("Id")
    if not target_id:
        return error_response_json("InvalidInputException",
                                   "Target.Id is required", 400)
    if target.get("Type") == "ACCOUNT":
        if not _12_DIGITS.match(target_id):
            return error_response_json("InvalidInputException",
                                       "Target.Id must be a 12-digit account id", 400)
        invited = target_id
    else:
        invited = _new_account_id()
    if invited in _accounts:
        return error_response_json("DuplicateAccountException",
                                   f"Account {invited} is already a member", 400)
    master = get_account_id()
    if any(h["State"] == "OPEN" and h["_InvitedAccountId"] == invited
           and h["_MasterAccountId"] == master for h in _handshakes.values()):
        return error_response_json("DuplicateHandshakeException",
                                   f"An open handshake for {invited} already exists", 400)
    org_id = _orgs["self"]["Id"]
    h_id = "h-" + new_uuid().replace("-", "")[:10]
    now = int(time.time())
    rec = {
        "Id": h_id,
        "Arn": f"arn:aws:organizations::{master}:handshake/{org_id}/invite/{h_id}",
        "State": "OPEN",
        "Action": "INVITE",
        "RequestedTimestamp": now,
        "ExpirationTimestamp": now + 15 * 24 * 3600,
        "Parties": [
            {"Id": org_id, "Type": "ORGANIZATION"},
            {"Id": invited, "Type": "ACCOUNT"},
        ],
        "_MasterAccountId": master,
        "_InvitedAccountId": invited,
    }
    _handshakes[h_id] = rec
    return _json(200, {"Handshake": _public_handshake(rec)})


def _accept_handshake(payload):
    _ensure_org()
    h_id = payload.get("HandshakeId")
    rec = _handshakes.get(h_id) if h_id else None
    if not rec:
        return error_response_json("HandshakeNotFoundException",
                                   f"Handshake {h_id} not found", 400)
    caller = get_account_id()
    if caller != rec["_InvitedAccountId"]:
        return error_response_json("AccountOwnerNotVerifiedException",
                                   "Only the invited account may accept this handshake", 400)
    if rec["State"] != "OPEN":
        return error_response_json("InvalidHandshakeTransitionException",
                                   f"Handshake {h_id} is not OPEN", 400)
    rec["State"] = "ACCEPTED"
    # Materialise the member into the MASTER's org graph. _accounts is scoped to
    # the current caller, so impersonate the master for the write, then restore.
    master = rec["_MasterAccountId"]
    invited = rec["_InvitedAccountId"]
    try:
        set_request_account_id(master)
        _ensure_org()
        _accounts[invited] = _account_record(
            invited, email=f"member+{invited}@ministack.local", name=f"Account {invited}",
            joined_method="INVITED", parent_id=_root_id())
        _attach_default_policies(invited)
        _account_org_index[invited] = master
    finally:
        set_request_account_id(caller)
    return _json(200, {"Handshake": _public_handshake(rec)})


def _list_handshakes_for_account(_payload):
    _ensure_org()
    caller = get_account_id()
    out = [_public_handshake(h) for h in _handshakes.values()
           if caller in (h["_MasterAccountId"], h["_InvitedAccountId"])]
    return _json(200, {"Handshakes": out, "NextToken": None})


# --- SCP management actions -------------------------------------------------

def _create_policy(payload):
    _ensure_org()
    content = payload.get("Content")
    name = payload.get("Name")
    ptype = payload.get("Type")
    description = payload.get("Description", "")
    if ptype not in _POLICY_TYPES:
        return error_response_json("InvalidInputException",
                                   "Type must be SERVICE_CONTROL_POLICY or "
                                   "RESOURCE_CONTROL_POLICY", 400)
    if not name or not content:
        return error_response_json("InvalidInputException",
                                   "Name and Content are required", 400)
    parsed = _validate_policy_doc(content)
    if parsed is None:
        return error_response_json("MalformedPolicyDocumentException",
                                   "The provided policy document is not valid", 400)
    if ptype == _RCP_TYPE and (v := _rcp_violation(parsed)):
        return error_response_json("MalformedPolicyDocumentException", v, 400)
    if any(p.get("Name") == name and p.get("Type") == ptype for p in _policies.values()):
        return error_response_json("DuplicatePolicyException",
                                   f"A policy named {name} already exists", 400)
    pid = _new_policy_id()
    org_id = _orgs["self"]["Id"]
    master = get_account_id()
    rec = {
        "Id": pid,
        "Arn": f"arn:aws:organizations::{master}:policy/{org_id}/"
               f"{_ARN_SEGMENT[ptype]}/{pid}",
        "Name": name,
        "Description": description,
        "Type": ptype,
        "AwsManaged": False,
        "_Content": content,
    }
    _policies[pid] = rec
    initial_tags = payload.get("Tags") or []
    if initial_tags:
        _tags[pid] = {t["Key"]: t.get("Value", "") for t in initial_tags if "Key" in t}
    return _json(200, {"Policy": {"PolicySummary": _policy_summary(rec), "Content": content}})


def _describe_policy(payload):
    _ensure_org()
    pid = payload.get("PolicyId")
    rec = _policies.get(pid) if pid else None
    if not rec:
        return error_response_json("PolicyNotFoundException",
                                   f"Policy {pid} not found", 400)
    return _json(200, {"Policy": {"PolicySummary": _policy_summary(rec),
                                  "Content": rec["_Content"]}})


def _update_policy(payload):
    _ensure_org()
    pid = payload.get("PolicyId")
    rec = _policies.get(pid) if pid else None
    if not rec:
        return error_response_json("PolicyNotFoundException",
                                   f"Policy {pid} not found", 400)
    if rec.get("AwsManaged"):
        return error_response_json("ConstraintViolationException",
                                   "AWS-managed policies cannot be modified", 400)
    name = payload.get("Name")
    content = payload.get("Content")
    description = payload.get("Description")
    if name is not None and name != rec["Name"] and any(
            p.get("Name") == name and p.get("Type") == rec.get("Type")
            for p in _policies.values()):
        return error_response_json("DuplicatePolicyException",
                                   f"A policy named {name} already exists", 400)
    if content is not None:
        parsed = _validate_policy_doc(content)
        if parsed is None:
            return error_response_json("MalformedPolicyDocumentException",
                                       "The provided policy document is not valid", 400)
        if rec.get("Type") == _RCP_TYPE and (v := _rcp_violation(parsed)):
            return error_response_json("MalformedPolicyDocumentException", v, 400)
    if name is not None:
        rec["Name"] = name
    if description is not None:
        rec["Description"] = description
    if content is not None:
        rec["_Content"] = content
    return _json(200, {"Policy": {"PolicySummary": _policy_summary(rec),
                                  "Content": rec["_Content"]}})


def _delete_policy(payload):
    _ensure_org()
    pid = payload.get("PolicyId")
    rec = _policies.get(pid) if pid else None
    if not rec:
        return error_response_json("PolicyNotFoundException",
                                   f"Policy {pid} not found", 400)
    if rec.get("AwsManaged"):
        return error_response_json("ConstraintViolationException",
                                   "AWS-managed policies cannot be deleted", 400)
    if _policy_targets.get(pid):
        return error_response_json("PolicyInUseException",
                                   f"Policy {pid} is still attached to one or more targets", 400)
    _policies.pop(pid, None)
    _policy_targets.pop(pid, None)
    _tags.pop(pid, None)
    return _json(200, {})


def _list_policies(payload):
    _ensure_org()
    pfilter = payload.get("Filter")
    if pfilter not in _POLICY_TYPES:
        return error_response_json("InvalidInputException",
                                   "Filter must be SERVICE_CONTROL_POLICY or "
                                   "RESOURCE_CONTROL_POLICY", 400)
    out = [_policy_summary(p) for p in _policies.values() if p.get("Type") == pfilter]
    page, nxt = _paginate(out, payload)
    return _json(200, {"Policies": page, "NextToken": nxt})


def _list_policies_for_target(payload):
    _ensure_org()
    target_id = payload.get("TargetId")
    pfilter = payload.get("Filter")
    if pfilter not in _POLICY_TYPES:
        return error_response_json("InvalidInputException",
                                   "Filter must be SERVICE_CONTROL_POLICY or "
                                   "RESOURCE_CONTROL_POLICY", 400)
    rec, _ttype = _resolve_target(target_id)
    if rec is None:
        return error_response_json("TargetNotFoundException",
                                   f"Target {target_id} not found", 400)
    pids = _target_policies.get(target_id) or []
    out = [_policy_summary(_policies[pid]) for pid in pids
           if pid in _policies and _policies[pid].get("Type") == pfilter]
    page, nxt = _paginate(out, payload)
    return _json(200, {"Policies": page, "NextToken": nxt})


def _list_targets_for_policy(payload):
    _ensure_org()
    pid = payload.get("PolicyId")
    if not pid or pid not in _policies:
        return error_response_json("PolicyNotFoundException",
                                   f"Policy {pid} not found", 400)
    out = []
    for tid in (_policy_targets.get(pid) or []):
        rec, ttype = _resolve_target(tid)
        if rec is None:
            continue
        out.append({
            "TargetId": tid,
            "Arn": rec.get("Arn", ""),
            "Name": rec.get("Name", ""),
            "Type": ttype,
        })
    page, nxt = _paginate(out, payload)
    return _json(200, {"Targets": page, "NextToken": nxt})


def _attach_policy(payload):
    _ensure_org()
    pid = payload.get("PolicyId")
    target_id = payload.get("TargetId")
    if not pid or pid not in _policies:
        return error_response_json("PolicyNotFoundException",
                                   f"Policy {pid} not found", 400)
    rec, _ttype = _resolve_target(target_id)
    if rec is None:
        return error_response_json("TargetNotFoundException",
                                   f"Target {target_id} not found", 400)
    ptype = _policies[pid].get("Type")
    if not _policy_type_enabled(ptype):
        return error_response_json("PolicyTypeNotEnabledException",
                                   f"The {ptype} type is not enabled on this root", 400)
    if pid in (_target_policies.get(target_id) or []):
        return error_response_json("DuplicatePolicyAttachmentException",
                                   f"Policy {pid} is already attached to {target_id}", 400)
    _attach(pid, target_id)
    return _json(200, {})


def _detach_policy(payload):
    _ensure_org()
    pid = payload.get("PolicyId")
    target_id = payload.get("TargetId")
    if not pid or pid not in _policies:
        return error_response_json("PolicyNotFoundException",
                                   f"Policy {pid} not found", 400)
    rec, _ttype = _resolve_target(target_id)
    if rec is None:
        return error_response_json("TargetNotFoundException",
                                   f"Target {target_id} not found", 400)
    attached = _target_policies.get(target_id) or []
    if pid not in attached:
        return error_response_json("PolicyNotAttachedException",
                                   f"Policy {pid} is not attached to {target_id}", 400)
    if pid == _RCPFULL_ID:
        return error_response_json("ConstraintViolationException",
                                   "The RCPFullAWSAccess policy cannot be detached", 400)
    ptype = _policies[pid].get("Type")
    same_type = [p for p in attached
                 if p in _policies and _policies[p].get("Type") == ptype]
    if len(same_type) <= 1:
        return error_response_json(
            "ConstraintViolationException",
            f"Cannot detach the last {ptype} from a target", 400)
    _detach(pid, target_id)
    return _json(200, {})


def _enable_policy_type(payload):
    _ensure_org()
    root_id = payload.get("RootId")
    ptype = payload.get("PolicyType")
    root = _roots.get(root_id) if root_id else None
    if not root:
        return error_response_json("RootNotFoundException",
                                   f"Root {root_id} not found", 400)
    if ptype not in _POLICY_TYPES:
        return error_response_json("PolicyTypeNotAvailableForOrganizationException",
                                   f"Policy type {ptype} is not available", 400)
    types = root.setdefault("PolicyTypes", [])
    if any(pt.get("Type") == ptype and pt.get("Status") == "ENABLED" for pt in types):
        return error_response_json("PolicyTypeAlreadyEnabledException",
                                   f"{ptype} is already enabled", 400)
    types[:] = [pt for pt in types if pt.get("Type") != ptype]
    types.append({"Type": ptype, "Status": "ENABLED"})
    return _json(200, {"Root": dict(root)})


def _disable_policy_type(payload):
    _ensure_org()
    root_id = payload.get("RootId")
    ptype = payload.get("PolicyType")
    root = _roots.get(root_id) if root_id else None
    if not root:
        return error_response_json("RootNotFoundException",
                                   f"Root {root_id} not found", 400)
    if ptype not in _POLICY_TYPES:
        return error_response_json("PolicyTypeNotAvailableForOrganizationException",
                                   f"Policy type {ptype} is not available", 400)
    types = root.get("PolicyTypes", [])
    if not any(pt.get("Type") == ptype and pt.get("Status") == "ENABLED" for pt in types):
        return error_response_json("PolicyTypeNotEnabledException",
                                   f"{ptype} is not enabled", 400)
    root["PolicyTypes"] = [pt for pt in types if pt.get("Type") != ptype]
    return _json(200, {"Root": dict(root)})


def _tag_resource(payload):
    _ensure_org()
    rid = payload.get("ResourceId")
    if not _resource_exists(rid):
        return error_response_json("InvalidInputException",
                                   f"Resource {rid} not found", 400)
    store = _tags.setdefault(rid, {})
    for t in payload.get("Tags") or []:
        if "Key" in t:
            store[t["Key"]] = t.get("Value", "")
    return _json(200, {})


def _untag_resource(payload):
    _ensure_org()
    rid = payload.get("ResourceId")
    if not _resource_exists(rid):
        return error_response_json("InvalidInputException",
                                   f"Resource {rid} not found", 400)
    store = _tags.get(rid) or {}
    for k in payload.get("TagKeys") or []:
        store.pop(k, None)
    return _json(200, {})


def _list_tags_for_resource(payload):
    _ensure_org()
    rid = payload.get("ResourceId")
    if not _resource_exists(rid):
        return error_response_json("InvalidInputException",
                                   f"Resource {rid} not found", 400)
    items = [{"Key": k, "Value": v} for k, v in (_tags.get(rid) or {}).items()]
    page, nxt = _paginate(items, payload)
    return _json(200, {"Tags": page, "NextToken": nxt})


_DISPATCH = {
    "DescribeOrganization": _describe_organization,
    "ListRoots": _list_roots,
    "ListAccounts": _list_accounts,
    "DescribeAccount": _describe_account,
    "ListOrganizationalUnitsForParent": _list_organizational_units_for_parent,
    "ListAccountsForParent": _list_accounts_for_parent,
    "CreateOrganizationalUnit": _create_organizational_unit,
    "DescribeOrganizationalUnit": _describe_organizational_unit,
    "DeleteOrganizationalUnit": _delete_organizational_unit,
    "CreateAccount": _create_account,
    "DescribeCreateAccountStatus": _describe_create_account_status,
    "MoveAccount": _move_account,
    "ListParents": _list_parents,
    "ListChildren": _list_children,
    "InviteAccountToOrganization": _invite_account_to_organization,
    "AcceptHandshake": _accept_handshake,
    "ListHandshakesForAccount": _list_handshakes_for_account,
    "CreatePolicy": _create_policy,
    "DescribePolicy": _describe_policy,
    "UpdatePolicy": _update_policy,
    "DeletePolicy": _delete_policy,
    "ListPolicies": _list_policies,
    "ListPoliciesForTarget": _list_policies_for_target,
    "ListTargetsForPolicy": _list_targets_for_policy,
    "AttachPolicy": _attach_policy,
    "DetachPolicy": _detach_policy,
    "EnablePolicyType": _enable_policy_type,
    "DisablePolicyType": _disable_policy_type,
    "TagResource": _tag_resource,
    "UntagResource": _untag_resource,
    "ListTagsForResource": _list_tags_for_resource,
}


async def handle_request(method, path, headers, body, query_params):
    target = headers.get("X-Amz-Target") or headers.get("x-amz-target") or ""
    op = target.split(".", 1)[1] if "." in target else target
    if not op:
        return error_response_json("InvalidAction", "missing X-Amz-Target", 400)

    body_text = body.decode("utf-8") if isinstance(body, bytes) else (body or "")
    try:
        payload = json.loads(body_text) if body_text else {}
    except json.JSONDecodeError:
        return error_response_json("SerializationException", "invalid JSON body", 400)

    fn = _DISPATCH.get(op)
    if fn is None:
        return error_response_json("InvalidAction",
                                   f"Operation '{op}' not implemented", 400)
    return fn(payload)
