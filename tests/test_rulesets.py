"""The prebuilt guardrail catalogue.

Every rule is exercised against something it MUST block and something it MUST NOT block.
A shipped rule that silently never fires is worse than no rule, because the operator
believes they are covered.
"""
import json

import pytest
from fastapi.testclient import TestClient

from provenrail import rulesets
from provenrail.anchor import LocalAnchor
from provenrail.easy import PolicyConfigError, load_policy
from provenrail.ingest_client import provision_stream
from provenrail.policy import Policy, PolicyViolation, SessionState
from provenrail.sdk import FlightRecorder
from provenrail.server.app import create_app


def _decide(rule_id, tool="some_tool", args=None, event_type="tool_call", oversight=False):
    """Run one catalogue rule against one call, the way the SDK does."""
    policy = Policy.from_dict({"rules": rulesets.resolve([rule_id])})
    ctx = {"tool": tool, "match_text": json.dumps(args or {})}
    return policy.decide(event_type, ctx, SessionState(had_oversight=oversight))


# (rule id, a call it must stop, a call it must let through)
BLOCK_CASES = [
    ("destructive.delete-tools", {"tool": "delete_user"}, {"tool": "get_user"}),
    ("destructive.drop-tools", {"tool": "drop_table"}, {"tool": "dropoff_scheduler"}),
    ("destructive.truncate-tools", {"tool": "truncate_logs"}, {"tool": "read_logs"}),
    ("destructive.destroy-tools", {"tool": "destroy_stack"}, {"tool": "describe_stack"}),
    ("destructive.recursive-force-remove",
     {"args": {"cmd": "rm -rf /var/data"}}, {"args": {"cmd": "rm file.txt"}}),
    ("destructive.sql-drop-or-truncate",
     {"args": {"q": "DROP TABLE users"}}, {"args": {"q": "SELECT id FROM users"}}),
    ("destructive.delete-without-where",
     # The trailing key matters: args are matched as JSON, and an earlier regex missed the
     # unbounded DELETE whenever another argument followed it in serialization order.
     {"args": {"q": "DELETE FROM orders", "db": "prod"}},
     {"args": {"q": "DELETE FROM orders WHERE id = 3", "db": "prod"}}),
    ("secrets.aws-access-key",
     {"args": {"k": "AKIAIOSFODNN7EXAMPLE"}}, {"args": {"k": "AKIA-not-a-key"}}),
    ("secrets.private-key-block",
     {"args": {"k": "-----BEGIN RSA PRIVATE KEY-----\nMII"}},
     {"args": {"k": "-----BEGIN CERTIFICATE-----"}}),
    ("secrets.bearer-token",
     {"args": {"t": "ghp_abcdefghijklmnopqrstuvwxyz01"}}, {"args": {"t": "ghp_short"}}),
    ("secrets.jwt",
     {"args": {"t": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K"}},
     {"args": {"t": "not.a.jwt"}}),
    ("production.force-push",
     {"args": {"cmd": "git push --force origin main"}},
     {"args": {"cmd": "git push origin main"}}),
    ("production.terraform-destroy",
     {"args": {"cmd": "terraform destroy -auto-approve"}},
     {"args": {"cmd": "terraform plan"}}),
    ("access.world-writable-chmod",
     {"args": {"cmd": "chmod 777 /srv"}}, {"args": {"cmd": "chmod 644 /srv"}}),
    ("access.disable-mfa",
     {"args": {"cmd": "disable mfa for user bob"}}, {"args": {"cmd": "enable mfa for bob"}}),
    ("exfiltration.paste-sites",
     {"args": {"url": "https://pastebin.com/abc"}},
     {"args": {"url": "https://example.com/abc"}}),
]


@pytest.mark.parametrize(("rule_id", "blocked", "allowed"), BLOCK_CASES,
                         ids=[c[0] for c in BLOCK_CASES])
def test_each_deny_rule_blocks_what_it_should_and_permits_what_it_should(rule_id, blocked, allowed):
    assert _decide(rule_id, **blocked).effect == "deny", f"{rule_id} failed to block"
    assert _decide(rule_id, **allowed).effect == "allow", f"{rule_id} over-blocked"


OVERSIGHT_CASES = [
    ("money.wire-transfer", "wire_transfer"),
    ("money.payment", "create_payment"),
    ("money.refund", "issue_refund"),
    ("money.charge", "charge_card"),
    ("production.deploy", "deploy_service"),
    ("production.migrate", "run_migration"),
    ("production.dns-change", "update_dns_record"),
    ("access.grant-permissions", "grant_role"),
    ("access.iam-change", "update_iam_policy"),
    ("exfiltration.external-upload", "upload_report"),
]


@pytest.mark.parametrize(("rule_id", "tool"), OVERSIGHT_CASES, ids=[c[0] for c in OVERSIGHT_CASES])
def test_oversight_rules_block_without_approval_and_allow_with_it(rule_id, tool):
    assert _decide(rule_id, tool=tool).effect == "deny", f"{rule_id} did not require oversight"
    assert _decide(rule_id, tool=tool, oversight=True).effect == "allow", \
        f"{rule_id} still blocked after a recorded human approval"


def test_env_file_rule_requires_oversight():
    assert _decide("secrets.env-file-read", args={"path": "/app/.env"}).effect == "deny"
    assert _decide("secrets.env-file-read", args={"path": "/app/.env"},
                   oversight=True).effect == "allow"
    assert _decide("secrets.env-file-read", args={"path": "/app/environment.py"}).effect == "allow"


def test_select_star_rule_requires_oversight_only_when_unbounded():
    r = "exfiltration.select-star-no-limit"
    assert _decide(r, args={"q": "SELECT * FROM customers"}).effect == "deny"
    assert _decide(r, args={"q": "SELECT * FROM customers", "db": "prod"}).effect == "deny"
    assert _decide(r, args={"q": "SELECT * FROM customers LIMIT 10"}).effect == "allow"
    assert _decide(r, args={"q": "SELECT id FROM customers"}).effect == "allow"


def test_limit_rules_allow_up_to_the_cap_then_block():
    policy = Policy.from_dict({"rules": rulesets.resolve(["blast-radius.email-cap"])})
    state = SessionState()
    ctx = {"tool": "send_email", "match_text": "{}"}
    effects = [policy.decide("tool_call", ctx, state).effect for _ in range(27)]
    assert effects[:25] == ["allow"] * 25
    assert effects[25:] == ["deny", "deny"]


# --------------------------------------------------------------------------------------
# Catalogue integrity
# --------------------------------------------------------------------------------------

def test_every_catalogue_rule_is_valid_and_loadable():
    """A malformed catalogue rule would only surface when a user enabled that pack."""
    policy = load_policy({"use": rulesets.pack_ids()})
    assert len(policy.rules) == len(rulesets.all_rules())


def test_every_rule_has_a_unique_id_a_reason_and_a_note():
    rules = rulesets.all_rules()
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule id in the catalogue"
    for r in rules:
        assert r["id"].startswith(r["pack"] + "."), f"{r['id']} is not namespaced to its pack"
        assert r.get("reason"), f"{r['id']} has no reason, so a denial would be unexplained"
        assert r.get("note"), f"{r['id']} has no false-positive note"
        assert r["effect"] in ("deny", "require_oversight", "limit")
        if r["effect"] == "limit":
            assert isinstance(r.get("max_per_session"), int)


def test_every_regex_in_the_catalogue_compiles():
    import re
    for r in rulesets.all_rules():
        if r.get("arg_contains"):
            re.compile(r["arg_contains"])


def test_catalogue_notes_are_stripped_before_reaching_the_engine():
    """`note` is documentation. It must not leak into the policy, which is hashed into the
    signed session-start record."""
    for rule in rulesets.resolve(["destructive"]):
        assert "note" not in rule
        assert "pack" not in rule


def test_the_policy_id_is_stable_for_the_same_enabled_packs():
    """The policy is committed into the signed chain, so the same configuration must hash
    identically across runs and machines."""
    a = load_policy({"use": ["destructive", "secrets"]}).policy_id()
    b = load_policy({"use": ["destructive", "secrets"]}).policy_id()
    assert a == b
    assert load_policy({"use": ["destructive"]}).policy_id() != a


# --------------------------------------------------------------------------------------
# Selecting rules
# --------------------------------------------------------------------------------------

def test_a_single_rule_can_be_enabled_without_its_pack():
    policy = load_policy({"use": ["secrets.aws-access-key"]})
    assert [r.id for r in policy.rules] == ["secrets.aws-access-key"]


def test_packs_and_single_rules_and_custom_rules_combine():
    policy = load_policy({
        "use": ["destructive", "money.refund"],
        "rules": [{"id": "custom.mine", "effect": "deny", "tool": "zzz_*"}],
    })
    ids = [r.id for r in policy.rules]
    assert "destructive.drop-tools" in ids
    assert "money.refund" in ids
    assert ids[-1] == "custom.mine", "custom rules come after the prebuilt ones"


def test_duplicate_selections_are_deduplicated():
    policy = load_policy({"use": ["destructive", "destructive.drop-tools", "destructive"]})
    ids = [r.id for r in policy.rules]
    assert len(ids) == len(set(ids))


def test_an_unknown_pack_or_rule_name_is_rejected_not_skipped():
    """A typo would otherwise leave the operator believing a guardrail is enabled."""
    for bad in ["destrutive", "secrets.aws-key", "nonsense"]:
        with pytest.raises(PolicyConfigError, match="not a known rule pack or rule id"):
            load_policy({"use": [bad]})


def test_use_must_be_a_list():
    with pytest.raises(PolicyConfigError, match='"use" must be a list'):
        load_policy({"use": {"packs": ["destructive"]}})


def test_no_pack_is_enabled_by_default():
    """An upgrade must never start blocking an agent's actions on its own."""
    assert load_policy({"rules": []}).rules == []
    assert load_policy({}).rules == []


# --------------------------------------------------------------------------------------
# End to end through the real recorder
# --------------------------------------------------------------------------------------

def test_enabling_a_pack_blocks_a_real_agent_and_records_the_denial():
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c,
                        policy=load_policy({"use": ["destructive", "money"]}))
    blocked = []
    with fr.session():
        fr.record_tool_call("get_user", {"id": 1}, "ok")
        for tool, args in [("delete_user", {"id": 1}), ("wire_transfer", {"amount": 100})]:
            try:
                fr.record_tool_call(tool, args, "ok")
            except PolicyViolation as e:
                blocked.append(e.rule_id)

    assert blocked == ["destructive.delete-tools", "money.wire-transfer"]
    s = c.get(f"/v1/streams/{prov['stream_id']}/summary",
              headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    assert s["totals"]["policy_denials"] == 2


# --------------------------------------------------------------------------------------
# The CLI surface
# --------------------------------------------------------------------------------------

def _bundle_with_tools(tmp_path):
    app = create_app(":memory:", anchor=LocalAnchor(), require_account=False)
    c = TestClient(app)
    prov = provision_stream("http://t", http=c)
    fr = FlightRecorder("http://t", prov["write_token"], prov["stream_id"], http=c)
    with fr.session():
        fr.record_tool_call("send_email", {"to": "a"}, "ok")
        fr.record_tool_call("delete_user", {"id": 1}, "ok")
    bundle = c.get(f"/v1/streams/{prov['stream_id']}/bundle",
                   headers={"Authorization": f"Bearer {prov['read_token']}"}).json()
    path = tmp_path / "b.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def test_pr_rules_lists_every_pack(capsys):
    from provenrail.cli import main
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    for pack in rulesets.pack_ids():
        assert pack in out
    assert "Nothing is enabled by default" in out


def test_pr_rules_json_is_machine_readable(capsys):
    from provenrail.cli import main
    assert main(["rules", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data["packs"]) == set(rulesets.pack_ids())


def test_pr_rules_check_reports_matches_and_content_rules(tmp_path, capsys):
    from provenrail.cli import main
    path = _bundle_with_tools(tmp_path)
    assert main(["rules", "--check", str(path)]) == 0
    out = capsys.readouterr().out
    assert "MATCHES   destructive.delete-tools  ->  delete_user" in out
    assert "MATCHES   blast-radius.email-cap  ->  send_email" in out
    # Content rules cannot be judged from tool names; the output must say so, not
    # silently imply coverage.
    assert "cannot be checked from names alone" in out


def test_pr_rules_check_scopes_to_selected_packs(tmp_path, capsys):
    from provenrail.cli import main
    path = _bundle_with_tools(tmp_path)
    assert main(["rules", "--check", str(path), "--use", "money"]) == 0
    out = capsys.readouterr().out
    assert "destructive" not in out
    assert "No name-based rule matched" in out


def test_pr_rules_check_rejects_an_unknown_pack(tmp_path, capsys):
    from provenrail.cli import main
    path = _bundle_with_tools(tmp_path)
    assert main(["rules", "--check", str(path), "--use", "destrutive"]) == 2
    assert "not a known rule pack" in capsys.readouterr().out
