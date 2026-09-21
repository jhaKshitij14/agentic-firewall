import pytest

from app.firewall.authorization import Authorizer
from app.firewall.risk import RiskClassifier
from app.models.policies import Policy, RiskLevel, load_policy
from attacks.harness import POLICY_PATH

L, M, H, C = RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL


# ---- risk classification -------------------------------------------------------------------
@pytest.mark.parametrize(
    "name,expected",
    [
        ("get_stock_price", L), ("search_news", L), ("list_files", L), ("read_file", L),
        ("write_file", M), ("send_email", M), ("create_ticket", M), ("update-record", M),
        ("delete_file", H), ("drop_table", H), ("execute_trade", H), ("transfer_funds", H), ("kill_process", H),
        ("execute_command", C), ("run_shell", C), ("exec", C), ("runScript", C), ("executeCommand", C),
        ("bash", C), ("eval_code", C), ("run_command", C),
        ("get_and_delete_cache", H),  # most dangerous verb wins
        ("frobnicate", M),  # unknown defaults to MEDIUM
        ("get_command_history", L),  # 'command' alone isn't dangerous
    ],
)
def test_rule_based_risk(name, expected):
    assert RiskClassifier().classify(name) == expected


def test_override_wins():
    assert RiskClassifier({"get_stock_price": C}).classify("get_stock_price") == C


# ---- policy --------------------------------------------------------------------------------
def test_shipped_policy_loads():
    policy = load_policy(POLICY_PATH)
    assert policy.roles["admin"].max_risk == H
    assert policy.tool_risk["execute_command"] == C


def test_policy_rejects_typos_and_bad_values():
    with pytest.raises(Exception):
        Policy.model_validate({"roles": {"a": {"allowed_tool": ["x"]}}})  # typo'd key
    with pytest.raises(Exception):
        Policy.model_validate({"roles": {"a": {"max_risk": "EXTREME"}}})
    with pytest.raises(Exception):
        Policy.model_validate({"roles": {"a": {"allowed_tools": ["*"]}}})  # no wildcards
    with pytest.raises(Exception):
        Policy.model_validate({"roles": {}})


def test_policy_risk_names_case_insensitive():
    p = Policy.model_validate({"roles": {"a": {"max_risk": "high"}}, "tool_risk": {"x": "critical"}})
    assert p.roles["a"].max_risk == H and p.tool_risk["x"] == C


# ---- authorization -------------------------------------------------------------------------
@pytest.fixture
def authz():
    return Authorizer(load_policy(POLICY_PATH))


def test_analyst_allowed_and_denied(authz):
    assert authz.check("analyst", "search_news", L).allowed
    assert authz.check("analyst", "get_stock_price", L).allowed
    d = authz.check("analyst", "execute_trade", H)
    assert not d.allowed and "not permitted" in d.reason


def test_admin_allowed_but_not_critical(authz):
    assert authz.check("admin", "execute_trade", H).allowed
    assert not authz.check("admin", "execute_command", C).allowed


def test_unknown_role_denied(authz):
    assert not authz.check("intern", "search_news", L).allowed


def test_risk_cap_applies_even_if_allowlisted():
    policy = Policy.model_validate({"roles": {"r": {"allowed_tools": ["execute_command"], "max_risk": "HIGH"}}})
    d = Authorizer(policy).check("r", "execute_command", C)
    assert not d.allowed and "exceeds" in d.reason


def test_can_manage(authz):
    assert authz.can_manage("admin") and not authz.can_manage("analyst") and not authz.can_manage("ghost")


# ---- end to end ----------------------------------------------------------------------------
def test_e2e_analyst_vs_admin(env, run):
    ok = run(env.call("alice", "search_news", {"query": "markets"}))
    assert ok.allowed and ok.response and "headlines" in ok.response.text
    no = run(env.call("alice", "execute_trade", {"symbol": "TCS", "quantity": 1}))
    assert not no.allowed and no.stage == "authorization" and no.risk == "HIGH"
    assert env.server.calls_to("execute_trade") == 0
    yes = run(env.call("bob", "execute_trade", {"symbol": "TCS", "quantity": 1}))
    assert yes.allowed and "executed" in yes.response.text
