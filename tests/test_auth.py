import pytest

from app.firewall.authentication import AuthError, Authenticator
from app.storage.database import Database
from attacks.harness import ManualClock


@pytest.fixture
def setup():
    clock = ManualClock()
    db = Database(":memory:")
    auth = Authenticator(db, clock=clock, session_ttl_seconds=600)
    auth.register_user("alice", "analyst", "alice-key-0123456789")
    return auth, db, clock


def test_login_and_validate(setup):
    auth, _, _ = setup
    sid, session = auth.login("alice", "alice-key-0123456789")
    assert session.user_id == "alice" and session.role == "analyst"
    assert auth.validate(sid).user_id == "alice"


@pytest.mark.parametrize("user,key", [("alice", "wrong-key-0123456789"), ("nobody", "alice-key-0123456789"), ("alice", ""), ("", ""), ("a b", "x")])
def test_bad_credentials_rejected_with_same_message(setup, user, key):
    auth, _, _ = setup
    with pytest.raises(AuthError, match="invalid credentials"):
        auth.login(user, key)


@pytest.mark.parametrize("forged", ["", "admin", "' OR 1=1 --", "A" * 43, "A" * 1000])
def test_forged_session_rejected(setup, forged):
    auth, _, _ = setup
    with pytest.raises(AuthError):
        auth.validate(forged)


def test_session_expires(setup):
    auth, _, clock = setup
    sid, _ = auth.login("alice", "alice-key-0123456789")
    clock.advance(599)
    auth.validate(sid)
    clock.advance(2)
    with pytest.raises(AuthError, match="expired"):
        auth.validate(sid)


def test_revoked_session_rejected(setup):
    auth, _, _ = setup
    sid, _ = auth.login("alice", "alice-key-0123456789")
    assert auth.revoke(sid)
    with pytest.raises(AuthError, match="revoked"):
        auth.validate(sid)


def test_raw_session_id_and_api_key_never_stored(setup):
    auth, db, _ = setup
    sid, _ = auth.login("alice", "alice-key-0123456789")
    dump = str(db._query("SELECT * FROM sessions")) + str(db._query("SELECT * FROM users"))
    assert sid not in dump
    assert "alice-key-0123456789" not in dump


def test_role_comes_from_users_table_not_client(setup):
    auth, db, _ = setup
    sid, _ = auth.login("alice", "alice-key-0123456789")
    db._write("UPDATE users SET role = 'admin' WHERE user_id = 'alice'")
    assert auth.validate(sid).role == "admin"  # role changes take effect on live sessions


def test_register_validation(setup):
    auth, _, _ = setup
    with pytest.raises(ValueError):
        auth.register_user("alice", "analyst", "another-key-0123456789")  # duplicate
    with pytest.raises(ValueError):
        auth.register_user("bad user!", "analyst", "another-key-0123456789")
    with pytest.raises(ValueError):
        auth.register_user("carol", "analyst", "short")


def test_sessions_are_unique(setup):
    auth, _, _ = setup
    ids = {auth.login("alice", "alice-key-0123456789")[0] for _ in range(20)}
    assert len(ids) == 20
