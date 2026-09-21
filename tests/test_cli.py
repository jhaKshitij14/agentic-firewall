import pytest

from app.firewall.authentication import Authenticator
from app.main import main
from app.storage.database import Database


def test_create_user_cli(tmp_path, monkeypatch, capsys):
    db_path = str(tmp_path / "fw.db")
    monkeypatch.setenv("FIREWALL_DB_PATH", db_path)
    assert main(["create-user", "alice", "analyst"]) == 0
    out = capsys.readouterr().out
    key = next(line.split(": ", 1)[1].strip() for line in out.splitlines() if line.startswith("api_key"))
    sid, session = Authenticator(Database(db_path)).login("alice", key)
    assert session.role == "analyst"
    assert main(["create-user", "alice", "analyst"]) == 2  # duplicate
    assert main(["create-user", "bob", "no-such-role"]) == 2


def test_upstream_env_selection(monkeypatch):
    from app.main import _upstream_from_env
    from app.mcp.client import InProcessUpstream, StdioMCPUpstream

    monkeypatch.delenv("FIREWALL_UPSTREAM", raising=False)
    assert isinstance(_upstream_from_env(), InProcessUpstream)
    monkeypatch.setenv("FIREWALL_UPSTREAM", "stdio")
    assert isinstance(_upstream_from_env(), StdioMCPUpstream)
    monkeypatch.setenv("FIREWALL_UPSTREAM", "bogus")
    with pytest.raises(ValueError):
        _upstream_from_env()
