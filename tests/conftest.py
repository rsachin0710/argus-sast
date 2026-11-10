import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).parent))  # for fake_llm


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Every test gets its own config/data dirs and no real API keys."""
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path / "argus-home"))
    monkeypatch.setenv("ARGUS_DISABLE_KEYRING", "1")
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path / "argus-home"


@pytest.fixture
def vuln_copy(tmp_path) -> Path:
    """A private copy of the vulnerable examples (tests may apply fixes to it)."""
    dest = tmp_path / "src"
    shutil.copytree(ROOT / "examples" / "vulnerable", dest)
    return dest


@pytest.fixture
def fake_client():
    from fake_llm import FakeProvider

    from argus.llm import LLMClient

    def make(**kw):
        return LLMClient(FakeProvider(**kw), None, 10_000, 4)

    return make
