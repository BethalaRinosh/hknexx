import json

import pytest

from backend.investigator import (
    InvestigatorConfigurationError,
    InvestigatorProviderError,
    call_openai_compatible,
)


def test_offline_mode_fails_closed_without_network(monkeypatch):
    monkeypatch.setenv("LLM_OFFLINE", "1")
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:9/v1/chat/completions")
    monkeypatch.setenv("LLM_MODEL", "offline-test")

    def fail_network(*args, **kwargs):
        raise AssertionError("offline investigator attempted a network request")

    monkeypatch.setattr("backend.investigator.request.urlopen", fail_network)

    with pytest.raises(InvestigatorConfigurationError, match="offline mode"):
        call_openai_compatible([])


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_offline_mode_is_disabled_for_false_values(monkeypatch, value):
    monkeypatch.setenv("LLM_OFFLINE", value)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)

    with pytest.raises(InvestigatorConfigurationError, match="LLM_BASE_URL and LLM_MODEL"):
        call_openai_compatible([])


@pytest.mark.parametrize("url", ["file:///tmp/provider", "ftp://example.com/provider", "localhost:8080/provider"])
def test_provider_url_must_be_http_or_https(monkeypatch, url):
    monkeypatch.delenv("LLM_OFFLINE", raising=False)
    monkeypatch.setenv("LLM_BASE_URL", url)
    monkeypatch.setenv("LLM_MODEL", "test-model")

    with pytest.raises(InvestigatorConfigurationError, match="http or https"):
        call_openai_compatible([])


def test_provider_response_size_is_bounded(monkeypatch):
    monkeypatch.delenv("LLM_OFFLINE", raising=False)
    monkeypatch.setenv("LLM_BASE_URL", "http://provider.test/v1/chat/completions")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setenv("LLM_MAX_RESPONSE_BYTES", "16")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size=-1):
            assert size == 17
            return b"x" * 17

    monkeypatch.setattr("backend.investigator.request.urlopen", lambda *args, **kwargs: FakeResponse())

    with pytest.raises(InvestigatorProviderError, match="response too large"):
        call_openai_compatible([])


def test_provider_response_is_parsed_when_within_limit(monkeypatch):
    monkeypatch.delenv("LLM_OFFLINE", raising=False)
    monkeypatch.setenv("LLM_BASE_URL", "http://provider.test/v1/chat/completions")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setenv("LLM_MAX_RESPONSE_BYTES", "1024")

    payload = {"choices": [{"message": {"content": "{}"}}]}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size=-1):
            assert size == 1025
            return json.dumps(payload).encode()

    monkeypatch.setattr("backend.investigator.request.urlopen", lambda *args, **kwargs: FakeResponse())

    content, provider, model = call_openai_compatible([])
    assert content == "{}"
    assert provider == "openai-compatible"
    assert model == "test-model"
