"""Tests for the optional official Gemini extraction path (no network by default)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from gemini_extractor import (
    GeminiConfigurationError,
    GeminiExtractor,
    GeminiResponseError,
)

FIXTURE = b"\x89PNG\r\n\x1a\nsynthetic-image-bytes"

VALID = json.dumps({
    "observations": [{
        "visible_resource_ids": ["support_9001"],
        "visible_aliases": [],
        "identifiers": {
            "emails": ["subject@example.com"],
            "phones": [],
            "user_ids": ["user_test"],
            "names": ["Test Subject"],
        },
        "visible_timestamps": ["2026-06-05"],
        "record_type": "Ticket",
        "visible_controls": {},
        "visible_text": "Ticket support_9001 Test Subject subject@example.com user_test 2026-06-05",
        "confidence": 0.99,
        "limitations": None,
    }]
})


class FakeResponse:
    def __init__(self, text: str):
        self.text = text
        self.usage_metadata = SimpleNamespace(
            prompt_token_count=10,
            candidates_token_count=5,
            total_token_count=15,
        )


class FakeModels:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def generate_content(self, **kwargs):
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return FakeResponse(response)


class FakeClient:
    def __init__(self, responses):
        self.models = FakeModels(responses)


def write_image(tmp_path):
    path = tmp_path / "image.png"
    path.write_bytes(FIXTURE)
    return path


def test_missing_api_key_is_explicit(monkeypatch, tmp_path):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    extractor = GeminiExtractor(client=None, cache_dir=tmp_path / "cache")
    with pytest.raises(GeminiConfigurationError) as error:
        extractor.extract_image(write_image(tmp_path), "evidence_test")
    assert "GEMINI_API_KEY" in str(error.value)


def test_valid_response_and_cache_hit(tmp_path):
    client = FakeClient([VALID])
    extractor = GeminiExtractor(client=client, cache_dir=tmp_path / "cache")
    image = write_image(tmp_path)
    first = extractor.extract_image(image, "evidence_test")
    second = extractor.extract_image(image, "evidence_test")
    assert first.cached is False
    assert second.cached is True
    assert client.models.calls == 1
    assert first.observations[0]["visible_resource_ids"] == ["support_9001"]
    assert first.usage["total_token_count"] == 15
    assert second.observations == first.observations
    assert list((tmp_path / "cache").glob("*.json"))


def test_changed_image_invalidates_cache(tmp_path):
    client = FakeClient([VALID, VALID])
    extractor = GeminiExtractor(client=client, cache_dir=tmp_path / "cache")
    image = write_image(tmp_path)
    assert extractor.extract_image(image, "evidence_test").cached is False
    image.write_bytes(FIXTURE + b"-changed")
    assert extractor.extract_image(image, "evidence_test").cached is False
    assert client.models.calls == 2


def test_invalid_json_is_rejected(tmp_path):
    extractor = GeminiExtractor(
        client=FakeClient(["not-json"]), cache_dir=tmp_path / "cache"
    )
    with pytest.raises(GeminiResponseError):
        extractor.extract_image(write_image(tmp_path), "evidence_test")


def test_invalid_schema_is_rejected(tmp_path):
    invalid = json.dumps({"observations": [{"resource_id": "support_9001"}]})
    extractor = GeminiExtractor(
        client=FakeClient([invalid]), cache_dir=tmp_path / "cache"
    )
    with pytest.raises(GeminiResponseError):
        extractor.extract_image(write_image(tmp_path), "evidence_test")


def test_model_decided_fields_are_rejected(tmp_path):
    decided = json.dumps({"observations": [{
        "visible_text": "support_9001", "visible_resource_ids": ["support_9001"],
        "data_category": "SUPPORT_MESSAGE", "status": "PRESENT",
    }]})
    extractor = GeminiExtractor(client=FakeClient([decided]), cache_dir=tmp_path / "cache")
    with pytest.raises(GeminiResponseError):
        extractor.extract_image(write_image(tmp_path), "evidence_test")


def test_invented_identifier_is_rejected(tmp_path):
    invented = json.dumps({
        "observations": [{
            "visible_resource_ids": ["support_9001"],
            "visible_text": "support_9001 visible text",
            "identifiers": {"emails": ["invented@example.com"]},
        }]
    })
    extractor = GeminiExtractor(
        client=FakeClient([invented]), cache_dir=tmp_path / "cache"
    )
    with pytest.raises(GeminiResponseError):
        extractor.extract_image(write_image(tmp_path), "evidence_test")


def test_transient_error_is_retried(tmp_path):
    client = FakeClient([Exception("503 UNAVAILABLE"), VALID])
    extractor = GeminiExtractor(
        client=client, cache_dir=tmp_path / "cache", retry_sleep=lambda _: None
    )
    result = extractor.extract_image(write_image(tmp_path), "evidence_test")
    assert result.cached is False
    assert client.models.calls == 2


def test_key_is_redacted_from_errors(tmp_path):
    secret = "SECRET-TEST-KEY"
    client = FakeClient([Exception(f"failure with {secret}")])
    extractor = GeminiExtractor(
        api_key=secret, client=client, cache_dir=tmp_path / "cache",
        retry_sleep=lambda _: None,
    )
    with pytest.raises(GeminiResponseError) as error:
        extractor.extract_image(write_image(tmp_path), "evidence_test")
    assert secret not in str(error.value)
    assert "[REDACTED]" in str(error.value)


@pytest.mark.skipif(
    os.environ.get("RUN_GEMINI_LIVE") != "1" or not os.environ.get("GEMINI_API_KEY"),
    reason="live Gemini smoke test is opt-in and requires GEMINI_API_KEY",
)
def test_live_gemini_smoke():
    image = REPO_ROOT / "dataset" / "evidence" / "images" / "support_ticket_console_20260524.png"
    extractor = GeminiExtractor()
    result = extractor.extract_image(image, "evidence_28", use_cache=False)
    assert result.observations
    assert any("support_1034" in o.get("visible_resource_ids", []) for o in result.observations)
