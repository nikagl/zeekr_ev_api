"""
Tests for zeekr_hmac.py
"""

import datetime
from unittest.mock import MagicMock
import pytest
from requests import Request

from zeekr_ev_api import zeekr_hmac


def test_hmac_sha256_base64():
    """Test hmac_sha256_base64"""
    data = "test data"
    key = "test key"
    # Expected value calculated independently
    expected = "RpV4jKlAFaJGQivhO72Wat5XGELvw6OSlr228jd1l/8="
    assert zeekr_hmac.hmac_sha256_base64(data, key) == expected


def test_get_canonical_path():
    """Test get_canonical_path"""
    assert zeekr_hmac.get_canonical_path(["a", "b", "c"]) == "/a/b/c"
    assert zeekr_hmac.get_canonical_path([]) == "/"
    assert zeekr_hmac.get_canonical_path([""]) == "/"


def test_parse_query_params():
    """Test parse_query_params"""
    assert zeekr_hmac.parse_query_params("a=1&b=2") == {"a": "1", "b": "2"}
    assert zeekr_hmac.parse_query_params("") == {}
    assert zeekr_hmac.parse_query_params("a=1") == {"a": "1"}
    assert zeekr_hmac.parse_query_params("a=1&b=") == {"a": "1", "b": ""}
    assert zeekr_hmac.parse_query_params("a=1&b") == {"a": "1"}


def test_get_canonical_query_string():
    """Test get_canonical_query_string"""
    assert zeekr_hmac.get_canonical_query_string({
        "a": "1",
        "b": "2"
    }) == "a=1&b=2"
    assert zeekr_hmac.get_canonical_query_string({
        "b": "2",
        "a": "1"
    }) == "a=1&b=2"
    assert zeekr_hmac.get_canonical_query_string({}) == ""
    assert zeekr_hmac.get_canonical_query_string({"a": "1"}) == "a=1"
    # Test case-insensitive sorting
    assert zeekr_hmac.get_canonical_query_string({
        "B": "2",
        "a": "1"
    }) == "a=1&B=2"


def test_get_request_body_content():
    """Test get_request_body_content"""
    assert zeekr_hmac.get_request_body_content(b"test") == "test"
    assert zeekr_hmac.get_request_body_content("test") == "test"
    assert zeekr_hmac.get_request_body_content(None) == ""


def test_generateHMAC(mocker):
    """Test generateHMAC"""
    # Mock to have a predictable date header
    mocker.patch('zeekr_ev_api.zeekr_hmac._get_gmt_date',
                 return_value="Thursday, 20 Nov 2025 04:42:38 GMT")

    req = Request(
        "POST",
        "https://gateway-pub-hw-em-sg.zeekrlife.com/overseas-app/protocol/service/getProtocol",
        data='{"country":"AU"}',
    )
    access_key = "673ca869165e446eb5356b8b5ae26938"
    secret_key = "dhn8kcmr903f39ccdd9f458f893bb6fac5e16968"

    signed_req = zeekr_hmac.generateHMAC(req, access_key, secret_key)

    assert signed_req.headers["X-HMAC-ALGORITHM"] == "hmac-sha256"
    assert signed_req.headers["X-HMAC-ACCESS-KEY"] == access_key
    assert signed_req.headers["X-DATE"] == "Thursday, 20 Nov 2025 04:42:38 GMT"

    # Expected values calculated independently for the given data
    expected_signature = "S1fKhGeiMZMdEPxM0+YEVLR7Cw48oV+j7q/CsHivMSk="
    expected_digest = "lvSSQu3t9v7eUjtwcK5htLyPC0Lu+iPEmeO9+Vox+zo="

    assert signed_req.headers["X-HMAC-SIGNATURE"] == expected_signature
    assert signed_req.headers["X-HMAC-DIGEST"] == expected_digest
