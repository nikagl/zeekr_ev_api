"""
Tests for zeekr_app_sig.py
"""

import pytest
from requests import PreparedRequest

from zeekr_ev_api import zeekr_app_sig, const


def test_validate_header():
    """Test validate_header"""
    # Allowed header
    assert zeekr_app_sig.validate_header("x-app-id", "some_id") is True
    # Disallowed header
    assert zeekr_app_sig.validate_header("x-disallowed", "some_value") is False
    # x-vin must have a value
    assert zeekr_app_sig.validate_header("x-vin", "") is False
    assert zeekr_app_sig.validate_header("x-vin", "some_vin") is True
    # authorization must have a value
    assert zeekr_app_sig.validate_header("authorization", "") is False
    assert zeekr_app_sig.validate_header("authorization", "some_token") is True


def test_map_entry_to_dict_string():
    """Test map_entry_to_dict_string"""
    sb_list = []
    zeekr_app_sig.map_entry_to_dict_string("Content-Type", "application/json",
                                           sb_list)
    assert sb_list == ["content-type:application/json\n"]


def test_map_entry_to_query_string():
    """Test map_entry_to_query_string"""
    sb_list = []
    zeekr_app_sig.map_entry_to_query_string("a", "1", sb_list)
    assert sb_list == ["a=1"]
    zeekr_app_sig.map_entry_to_query_string("b", "2", sb_list)
    assert sb_list == ["a=1", "&", "b=2"]


def test_calculate_sig(mocker):
    """Test calculate_sig"""
    req = PreparedRequest()
    req.method = "GET"
    req.url = "https://example.com/api/test?a=1"
    req.headers = {
        "x-app-id": "test_app",
        "Content-Type": "application/json",
        "X-API-SIGNATURE-NONCE": "test_nonce",
        "X-TIMESTAMP": "1672531200000",
    }
    secret = "test_secret"

    signature = zeekr_app_sig.calculate_sig(req, secret)
    assert isinstance(signature, str)
    # A more thorough test would compare against a known-good signature
    # assert signature == "expected_signature"


def test_sign_request():
    """Test sign_request"""
    req = PreparedRequest()
    req.method = "GET"
    req.url = "https://example.com/api/test?a=1"
    req.headers = {
        "x-app-id": "test_app",
        "Content-Type": "application/json",
    }
    secret = "test_secret"

    signed_req = zeekr_app_sig.sign_request(req, secret)

    assert "X-API-SIGNATURE-NONCE" in signed_req.headers
    assert "X-TIMESTAMP" in signed_req.headers
    assert "X-SIGNATURE" in signed_req.headers
    assert isinstance(signed_req.headers["X-SIGNATURE"], str)
