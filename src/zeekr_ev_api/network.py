import logging
from typing import Any

from requests import Request, Session
from . import const, zeekr_app_sig, zeekr_hmac

log = logging.getLogger(__name__)


def customPost(s: Session, url: str, body: dict | None = None) -> Any:
    """ Sends a signed POST request with HMAC authentication. """
    req = Request("POST", url, headers=const.DEFAULT_HEADERS, json=body)
    req = zeekr_hmac.generateHMAC(req, const.HMAC_ACCESS_KEY,
                                  const.HMAC_SECRET_KEY)

    prepped = s.prepare_request(req)
    resp = s.send(prepped)
    log.debug("------ HEADERS ------")
    log.debug(resp.headers)
    log.debug("------ RESPONSE ------")
    log.debug(resp.text)

    return resp.json()


def customGet(s: Session, url: str) -> Any:
    """ Sends a signed GET request with HMAC authentication. """
    req = Request("GET", url, headers=const.DEFAULT_HEADERS)
    req = zeekr_hmac.generateHMAC(req, const.HMAC_ACCESS_KEY,
                                  const.HMAC_SECRET_KEY)

    prepped = s.prepare_request(req)
    resp = s.send(prepped)
    log.debug("------ HEADERS ------")
    log.debug(resp.headers)
    log.debug("------ RESPONSE ------")
    log.debug(resp.text)

    return resp.json()


def appSignedPost(s: Session, url: str, body: str | None = None) -> Any:
    """ Sends a signed POST request with an app signature. """
    req = Request("POST", url, headers=const.LOGGED_IN_HEADERS, data=body)
    prepped = s.prepare_request(req)

    final = zeekr_app_sig.sign_request(prepped, const.PROD_SECRET)

    log.debug("--- Signed Request Details ---")
    log.debug(f"Method: {final.method}")
    log.debug(f"URL: {final.url}")
    log.debug("Headers:")
    for k, v in final.headers.items():
        log.debug(f"  {k}: {v}")
    log.debug(f"Body: {final.body or ''}")
    log.debug(f"\nX-SIGNATURE: {final.headers['X-SIGNATURE']}")

    resp = s.send(final)
    log.debug("------ HEADERS ------")
    log.debug(resp.headers)
    log.debug("------ RESPONSE ------")
    log.debug(resp.text)

    return resp.json()


def appSignedGet(s: Session, url: str, headers: dict | None = None) -> Any:
    """ Sends a signed GET request with an app signature. """
    req = Request("GET", url, headers=const.LOGGED_IN_HEADERS)
    if headers:
        req.headers.update(headers)
    prepped = s.prepare_request(req)

    final = zeekr_app_sig.sign_request(prepped, const.PROD_SECRET)
    resp = s.send(final)
    log.debug("------ HEADERS ------")
    log.debug(resp.headers)
    log.debug("------ RESPONSE ------")
    log.debug(resp.text)

    return resp.json()
