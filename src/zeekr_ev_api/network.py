import const
import zeekr_app_sig
import zeekr_hmac
from requests import Request


def customPost(s, url, body=None):
    req = Request("POST", url, headers=const.DEFAULT_HEADERS, json=body)
    req = zeekr_hmac.generateHMAC(req, const.HMAC_ACCESS_KEY, const.HMAC_SECRET_KEY)

    prepped = s.prepare_request(req)
    resp = s.send(prepped)
    print("------ HEADERS ------")
    print(resp.headers)
    print("------ RESPONSE ------")
    print(resp.text)

    return resp.json()


def customGet(s, url):
    req = Request("GET", url, headers=const.DEFAULT_HEADERS)
    req = zeekr_hmac.generateHMAC(req, const.HMAC_ACCESS_KEY, const.HMAC_SECRET_KEY)

    prepped = s.prepare_request(req)
    resp = s.send(prepped)
    print("------ HEADERS ------")
    print(resp.headers)
    print("------ RESPONSE ------")
    print(resp.text)

    return resp.json()


def appSignedPost(s, url, body=None):
    req = Request("POST", url, headers=const.LOGGED_IN_HEADERS, data=body)
    prepped = s.prepare_request(req)

    final = zeekr_app_sig.sign_request(prepped, const.PROD_SECRET)

    print("--- Signed Request Details ---")
    print(f"Method: {final.method}")
    print(f"URL: {final.url}")
    print("Headers:")
    for k, v in final.headers.items():
        print(f"  {k}: {v}")
    print(f"Body: {final.body or ''}")
    print(f"\nX-SIGNATURE: {final.headers['X-SIGNATURE']}")

    resp = s.send(final)
    print("------ HEADERS ------")
    print(resp.headers)
    print("------ RESPONSE ------")
    print(resp.text)

    return resp.json()


def appSignedGet(s, url):
    req = Request("GET", url, headers=const.LOGGED_IN_HEADERS)
    prepped = s.prepare_request(req)

    final = zeekr_app_sig.sign_request(prepped, const.PROD_SECRET)
    resp = s.send(final)
    print("------ HEADERS ------")
    print(resp.headers)
    print("------ RESPONSE ------")
    print(resp.text)

    return resp.json()
