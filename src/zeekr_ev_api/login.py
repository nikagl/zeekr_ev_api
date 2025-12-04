import base64
import const
import network
import json
import sys
import zeekr_hmac

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from requests import Request, Session


# Global
s = Session()


def rsa_encrypt_password(plain_text, b64_pub_key_str):
    """
    Performs RSA/ECB/PKCS1Padding encryption and then MIME Base64 encoding,
    """
    print("--- Starting Encryption Process ---")
    try:
        # 1. Decode the Base64 Public Key
        key_bytes = base64.b64decode(b64_pub_key_str)
        print(f"Key bytes length: {len(key_bytes)} bytes")

        # 2. Generate the Public Key Object
        public_key = RSA.import_key(key_bytes)
        print("Public Key imported successfully.")

        # 3. Create the Cipher (RSA/ECB/PKCS1Padding)
        cipher = PKCS1_v1_5.new(public_key)

        # 4. Get Password Bytes (StandardCharsets.UTF_8)
        password_bytes = plain_text.encode("utf-8")
        print(f"Plain text bytes: {password_bytes}")

        # 5. Encrypt the Data (doFinal)
        encrypted_bytes = cipher.encrypt(password_bytes)
        print(f"Encrypted bytes length: {len(encrypted_bytes)} bytes")

        # 6. Base64 Encode the Encrypted Data
        encoded_string = base64.b64encode(encrypted_bytes).decode("utf-8")

        return encoded_string

    except ValueError as e:
        # Catch key import errors, invalid padding, or other cryptographic failures
        print(f"An error occurred: {e}")
        print(
            "Ensure the BASE64_PUBLIC_KEY is a valid, uncorrupted X.509/PKCS#8 encoded RSA public key."
        )
        return None
    except Exception as e:
        # Catch general exceptions
        print(f"An unexpected error occurred: {e}")
        return None


def doLoginRequest(username, password):
    encrypted_password = rsa_encrypt_password(password, const.PASSWORD_PUBLIC_KEY)
    if not encrypted_password:
        return

    request_data = {
        "code": "",
        "codeId": "",
        "email": username,
        "password": encrypted_password,
    }

    req = Request(
        "POST",
        f"{const.USERCENTER_HOST}{const.LOGIN_URL}",
        headers=const.DEFAULT_HEADERS,
        json=request_data,
    )
    new_req = zeekr_hmac.generateHMAC(req, const.HMAC_ACCESS_KEY, const.HMAC_SECRET_KEY)
    prepped = s.prepare_request(new_req)
    resp = s.send(prepped)
    print("------ RESPONSE HEADERS ------")
    print(resp.headers)
    print("------ RESPONSE BODY ------")
    print(resp.text)

    return resp.json()


def doLogin(username, password):
    # getURL
    urls = network.customGet(s, f"{const.APP_SERVER_HOST}{const.URL_URL}")
    found = False
    if not urls.get("success", False):
        print("Unable to fetch URL data, defaulting to SG (SEA)")
        found = True
    urlData = urls.get("data", [])
    for urlBlock in urlData:
        if urlBlock.get("countryCode", "").lower() == const.COUNTRY_CODE.lower():
            const.APP_SERVER_HOST = urlBlock.get("url", {}).get("appServerUrl", "")
            const.USERCENTER_HOST = urlBlock.get("url", {}).get("userCenterUrl", "")
            const.MESSAGE_HOST = urlBlock.get("url", {}).get("messageCoreUrl", "")
            const.REGION_CODE = urlBlock.get("regionCode", "SEA")
            found = True
            print("Found your country, updating URLs")
            break
    if not found:
        print(
            "Unable to find URLs for your Country Code - are you sure it's supported?"
        )

    if not const.APP_SERVER_HOST or not const.USERCENTER_HOST or not const.MESSAGE_HOST:
        print("URLs update but one or more were blank. Something went wrong.")
        sys.exit(0)

    # checkUser
    print("--- Check User ---")
    userCode = network.customPost(
        s,
        f"{const.USERCENTER_HOST}{const.CHECKUSER_URL}",
        {"email": username, "checkType": "1"},
    )

    loginData = {}

    if userCode.get("success", False):
        loginData = doLoginRequest(username, password)
    else:
        print("Check Failure")

    if not loginData or not loginData.get("success", False):
        print(f"Login failure: {loginData}")
        sys.exit(1)

    loginToken = loginData.get("data", {})
    if loginToken.get("tokenName", "") != "Authorization":
        print(f"Unknown Login Token Type: {loginToken}")
        sys.exit(1)

    const.DEFAULT_HEADERS["authorization"] = loginToken.get("tokenValue", "")

    if not const.DEFAULT_HEADERS["authorization"]:
        print(f"No token supplied !? {loginData}")
        sys.exit(1)

    # userInfo
    print("--- User Info ---")
    userInfo = network.customPost(s, f"{const.USERCENTER_HOST}{const.USERINFO_URL}")
    if not userInfo.get("success", False):
        print("Unable to fetch user info")
    else:
        userInfoData = userInfo.get("data", {})
        if userInfoData:
            print(
                f"You are {userInfoData.get('firstName', '')} {userInfoData.get('lastName', '')}. Welcome to Zeekr."
            )

    # getProtocol
    print("--- Get Protocol ---")
    protocol = network.customPost(
        s,
        f"{const.APP_SERVER_HOST}{const.PROTOCOL_URL}",
        {"country": const.COUNTRY_CODE},
    )
    if not protocol.get("success", False):
        print(f"Unable to get Protocol: {protocol}")

    # check Inbox
    print("--- Check Inbox ---")
    inbox = network.customGet(s, f"{const.APP_SERVER_HOST}{const.INBOX_URL}")
    if not inbox.get("success", False):
        print("Unable to fetch Inbox data")

    print("--- Get TSP Code ---")
    tspCodeBlock = network.customGet(
        s,
        f"{const.USERCENTER_HOST}{const.TSPCODE_URL}?tspClientId={const.DEFAULT_HEADERS.get('client-id', '')}",
    )
    if not tspCodeBlock.get("success", False):
        print(f"Unable to fetch TSP Code - Unable to continue\n{tspCodeBlock}")
        sys.exit(1)

    tspCode = tspCodeBlock.get("data", {}).get("code", None)
    if not tspCode:
        print(
            f"TSP Fetch was success but no code found - Unable to continue\n{tspCodeBlock}"
        )
        sys.exit(1)

    loginId = tspCodeBlock.get("data", {}).get("loginId", None)
    if not loginId:
        print("No LoginID extracted from TSP Code")

    # Update Language
    print("--- Update Language ---")
    updateLanguageBlock = network.customGet(
        s, f"{const.USERCENTER_HOST}{const.UPDATELANGUAGE_URL}?language=en"
    )
    if not updateLanguageBlock.get("success", False):
        print("Unable to update Language")

    # Sycn
    print("--- Sycn ---")
    sycn_body = {
        "appId": const.DEFAULT_HEADERS.get("msgappid", ""),
        # TODO: How to generate this?
        "deviceToken": "cK9QrDpUQEy6guAIDhHlat:APA91bGMRVYtR-kERoJXayOKnMI1lYgK2_ZUjTA1zVWlZ3HEb_YT-Ryxtpk_zkQLj4pD9OzJWo9bBS96qlySD0UoUIyXavrD5niuAuEhsk9UJ44T1WLiIIU",
        "platformType": 1,
        "receive": loginId,
        "region": "eu-central-1",
    }
    if loginId:
        network.customPost(s, f"{const.MESSAGE_HOST}{const.SYCN_URL}", sycn_body)

    bearer_body = {
        "identifier": tspCode,
        "identityType": 10,
        "loginDeviceId": "google-sdk_gphone64_x86_64-36-16",
        "loginDeviceJgId": "",
        "loginDeviceType": 1,
        "loginPhoneBrand": "google",
        "loginPhoneModel": "sdk_gphone64_x86_64",
        "loginSystem": "Android",
    }

    bearerLoginBlock = network.appSignedPost(
        s,
        f"{const.REGION_LOGIN_SERVERS[const.REGION_CODE]}{const.BEARERLOGIN_URL}",
        json.dumps(bearer_body, separators=(",", ":")),
    )
    if not bearerLoginBlock.get("success", False):
        print(f"Unable to Login - Unable to continue\n{bearerLoginBlock}")
        sys.exit(1)

    bearerLoginData = bearerLoginBlock.get("data", {})
    if not bearerLoginData or not bearerLoginData.get("accessToken", ""):
        print(
            f"Login was success but no code found - Unable to continue\n{bearerLoginData}"
        )
        sys.exit(1)

    const.LOGGED_IN_HEADERS["authorization"] = bearerLoginData.get("accessToken", "")
    # Are we ok not to have VIN here?


# TODO: Refresh Token & Detect Bearer Expiry
