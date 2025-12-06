"""
Tests for client.py
"""
from zeekr_ev_api import const
import pytest
from requests import Session
from zeekr_ev_api.client import ZeekrClient, ZeekrException, Vehicle


@pytest.fixture
def client():
    """Fixture for ZeekrClient"""
    return ZeekrClient("test_user", "test_password")


def test_client_initialization(client: ZeekrClient):
    """Test ZeekrClient initialization"""
    assert client.username == "test_user"
    assert client.password == "test_password"
    assert client.country_code == "AU"
    assert isinstance(client.session, Session)
    assert client.logged_in is False
    assert client.auth_token is None
    assert client.user_info == {}
    assert client.vehicles == []


def test_login_success(client: ZeekrClient, mocker):
    """Test successful login"""
    const.PASSWORD_PUBLIC_KEY = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCBzg6+dwMVtGTNo8EPL+XFyz0OY0pMMo3HdRZGauuCSgISfVMkMmOhNEb2q9UfiQcEeOwVmOgts9VF4q0BJYrRNGQaPkLybwkWsx1JmbBRcr3qq+WWhqq8xQFksfn8KeXmwgVMFX+bzup43LE0vy0yyb+SuQ9FBBGuE1d/BfHHpQIDAQAB'

    # Mock all network calls
    mocker.patch('zeekr_ev_api.network.customGet',
                 return_value={
                     "success":
                     True,
                     "data": [{
                         "countryCode": "AU",
                         "url": {
                             "appServerUrl": "https://app.zeekr.eu",
                             "userCenterUrl": "https://user.zeekr.eu",
                             "messageCoreUrl": "https://msg.zeekr.eu"
                         },
                         "regionCode": "EU"
                     }]
                 })
    mocker.patch('zeekr_ev_api.network.customPost',
                 return_value={
                     "success": True,
                     "data": {}
                 })
    mocker.patch('requests.sessions.Session.send',
                 return_value=mocker.MagicMock(
                     json=lambda: {
                         "success": True,
                         "data": {
                             "tokenName": "Authorization",
                             "tokenValue": "test_token"
                         }
                     }))
    mocker.patch('zeekr_ev_api.network.appSignedPost',
                 return_value={
                     "success": True,
                     "data": {
                         "accessToken": "bearer_token"
                     }
                 })
    mocker.patch('zeekr_ev_api.client.ZeekrClient._get_tsp_code',
                 return_value=("tsp_code", "login_id"))

    client.login()

    assert client.logged_in is True
    assert client.auth_token == "test_token"
    assert client.bearer_token == "bearer_token"


def test_login_failure(client: ZeekrClient, mocker):
    """Test failed login"""
    mocker.patch('zeekr_ev_api.network.customGet',
                 return_value={"success": False})
    with pytest.raises(ZeekrException):
        client.login()


def test_get_vehicle_list(client: ZeekrClient, mocker):
    """Test get_vehicle_list"""
    client.logged_in = True
    client.region_login_server = "https://login.zeekr.eu"
    mock_response = {
        "success":
        True,
        "data": [
            {
                "vin": "VIN123",
                "appModelCode": "001",
                "plateNo": "PLATE1"
            },
            {
                "vin": "VIN456",
                "appModelCode": "009",
                "plateNo": "PLATE2"
            },
        ]
    }
    mocker.patch('zeekr_ev_api.network.appSignedGet',
                 return_value=mock_response)
    mocker.patch('zeekr_ev_api.const.CAR_MODELS', {
        "001": "Zeekr 001",
        "009": "Zeekr 009"
    })

    vehicles = client.get_vehicle_list()

    assert len(vehicles) == 2
    assert isinstance(vehicles[0], Vehicle)
    assert vehicles[0].vin == "VIN123"


def test_get_vehicle_status(client: ZeekrClient, mocker):
    """Test get_vehicle_status"""
    client.logged_in = True
    client.region_login_server = "https://login.zeekr.eu"
    mock_response = {"success": True, "data": {"soc": 80}}
    mocker.patch('zeekr_ev_api.network.appSignedGet',
                 return_value=mock_response)
    mocker.patch('zeekr_ev_api.zeekr_app_sig.aes_encrypt',
                 return_value="encrypted_vin")
    mocker.patch('zeekr_ev_api.const.VIN_KEY',
                 '12345678901234567890123456789012')
    mocker.patch('zeekr_ev_api.const.VIN_IV', '1234567890123456')

    status = client.get_vehicle_status("VIN123")

    assert status == {"soc": 80}


def test_vehicle_class(client: ZeekrClient, mocker):
    """Test Vehicle class"""
    mocker.patch('zeekr_ev_api.const.CAR_MODELS', {"001": "Zeekr 001"})
    vehicle = Vehicle(client, "VIN123", {
        "appModelCode": "001",
        "plateNo": "PLATE1"
    })

    assert repr(vehicle) == "<Vehicle VIN123>"

    mocker.patch.object(client, 'get_vehicle_status', return_value={"soc": 90})
    status = vehicle.get_status()
    assert status == {"soc": 90}
    client.get_vehicle_status.assert_called_once_with("VIN123")
