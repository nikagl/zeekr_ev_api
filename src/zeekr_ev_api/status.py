import const
import network
import zeekr_app_sig


def getVehicleList(s):
    vehicleListBlock = network.appSignedGet(
        s,
        f"{const.REGION_LOGIN_SERVERS[const.REGION_CODE]}{const.VEHLIST_URL}?needSharedCar=true",
    )
    if not vehicleListBlock.get("success", False):
        print(f"Failed to get Vehicle List: {vehicleListBlock}")

    vehicleList = vehicleListBlock.get("data", [])
    if len(vehicleList) == 0:
        print("No Vehicles Found")

    for vehicle in vehicleList:
        print(
            f"Discovered your {const.CAR_MODELS.get(vehicle.get('appModelCode', 'UNKNOWN'), 'UNKNOWN')} with VIN {vehicle.get('vin', 'UNKNOWN')}, rego plates {vehicle.get('plateNo', 'UNKNOWN')}\n"
        )
        if not const.VIN and "vin" in vehicle:
            const.VIN = vehicle.get("vin", "UNKNOWN")
        # TODO: Somehow get this list of VINs into HA

    encrypted_vin = zeekr_app_sig.aes_encrypt(const.VIN, const.VIN_KEY, const.VIN_IV)
    const.LOGGED_IN_HEADERS["X-VIN"] = encrypted_vin

    vehicleStatusBlock = network.appSignedGet(
        s,
        f"{const.REGION_LOGIN_SERVERS[const.REGION_CODE]}{const.VEHICLESTATUS_URL}?latest=false&target=new",
    )
    if not vehicleStatusBlock.get("success", False):
        print(f"Failed to get Vehicle Status: {vehicleStatusBlock}")
    vehicleStatusData = vehicleStatusBlock.get("data", {})
    basicVehicleStatus = vehicleStatusData.get("basicVehicleStatus", {})
    if basicVehicleStatus:
        position = basicVehicleStatus.get("position", {})
        if position:
            print(
                f"Your car is located at {position.get('latitude', 'UNKNOWN')} x {position.get('longitude', 'UNKNOWN')}"
            )
    additionalVehicleStatus = vehicleStatusData.get("additionalVehicleStatus", {})
    if additionalVehicleStatus:
        electricVehicleStatus = additionalVehicleStatus.get("electricVehicleStatus", {})
        if electricVehicleStatus:
            print("Your car is currently:\n")
            print(f"Charging: {electricVehicleStatus.get('isCharging', 'UNKNOWN')}")
            print(f"Plugged in: {electricVehicleStatus.get('isPluggedIn', 'UNKNOWN')}")
            print(f"Battery %: {electricVehicleStatus.get('chargeLevel', 'UNKNOWN')}%")
        drivingSafetyStatus = additionalVehicleStatus.get("drivingSafetyStatus", {})
        if drivingSafetyStatus:
            print(
                f"Centrally locked: {bool(drivingSafetyStatus.get('centralLockingStatus', 'False'))}"
            )
        climateStatus = additionalVehicleStatus.get("climateStatus", {})
        if climateStatus:
            print(
                f"Interior Temperature: {climateStatus.get('interiorTemp', 'UNKNOWN')}C"
            )
