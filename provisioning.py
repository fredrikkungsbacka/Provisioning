# $language = "Python3"
# $interface = "1.0"

""" Provisioning, upgrade, reconfiguration and reports of Cisco network devices via Vandyke SecureCRT and integration with other systems """

def get_secrets(secretsfile: str, secretskeyfile: str) -> dict:
  """ reads and decrypt secrets file """
  from cryptography.fernet import Fernet
  import json

  # read decoding key
  with open(secretskeyfile, "rb") as key_file:
    key = key_file.read()
    fernet = Fernet(key)

  # read file and return decoded values
  with open(secretsfile, "rb") as enc_file:
    try:
      data = json.loads(fernet.decrypt(enc_file.read()).decode())
    except (OSError, json.decoder.JSONDecodeError):
      return {"status": "error"}

  # verify dict
  if data.get("Header") is not None:
    # the file is readable
    data.pop("Header", None)
    data["secrets"]["status"] = "success"
    return data["secrets"] # type: ignore[no-any-return]
  # cannot read file content
  return {"status": "error"}

def get_model(modelsfile: str, crt_tab_object: object) -> dict:
  """ read modelsfile and compare output to detect model number and return corresponding dict """

  data = read_jsonfile(modelsfile)
  if data["status"] == "error":
    return {"status": "error"}

  models = list(data.keys()) # extract keys/model numbers
  command = ["sh ver | inc Model [nN]umber"] # command to run

  # serial
  crt_tab_object.Screen.Send(command[0] + chr(13))
  output = crt_tab_object.Screen.WaitForStrings(models, 30)
  if output != 0:
    # model found
    modelno = models[output-1]
    data[modelno]["status"] = "success"
    data[modelno]["model"] = modelno
    return data[modelno] # type: ignore[no-any-return]

  # model not found
  return {"status": "nomatch"}

def read_jsonfile(filename: str) -> dict:
  """ read json file validate and return dict """
  import json

  # read file and return values
  with open(filename, "r", encoding="LATIN-1") as json_file:
    try:
      data: dict = json.load(json_file)
    except (OSError, json.decoder.JSONDecodeError):
      return {"status": "error"}

  # verify dict
  if data.get("Header") is not None:
    # the file is readable
    data.pop("Header", None)
    data["status"] = "success"
    return data
  # cannot read file content
  return {"status": "error"}

def get_version(crt_tab_object: object) -> dict:
  """ get running version and convert it """
  import re

  for _ in range(3):
    # find the ios version
    crt_tab_object.Screen.Send(r"sh ver | inc Cisco IOS Software,|Cisco IOS XE Software," + chr(13))
    if crt_tab_object.Screen.WaitForString("Version"):
      result = crt_tab_object.Screen.ReadString(chr(13))
      # find string and break it up
      version = re.search(r"(([1-9]{2}.[0-9]{1,2})((\([1-9]{1,2}\))|.)[0-9a-zA-Z]{1,4})", result) # https://regexr.com/5pj42
      if version:
        # respond with version as string
        flatversion = version[0].replace("(", ".").replace(")", ".")
        return {
          "status": "success",
          "version": flatversion
        }
  # respond with error
  return {"status": "error"}

def get_cluster(model: dict, crt_tab_object: object) -> dict:
  """ catch device stack and active members """

  # command to run
  command = ["sh switch stack-ports | inc Ok|OK"]

  if model["stackwise"] is True:
    # serial
    crt_tab_object.Screen.Send(command[0] + chr(13))
    crt_tab_object.Screen.WaitForString(command[0])
    output_serial = crt_tab_object.Screen.ReadString("#")
    output = output_serial
  else:
    # is not capable of stackwise
    output = ""

  # split output and remove unwanted rows
  row = output.split(chr(13))
  if len(row[0]) == 0:
    # remove first row if empty
    row.pop(0)
  if len(row) != 0:
    # remove last row if not empty list
    row.pop(len(row)-1)

  # create list of prefixes
  prefixes = {}
  prefixes_a = []
  prefixes_m = []
  prefixes_t = []
  if len(row) >= 2:
    # is member of a cluster
    for cluster_member in row:
      if "Ok" in cluster_member or "OK" in cluster_member: # at least one port must be active
        # access
        if model["interfaces"]["access"] is not False:
          prefix_a = model["interfaces"]["access"]["prefix"][:2]
          suffix_a = model["interfaces"]["access"]["prefix"][3:]
          prefixes_a.append(prefix_a + cluster_member[:6].strip() + suffix_a)
        # multigig
        if model["interfaces"]["multigig"] is not False:
          prefix_m = model["interfaces"]["multigig"]["prefix"][:2]
          suffix_m = model["interfaces"]["multigig"]["prefix"][3:]
          prefixes_m.append(prefix_m + cluster_member[:6].strip() + suffix_m)
        # trunk
        if model["interfaces"]["trunk"] is not False:
          prefix_t = model["interfaces"]["trunk"]["prefix"][:2]
          suffix_t = model["interfaces"]["trunk"]["prefix"][3:]
          prefixes_t.append(prefix_t + cluster_member[:6].strip() + suffix_t)
    # assign values
    prefixes["access"] = prefixes_a
    prefixes["multigig"] = prefixes_m
    prefixes["trunk"] = prefixes_t
  else:
    # not member of cluster
    # access
    if model["interfaces"]["access"] is not False:
      prefixes["access"] = [model["interfaces"]["access"]["prefix"]]
    # multigig
    if model["interfaces"]["multigig"] is not False:
      prefixes["multigig"] = [model["interfaces"]["multigig"]["prefix"]]
    # trunk
    if model["interfaces"]["trunk"] is not False:
      prefixes["trunk"] = [model["interfaces"]["trunk"]["prefix"]]

  # finishing
  prefixes["status"] = "success" # type: ignore[assignment]
  return prefixes

def put_personal_settings(personalsettingsfile: str, personalsettings: dict) -> dict:
  """ write new personal settings file """
  import json

  # if header is missing create it
  if personalsettings.get("Header") is None:
    personalsettings["Header"] = {
      "name": "Cisco Provisioning Script",
      "description": "Personal settings file to main Python script"
    }

  # remove result key
  personalsettings.pop("status", None)

  # open file and write it
  with open(personalsettingsfile, "w", encoding="UTF-8") as json_file:
    try:
      json_file.write(json.dumps(personalsettings, indent=2))
    except OSError:
      return {"status": "error"}

  # finished
  return {"status": "success"}

def ise_find_device_by_name(hostname: str, secret: dict, settings: dict) -> dict:
  """ return if name exist or not from ise """
  import requests
  from requests.auth import HTTPBasicAuth

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }

  # query api
  url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/networkdevice?filter=name.EQ." + hostname
  try:
    response = requests.get(url, auth = HTTPBasicAuth(secret["ise"]["username"], secret["ise"]["password"]), verify = settings["ISE"]["PAN"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  data = response.json()
  status = response.status_code
  response.close()

  # return result
  if status == 200:
    if data["SearchResult"]["total"] == 1:
      return {
        "status": "success",
        "result": True
      }
    return {
      "status": "success",
      "result": False
    }
  return {"status": "error"}

def ise_find_device_by_ip(ipaddress: str, secret: dict, settings: dict) -> dict:
  """ return if ip exist or not from ise """
  import requests
  from requests.auth import HTTPBasicAuth

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }

  # query api
  url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/networkdevice?filter=ipaddress.EQ." + ipaddress
  try:
    response = requests.get(url, auth = HTTPBasicAuth(secret["ise"]["username"], secret["ise"]["password"]), verify = settings["ISE"]["PAN"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  data = response.json()
  status = response.status_code
  response.close()

  # return result
  if status == 200:
    if data["SearchResult"]["total"] == 1:
      return {
        "status": "success",
        "result": True,
        "name": data["SearchResult"]["resources"][0]["name"]
      }
    return {
      "status": "success",
      "result": False
    }
  return {"status": "error"}

def ise_create_device(ipaddress: str, hostname: str, secret: dict, settings: dict, org: str) -> dict:
  """ create device in ise """
  import requests
  from requests.auth import HTTPBasicAuth

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }

  payload_kommun = {
    "NetworkDevice": {
      "name": hostname,
      "authenticationSettings": {
        "networkProtocol": "RADIUS",
        "radiusSharedSecret": secret["radius"],
        "enableKeyWrap": False,
        "dtlsRequired": False,
        "keyInputFormat": "ASCII",
        "enableMultiSecret": False
      },
      "snmpsettings": {
        "version": "ONE",
        "roCommunity": secret["ise_snmp"],
        "pollingInterval": 600,
        "linkTrapQuery": True,
        "macTrapQuery": True,
        "originatingPolicyServicesNode": "Auto"
      },
      "tacacsSettings": {
        "sharedSecret": secret["tacacs"],
        "connectModeOptions": "OFF",
        "previousSharedSecret": secret["tacacs"],
        "previousSharedSecretExpiry": 0
      },
      "profileName": "Cisco",
      "coaPort": 1700,
      "NetworkDeviceIPList": [
        {
        "ipaddress": ipaddress,
        "mask": 32
        }
      ],
      "NetworkDeviceGroupList": [
        "Device Type#All Device Types#Cisco IOS",
        "IPSEC#Is IPSEC Device#No",
        "Location#All Locations#Kommun",
        "Status#All status"
      ]
    }
  }

  payload_bredband = {
    "NetworkDevice": {
      "name": hostname,
      "tacacsSettings": {
        "sharedSecret": secret["tacacs_kbn"],
        "connectModeOptions": "OFF",
        "previousSharedSecret": secret["tacacs_kbn"],
        "previousSharedSecretExpiry": 0
      },
      "profileName": "Cisco",
      "coaPort": 1700,
      "NetworkDeviceIPList": [
        {
        "ipaddress": ipaddress,
        "mask": 32
        }
      ],
      "NetworkDeviceGroupList": [
        "Device Type#All Device Types#Cisco IOS",
        "IPSEC#Is IPSEC Device#No",
        "Location#All Locations#KBN",
        "Status#All status"
      ]
    }
  }

  if org == "Kommun":
    payload = payload_kommun
  elif org == "Bredband":
    payload = payload_bredband

  # query api
  url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/networkdevice"
  try:
    response = requests.post(url, json = payload, auth = HTTPBasicAuth(secret["ise"]["username"], secret["ise"]["password"]), verify = settings["ISE"]["PAN"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  status = response.status_code
  response.close()

  # return result
  if status == 201:
    return {"status": "success"}
  return {"status": "error"}

def ise_delete_device(ipaddress: str, secret: dict, settings: dict) -> dict:
  """ delete device from ise """
  import requests
  from requests.auth import HTTPBasicAuth

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }

  # get id of the network device
  url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/networkdevice?filter=ipaddress.EQ." + ipaddress
  try:
    response = requests.get(url, auth = HTTPBasicAuth(secret["ise"]["username"], secret["ise"]["password"]), verify = settings["ISE"]["PAN"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  data = response.json()
  status = response.status_code
  response.close()

  # delete network device based on id
  try:
    url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/networkdevice/" + data["SearchResult"]["resources"][0]["id"]
  except IndexError:
    # device does not exist
    return {"status": "error"}
  try:
    response = requests.delete(url, auth = HTTPBasicAuth(secret["ise"]["username"], secret["ise"]["password"]), verify = settings["ISE"]["PAN"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  status = response.status_code
  response.close()

  # return result
  if status == 204:
    return {"status": "success"}
  return {"status": "error"}

def ise_update_endpoint(macaddress: str, endpoint_group: str, endpoint_profile: str, secret: dict, settings: dict) -> dict:
  """ return if endpoint exist or not in ise """
  import requests
  from requests.auth import HTTPBasicAuth

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }

  # search for endpoint
  url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/endpoint?filter=mac.EQ." + macaddress
  try:
    response = requests.get(url, auth = HTTPBasicAuth(secret["ise"]["username"], secret["ise"]["password"]), verify = settings["ISE"]["PAN"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  data = response.json()
  status = response.status_code
  response.close()

  if status == 200:
    # proceed if endpoint exist
    if data["SearchResult"]["total"] == 1:

      # endpoint is found, get endpoint id
      ep_id = data["SearchResult"]["resources"][0]["id"]
      url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/endpoint/" + ep_id
      try:
        response = requests.get(url, auth = HTTPBasicAuth(secret["ise"]["username"], secret["ise"]["password"]), verify = settings["ISE"]["PAN"]["verifycert"], headers = headers, timeout = 30)
      except requests.exceptions.Timeout:
        return {"status": "error"}
      response.keep_alive = False
      data = response.json()
      status = response.status_code
      response.close()

      # edit settings
      # endpoint group
      data["ERSEndPoint"]["staticGroupAssignment"] = True
      data["ERSEndPoint"]["groupId"] = endpoint_group
      if endpoint_profile != "":
        # endpoint profile
        data["ERSEndPoint"]["staticProfileAssignment"] = True
        data["ERSEndPoint"]["profileId"] = endpoint_profile

      # do the update
      url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/endpoint/" + ep_id
      try:
        response = requests.put(url, json = data, auth = HTTPBasicAuth(secret["ise"]["username"], secret["ise"]["password"]), verify = settings["ISE"]["PAN"]["verifycert"], headers = headers, timeout = 30)
      except requests.exceptions.Timeout:
        return {"status": "error"}
      response.keep_alive = False
      status = response.status_code
      response.close()

      # success
      return {"status": "success"}
    # endpoint not found
    return {"status": "not found"}
  # something went wrong
  return {"status": "error"}

def crt_box_yes_no(in_message: str, in_title: str) -> bool:
  """ ok/cancel button """

  result = crt_object.Dialog.MessageBox(str(in_message), in_title, ICON_INFO | BUTTON_CANCEL | DEFBUTTON2 ) # type: ignore[name-defined] # pylint: disable=undefined-variable

  if result == IDOK: # type: ignore[name-defined] # pylint: disable=undefined-variable
    # ok button
    return True
  if result == IDCANCEL: # type: ignore[name-defined] # pylint: disable=undefined-variable
    # cancel button
    return False

  # finished
  return False

def crt_box_message(in_message: str, in_title: str, in_icon: str) -> None:
  """ ok button """

  if in_icon == "Info":
    icon = ICON_INFO # type: ignore[name-defined] # pylint: disable=undefined-variable
  elif in_icon == "Warn":
    icon = ICON_WARN # type: ignore[name-defined] # pylint: disable=undefined-variable
  elif in_icon == "Stop":
    icon = ICON_STOP # type: ignore[name-defined] # pylint: disable=undefined-variable

  crt_object.Dialog.MessageBox(str(in_message), in_title, icon | BUTTON_OK ) # type: ignore[name-defined] # pylint: disable=undefined-variable

  # finished
  return None

def crt_box_input(in_message: str, in_title: str, in_default: str, password: bool = False) -> str:
  """ user input """

  result = crt_object.Dialog.Prompt(str(in_message), in_title, in_default, password)

  # finished
  return result # type: ignore[no-any-return]

def crt_box_dialogue(in_value: str, in_title: str, in_type: str) -> dict:
  """ verification of input """
  import re

  if in_type == "Interface":
    text = "Enter interface name:"
    title = "Interface name"
    value = in_value
    regex = r"^((([Tt]en|[Ff]orty|([Tt]wo){0,1}[Hh]undred|[Tt]wenty[Ff]ive){0,1}(([Gg]igabit|[Ff]ast){0,1}[Ee]thernet|[Gg]ig[Ee]))|(([TtGgFfHh][eFfiaowu])|[Ee]))([0-9]{1,3}(\/([0-9]{1,3})){0,3})$" # regexr.com/5ipll
    error = "Faulty interface name"
  elif in_type == "Vlan":
    text = "Enter vlan:"
    title = in_title
    value = ""
    regex = r"^([1-9]|([123][0-9])[0-9]?[0-9]?|[56789][0-9]?[0-9]?|4[0-9][0-9]?[0-4]?)$" # regexr.com/5kinh
    error = "Faulty vlan number"
  elif in_type == "IP":
    text = "Enter ipaddress of device:"
    title = "IP address"
    value = ""
    regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" # regexr.com/5ke5o
    error = "Wrong IP address"
  elif in_type == "Inventory":
    text = "Enter device number:"
    title = "Device Number"
    value = in_value
    regex = "^[0-9]{4}$" # four digits
    error = "Faulty device number"
  elif in_type == "Site":
    text = "Enter site name:\nExample " + chr(34) + "Stadshuset" + chr(34)
    title = "Site name"
    value = in_value
    regex = r"^[A-Za-z0-9-]+$" # regexr.com/5ke61
    error = "Faulty site name"
  elif in_type == "Location":
    text = "Enter location address:"
    title = "Location"
    value = in_value
    regex = r"^([a-zA-Z ]+( \d+[A-Z]?)(-\d+[A-Z]?)?, [A-Z][a-z]+)$" # regexr.com/6l99i
    error = "Faulty location address"
  elif in_type == "Vlans":
    text = "Enter comma separated list of vlans:"
    title = in_title
    value = in_value
    regex = r"^([0-9]{1,4},{0,1})*$" # regexr.com/5kipp
    error = "Error in list of vlans"
  elif in_type == "MAC":
    text = "Enter mac address"
    title = "MAC"
    value = ""
    regex = r"^(([0-9A-Fa-f]{2}[-:.]){5}[0-9A-Fa-f]{2})|(([0-9A-Fa-f]{4}[-:.]){2}[0-9A-Fa-f]{4})$" # regexr.com/6enrc
    error = "MAC format error, Exiting!"
  else:
    return {"status": "fail"}

  while True:
    input_string = crt_box_input(text, title, value)
    if input_string == "":
      # cancel or x
      return {"status": "fail"}
    if re.search(regex, input_string, re.MULTILINE):
      return {
        "status": "success",
        "text": input_string
      }
    crt_box_message(error, "Error", "Stop")

def crt_sendline(text: str, crt_tab_object: object) -> None:
  """ send string to tab and return when ready """

  # send string to console followed by enter
  crt_tab_object.Screen.Send(text + chr(13))

  # wait for string or timeout after 175ms
  #crt_tab_object.Screen.WaitForString("#", 175, False, True)

  # wait 175ms
  crt_object.Sleep(175)

  # finished
  return None

def crt_connect_serial(settings: dict, systemenv: dict, connectall: bool) -> dict:
  """ connect serial session only through supported usb-adapter and return object"""
  import serial.tools.list_ports

  # create list for com ports in tabs
  ports_serial = []
  crt_tabcount = crt_object.GetTabCount() # get the amount of tabs

  # loop through the tab index
  for crt_tab_no in range(1,crt_tabcount+1):
    try:
      crt_tab_object = crt_object.GetTab(crt_tab_no) # get tab object
    except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
      # tab is locked
      return {"status": "error"}

    crt_config_object = crt_tab_object.Session.Config # get tab config object
    try:
      # get value of config option if it exist
      port_no = crt_config_object.GetOption(systemenv["comPort"])
    except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
      # the config option does not exist
      port_no = "None"
    else:
      # add value to list
      ports_serial.append([crt_tab_no,port_no])

  # list serial ports
  ports = list(serial.tools.list_ports.comports())
  if len(ports) == 0:
    # no ports detected
    return {"status": "error"}

  # serial port exist
  for i in ports:
    # walk through all serial ports
    pidvid = f"{i.pid:0{4}X}" + ":" + f"{i.vid:0{4}X}" # serial present pid and vid as decimal, this needs to be converted and padded to match list
    if pidvid in settings["USBserial"]["approved"]:
      # adapter is in allowed list
      for crt_tab in ports_serial:
        # walk through list of tabs
        if i.device in crt_tab[1]:
          # port exist in tabs
          crt_tab_object = crt_object.GetTab(crt_tab[0])
          if not crt_tab_object.Session.Connected:
            # connect if disconnected
            try:
              crt_tab_object.Session.Connect()
            except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
              # error establishing serial
              return {"status": "error"}
          crt_tab_object.Activate() # tab to front

          # set session config parameters
          crt_session_config(crt_tab_object)

          if connectall is False:
            return {
              "status": "success",
              "crt_tab_object": crt_tab_object
            }
      else: # pylint: disable=useless-else-on-loop
        # port does not exist in tabs
        try:
          crt_tab_object = crt_object.Session.ConnectInTab("/Serial " + i.device + " /BAUD 9600 /PARITY NONE /STOP 0 /DATA 8 /NOCTS /NODSR /NOXON")
        except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
          # error establishing serial
          return {"status": "error"}
        if crt_tab_object.Session.Connected:
          # serial session is connected
          crt_tab_object.Activate() # tab to front

          # set session config parameters
          crt_session_config(crt_tab_object)

          if connectall is False:
            return {
              "status": "success",
              "crt_tab_object": crt_tab_object
            }
        else:
          # could not connect
          return {"status": "error"}
  else: # pylint: disable=useless-else-on-loop
    if connectall is True:
      return {"status": "success"}
    # no valid ports found
    return {"status": "error"}

def crt_connect_ssh_start(ipaddress: str, ssh_cred: dict, logtofile: bool, systemenv: dict, settings: dict, noauto: bool) -> dict:
  """ establish a ssh session and return crt object """
  import os
  import datetime

  if len(ssh_cred) == 0:
    try:
      crt_tab_object = crt_object.Session.ConnectInTab("/SSH2 /ACCEPTHOSTKEYS" + " " + ipaddress)
    except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
      return {"status": "error"}
  else:
    if ssh_cred["ConfigManager"] == "":
      # configuration manager not used
      try:
        crt_tab_object = crt_object.Session.ConnectInTab("/SSH2 /ACCEPTHOSTKEYS /L " + ssh_cred["username"] + " /PASSWORD " + ssh_cred["password"] + " " + ipaddress)
      except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
        return {"status": "error"}
    else:
      # configuration manager is used
      try:
        crt_tab_object = crt_object.Session.ConnectInTab("/SSH2 /ACCEPTHOSTKEYS /CREDENTIALS " + ssh_cred["ConfigManager"] + " " + ipaddress)
      except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
        return {"status": "error"}

  # wait for connection to complete
  crt_object.Sleep(250) # 250ms

  # set session config parameters
  crt_session_config(crt_tab_object)

  # get a point in time
  timestamp = datetime.datetime.now()

  if noauto is False:
    # lock session to prevent accidental keyboard input
    crt_tab_object.Session.Lock()

    # verify connected device and mode
    if not check_exec_mode({}, crt_tab_object) is True:
      return {"status": "error"}

    # log to file
    if logtofile is True:
      # log output on screen to logfile
      crt_log_path = os.path.join(systemenv["homePath"], *settings["onedrive"]["personal_documents"], *settings["SecureCRT"]["path"], settings["SecureCRT"]["logs"])
      if os.path.isdir(crt_log_path) is True:
        crt_tab_object.Session.Log(False) # stop logging
        crt_config_object = crt_tab_object.Session.Config # get config object
        crt_config_object.SetOption("Log Filename V2", os.path.join(crt_log_path, ipaddress + "_" + timestamp.now().strftime("%Y%m%d") + ".log")) # define logfile
        crt_tab_object.Session.Log(True, True) # start logging and append
      else:
        # directory does not exist
        crt_box_message("Logfile cannot be created for this session!", "Error", "Warn")

      # begin session
      crt_sendline("!!! Starting " + timestamp.now().strftime("%Y-%m-%d %H:%M:%S"), crt_tab_object)

    # prepare for commands
    crt_sendline("terminal length 0", crt_tab_object)
    crt_sendline("terminal width 80", crt_tab_object)

  # finished
  return {
    "status": "success",
    "crt_tab_object": crt_tab_object
  }

def crt_connect_ssh_end(crt_tab_object: object, logtofile: bool) -> dict:
  """ end ssh session """
  import datetime

  # get a point in time
  timestamp = datetime.datetime.now()

  if logtofile is True:
    # end session
    crt_sendline("!!! Ending " + timestamp.now().strftime("%Y-%m-%d %H:%M:%S"), crt_tab_object)

    # clear log settings in case session is reused
    crt_tab_object.Session.Log(False) # stop logging to file
    crt_config_object = crt_tab_object.Session.Config # get config object
    crt_config_object.SetOption("Log Filename V2", "") # remove log file name
    crt_config_object.SetOption("Start Log Upon Connect",00000000) # do not start log upon connect

  # finished
  crt_tab_object.Session.Unlock()
  crt_tab_object.ResetCaption()
  crt_tab_object.Session.Disconnect()
  crt_scripttab = crt_object.GetScriptTab()
  if crt_tab_object.Index != crt_scripttab.Index:
    # cannot close tab running script
    crt_tab_object.Close()
  return {
    "status": "success",
  }

def crt_connect_cmd(command: list, label: str, systemenv: dict, settings: dict) -> dict:
  """ connect a local shell session and run commands """
  import os
  import datetime

  # get a point in time
  timestamp = datetime.datetime.now()

  # establish session
  try:
    crt_tab_object = crt_object.Session.ConnectInTab("/LOCALSHELL")
  except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
    return {"status": "error"}

  # wait for connection to complete
  crt_object.Sleep(250) # 250ms

  # set session label
  crt_tab_object.Caption = label

  # lock session to prevent accidental keyboard input
  crt_tab_object.Session.Lock()

  # log output on screen to logfile
  crt_log_path = os.path.join(systemenv["homePath"], *settings["onedrive"]["personal_documents"], *settings["SecureCRT"]["path"], settings["SecureCRT"]["logs"])
  if os.path.isdir(crt_log_path) is True:
    crt_tab_object.Session.Log(False) # stop logging
    crt_config_object = crt_tab_object.Session.Config # get config object
    crt_config_object.SetOption("Log Filename V2", os.path.join(crt_log_path, "Command_" + timestamp.now().strftime("%Y%m%d") + ".log")) # define logfile
    crt_tab_object.Session.Log(True, True) # start logging and append
  else:
    # directory does not exist
    crt_box_message("Logfile cannot be created for this session!", "Error", "Warn")

  # enter commands and collect output
  output = []
  for i in command:
    crt_tab_object.Screen.Send(i + chr(13))
    crt_tab_object.Screen.WaitForString(i[0:10]) # only the first characters if poor screen resolution
    capture = crt_tab_object.Screen.ReadString(systemenv["prompt"])
    output.append(capture)

  # finished
  crt_tab_object.Session.Log(False) # stop logging to file
  crt_config_object.SetOption("Log Filename V2", "") # remove log file name
  crt_config_object.SetOption("Start Log Upon Connect",00000000) # do not start log upon connect
  crt_tab_object.Session.Unlock()
  crt_tab_object.Session.Disconnect()
  crt_scripttab = crt_object.GetScriptTab()
  if crt_tab_object.Index != crt_scripttab.Index:
    # cannot close tab running script
    crt_tab_object.Close()
  return {
    "status": "success",
    "output": output
  }

def crt_connect_rdp(device: str, configmanager: str) -> dict:
  """ connect a local shell session and run commands """

  # if label contain spaces
  if " " in configmanager:
    # fix for space in profile name
    configmanager = "\"" + configmanager + "\""

  # establish session
  if configmanager not in ("", "False"):
    # is used
    try:
      crt_tab_object = crt_object.Session.ConnectInTab("/RDP /CREDENTIALS " + configmanager + " " + device)
    except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
      return {"status": "error"}
  else:
    # is not used
    try:
      crt_tab_object = crt_object.Session.ConnectInTab("/RDP" + " " + device)
    except ScriptError: # type: ignore[name-defined] # pylint: disable=undefined-variable
      return {"status": "error"}

  # wait for connection to complete
  crt_object.Sleep(250) # 250ms

  # set session config parameters
  crt_session_config(crt_tab_object)

  return {
    "status": "success",
    "crt_tab_object": crt_tab_object
  }

def crt_session_config(crt_tab_object: object) -> None:
  """ set session config parameters """

  # get config object
  crt_object_config = crt_tab_object.Session.Config

  # valid for ssh and serial sessions
  if crt_object_config.GetOption("Protocol Name") in ("SSH2", "Serial"):
    # prevent session from idle timeout
    if crt_object_config.GetOption("Idle Check") != 1:
      crt_object_config.SetOption("Idle Check", 1) # activate idle check
      crt_object_config.SetOption("Idle String", r"\000") # use null character
      crt_object_config.SetOption("Idle Timeout", 120) # send string every 120 seconds
    # set line send delay
    if crt_object_config.GetOption("Line Send Delay") != 5:
      crt_object_config.SetOption("Line Send Delay", 5) # set line send delay to 5ms
    # set char send delay
    if crt_object_config.GetOption("Character Send Delay") != 0:
      crt_object_config.SetOption("Character Send Delay", 0) # set char send delay to 0ms

  # only valid for ssh sessions
  if crt_object_config.GetOption("Protocol Name") in ("SSH2"):
    # no-op protocol
    if crt_object_config.GetOption("Idle NO-OP Check") != 1:
      crt_object_config.SetOption("Idle NO-OP Check", 1) # enable sending no-op protocol
      crt_object_config.SetOption("Idle NO-OP Timeout", 60) # 60 seconds delay
    # set auth prompt
    if crt_object_config.GetOption("Auth Prompts in Window") != 0:
      crt_object_config.SetOption("Auth Prompts in Window", 0) # prompt for credentials in popup

  # only valid for rdp sessions
  if crt_object_config.GetOption("Protocol Name") in ("RDP"):
    if crt_object_config.GetOption("Close On Disconnect") != 1:
      crt_object_config.SetOption("Close On Disconnect", 1) # close tab on disconnect

  # finished
  return None

def port_trunk(model: dict, crt_tab_object: object) -> None:
  """ trunk port """

  # generic config
  crt_sendline("description TRUNK", crt_tab_object)
  crt_sendline("switchport mode trunk", crt_tab_object)

  # finished
  return None

def port_access(model: dict, network: dict, crt_tab_object: object) -> None:
  """ access port """

  # general
  crt_sendline("switchport mode access", crt_tab_object)

  # ise
  if network["ise"] is True:
    # quarantine
    if network["quarantine"] is not False:
      crt_sendline("switchport access vlan " + network["quarantine"]["id"], crt_tab_object)

    # voice
    if network["voice"] is not False:
      crt_sendline("authentication host-mode multi-domain", crt_tab_object)

    crt_sendline("description ISE", crt_tab_object)
  else:
    crt_sendline("description ACCESS", crt_tab_object)

  # finished
  return None

def sol_find_ip(vlan: str, secret: dict, settings: dict) -> dict:
  """ returns next available ip on vlan from ipam """
  from orionsdk import SwisClient
  import requests

  # no certificate warning
  if settings["Solarwinds"]["verifycert"] is False:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # pylint: disable=no-member

  # set session paramaters
  session = requests.Session()
  session.timeout = 30

  # setup session
  swis = SwisClient(settings["Solarwinds"]["URL"], secret["solarwinds"]["username"], secret["solarwinds"]["password"], verify = settings["Solarwinds"]["verifycert"], session=session)

  # query ipam for next ip
  try:
    json_ip = swis.query("SELECT TOP 1 I.DisplayName FROM IPAM.IPNode I WHERE Status=2 AND I.Subnet.VLAN=" + vlan)
  except ValueError: # JSONDecodeError
    # when no or corrupt data is returned
    return {"status": "error"}
  if json_ip:
    return {
      "status": "success",
      "output": json_ip["results"][0]["DisplayName"]
    }
  return {"status": "error"}

def sol_reserve_ip(ipaddress: str, secret: dict, settings: dict) -> dict:
  """ reserve ip in ipam """
  from orionsdk import SwisClient
  import requests

  # no certificate warning
  if settings["Solarwinds"]["verifycert"] is False:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # pylint: disable=no-member

  # set session paramaters
  session = requests.Session()
  session.timeout = 30

  # setup session
  swis = SwisClient(settings["Solarwinds"]["URL"], secret["solarwinds"]["username"], secret["solarwinds"]["password"], verify = settings["Solarwinds"]["verifycert"], session=session)

  # reserve ip in ipam
  result = swis.invoke("IPAM.SubnetManagement", "ChangeIPStatus", ipaddress, "Reserved")
  if result is None:
    return {"status": "success"}
  return {
    "status": "error",
    "error": None
  }

def sol_add_node(ipaddress: str, secret: dict, settings: dict) -> dict:
  """ discover and add node and correct interfaces """
  from orionsdk import SwisClient
  import requests

  # no certificate warning
  if settings["Solarwinds"]["verifycert"] is False:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # pylint: disable=no-member

  # set session paramaters
  session = requests.Session()
  session.timeout = 60

  # setup session
  swis = SwisClient(settings["Solarwinds"]["URL"], secret["solarwinds"]["username"], secret["solarwinds"]["password"], verify = settings["Solarwinds"]["verifycert"], session=session)

  # create core plugin
  corePluginContext = { # pylint: disable=invalid-name
    "BulkList": [{"Address": ipaddress}],
    "Credentials": [{
      "CredentialID": settings["Solarwinds"]["snmpv3_credential_id"], # Orion.Credentials
      "Order": 1
    }],
    "WmiRetriesCount": 0,
    "WmiRetryIntervalMiliseconds": 1000
  }
  corePluginConfig = swis.invoke("Orion.Discovery", "CreateCorePluginConfiguration", corePluginContext) # pylint: disable=invalid-name

  # create interface plugin
  interfacesPluginContext = { # pylint: disable=invalid-name
    "AutoImportStatus": ["Up", "Down"], # , "Shutdown"
    "AutoImportVlanPortTypes": ["Trunk", "Access"],
    "AutoImportVirtualTypes": ["Physical"],
    "AutoImportExpressionFilter": [{"Prop": "Alias", "Op": "!Regex", "Val": "DO_NOT_USE"}, {"Prop": "Name", "Op": "!Regex", "Val": "Ap1/0/1"}]
    # Available values for Prop: Type, Name, Descr, Alias, Node, All, Vlan
    # Available values for Op: All, !All, Any, !Any, Equals, !Equals, Regex, !Regex, #All, !#All, #Any, !#Any
    # Val is the literal value to compare Prop to
    # If more than one expression is provided, the interface must match all of the expressions to be imported
    # To specify more than one number or string for the All and Any operators (including variants), separate them by spaces
  }
  interfacesPluginConfig = swis.invoke('Orion.NPM.Interfaces', 'CreateInterfacesPluginConfiguration', interfacesPluginContext) # pylint: disable=invalid-name

  # start discovery
  discoveryProfile = { # pylint: disable=invalid-name
    "Name": "Provisioning",
    "EngineID": settings["Solarwinds"]["orion_engine_id"], # Orion.Engines
    "JobTimeoutSeconds": 3600,
    "SearchTimeoutMiliseconds": 3000,
    "SnmpTimeoutMiliseconds": 2000,
    "SnmpRetries": 2,
    "RepeatIntervalMiliseconds": 1800,
    "SnmpPort": 161,
    "HopCount": 0,
    "PreferredSnmpVersion": "SNMP3",
    "DisableIcmp": False,
    "AllowDuplicateNodes": False,
    "IsAutoImport": True,
    "IsHidden": True,
    "PluginConfigurations": [
      {"PluginConfigurationItem": corePluginConfig},
      {"PluginConfigurationItem": interfacesPluginConfig}
    ]
  }
  discoveryProfileID = swis.invoke("Orion.Discovery", "StartDiscovery", discoveryProfile) # pylint: disable=invalid-name

  # wait until done
  while True:
    result = swis.query("SELECT Status FROM Orion.DiscoveryProfiles WHERE ProfileID = " + str(discoveryProfileID))
    if len(result["results"]) < 1:
      break
    crt_object.Sleep(5000) # wait 5 seconds

  # find out the added node nodeid and return it
  target = swis.query("SELECT NodeID FROM Orion.Nodes WHERE IPAddress = '" + ipaddress + "' ")
  if not "results" in target or len(target["results"]) == 0:
    return {"status": "error"}
  return {
    "status": "success",
    "output": target["results"][0]["NodeID"]
  }

def sol_update_int(node_id: str, secret: dict, settings: dict) -> dict:
  """ update interfaces on node to unpluggable """
  from orionsdk import SwisClient
  import requests

  # no certificate warning
  if settings["Solarwinds"]["verifycert"] is False:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # pylint: disable=no-member

  # set session paramaters
  session = requests.Session()
  session.timeout = 30

  # setup session
  swis = SwisClient(settings["Solarwinds"]["URL"], secret["solarwinds"]["username"], secret["solarwinds"]["password"], verify = settings["Solarwinds"]["verifycert"], session=session)

  # get list of interfaces
  json_int_id = swis.query("SELECT InterfaceID FROM Orion.NPM.Interfaces WHERE NodeID = '" + node_id + "' AND Alias = '*** ise'")

  # get uri of node
  json_uri = swis.query("SELECT Uri FROM Orion.Nodes WHERE NodeID = '" + node_id + "'")

  # set interfaces
  returnvalue = "success"
  for row in json_int_id["results"]:
    result = swis.update(json_uri["results"][0]["Uri"] + "/Interfaces/InterfaceID=" + str(row["InterfaceID"]), UnPluggable=True) # pylint: disable=assignment-from-no-return
    if result is not None:
      returnvalue = "error"
  return {"status": returnvalue}

def sol_update_poller(node_id: str, secret: dict, settings: dict) -> dict:
  """ update pollers on node """
  from orionsdk import SwisClient
  import requests

  # no certificate warning
  if settings["Solarwinds"]["verifycert"] is False:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # pylint: disable=no-member

  # set session paramaters
  session = requests.Session()
  session.timeout = 30

  # setup session
  swis = SwisClient(settings["Solarwinds"]["URL"], secret["solarwinds"]["username"], secret["solarwinds"]["password"], verify = settings["Solarwinds"]["verifycert"], session=session)

  # get uri of poller
  json_uri = swis.query("SELECT Uri FROM Orion.Pollers WHERE NetObjectID=" + node_id + " AND PollerType LIKE '%EnergyWise%'")
  if not "results" in json_uri or len(json_uri["results"]) == 0:
    return {"status": "error"}

  # disable poller
  result = swis.update(json_uri["results"][0]["Uri"], Enabled=False) # pylint: disable=assignment-from-no-return
  if result is None:
    return {"status": "success"}
  return {"status": "error"}

def sol_manage_node(node_id: str, secret: dict, settings: dict) -> dict:
  """ manage node in ncm with correct connectionprofile """
  from orionsdk import SwisClient
  import requests

  # no certificate warning
  if settings["Solarwinds"]["verifycert"] is False:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # pylint: disable=no-member

  # set session paramaters
  session = requests.Session()
  session.timeout = 30

  # setup session
  swis = SwisClient(settings["Solarwinds"]["URL"], secret["solarwinds"]["username"], secret["solarwinds"]["password"], verify = settings["Solarwinds"]["verifycert"], session=session)

  # add node to ncm with id
  result = swis.invoke("Cirrus.Nodes", "AddNodeToNCM", node_id)

  # get uri
  json_uri = swis.query("SELECT Uri FROM Cirrus.Nodes WHERE CoreNodeID = " + node_id)
  if not "results" in json_uri or len(json_uri["results"]) == 0:
    return {"status": "error"}

  # add connectionprofile to node
  result = swis.update(json_uri["results"][0]["Uri"], ConnectionProfile=1) # pylint: disable=assignment-from-no-return
  if result is None:
    return {"status": "success"}
  return {"status": "error"}

def sol_update_custom(node_id: str, secret: dict, settings: dict) -> dict:
  """ add custom properties """
  from orionsdk import SwisClient
  import requests

  # no certificate warning
  if settings["Solarwinds"]["verifycert"] is False:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # pylint: disable=no-member

  # set session paramaters
  session = requests.Session()
  session.timeout = 30

  # setup session
  swis = SwisClient(settings["Solarwinds"]["URL"], secret["solarwinds"]["username"], secret["solarwinds"]["password"], verify = settings["Solarwinds"]["verifycert"], session=session)

  # get uri
  json_uri = swis.query("SELECT Uri FROM Orion.NodesCustomProperties WHERE NodeID =" + node_id)
  if not "results" in json_uri or len(json_uri["results"]) == 0:
    return {"status": "error"}

  # update node
  result = swis.update(json_uri["results"][0]["Uri"], Typ="Klientswitch") # pylint: disable=assignment-from-no-return
  if result is None:
    return {"status": "success"}
  return {"status": "error"}

def sol_update_int2(ipaddress: str, interface: str, unpluggable: bool, secret: dict, settings: dict) -> dict:
  """ update unpluggable on a single interface in solarwinds """
  from orionsdk import SwisClient
  import requests
  from string import ascii_letters

  # no certificate warning
  if settings["Solarwinds"]["verifycert"] is False:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # pylint: disable=no-member

  # set session paramaters
  session = requests.Session()
  session.timeout = 30

  # setup session
  swis = SwisClient(settings["Solarwinds"]["URL"], secret["solarwinds"]["username"], secret["solarwinds"]["password"], verify = settings["Solarwinds"]["verifycert"], session=session)

  # get node uri and id
  node = swis.query("SELECT IPAddress, Caption, Uri, NodeID FROM Orion.Nodes WHERE IPAddress = @ip_addr", ip_addr=ipaddress)
  if len(node['results']) != 1:
    return {"status": "error"}

  # get interface id
  interface_id = swis.query("SELECT Name, InterfaceID FROM Orion.NPM.Interfaces WHERE NodeID = " + str(node["results"][0]["NodeID"]) + " AND Name LIKE '%" + interface.lstrip(ascii_letters) + "'")["results"][0]["InterfaceID"]

  # update node
  result = swis.update(node["results"][0]["Uri"] + "/Interfaces/InterfaceID=" + str(interface_id), UnPluggable=unpluggable) # pylint: disable=assignment-from-no-return
  if result is not None:
    return {"status": "error"}

  # finished
  return {"status": "success"}

def sol_delete_node(ipaddress: str, secret: dict, settings: dict) -> dict:
  """ delete node from solarwinds """
  from orionsdk import SwisClient
  import requests

  # no certificate warning
  if settings["Solarwinds"]["verifycert"] is False:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # pylint: disable=no-member

  # set session paramaters
  session = requests.Session()
  session.timeout = 30

  # setup session
  swis = SwisClient(settings["Solarwinds"]["URL"], secret["solarwinds"]["username"], secret["solarwinds"]["password"], verify = settings["Solarwinds"]["verifycert"], session=session)

  # get uri
  result = swis.query("SELECT IPAddress, Caption, Uri FROM Orion.Nodes WHERE IPAddress = @ip_addr", ip_addr=ipaddress)
  if len(result['results']) != 1:
    return {"status": "error"}

  # delete node
  swis.delete(result["results"][0]["Uri"]) # pylint: disable=assignment-from-no-return
  return {"status": "success"}

def check_web_server(servername: str, port: str, verify: bool) -> bool:
  """ validate weservers before use """
  import requests

  # check url and catch error
  try:
    response = requests.get("https://" + servername + ":" + port, verify = verify, timeout = 30)
  except requests.exceptions.SSLError:
    return False
  except requests.exceptions.Timeout:
    return False
  except requests.exceptions.ConnectionError:
    return False

  # finished
  response.close()
  return True

def validate_mac(macaddress: str) -> dict:
  """ validate and convert mac to eui format """
  import re

  # strip characters from cut-n-paste
  macaddress = macaddress.strip()

  # identify the delimiter
  if "." in macaddress:
    delimiter = "."
  elif ":" in macaddress:
    delimiter = ":"
  elif "-" in macaddress:
    delimiter = "-"
  else:
    delimiter = ""

  # strip the delimiter and make upper case
  mac = macaddress.replace(delimiter, "")
  mac = mac.upper()

  if len(mac) != 12:
    # wrong length
    return {"status": "error"}

  # format new mac
  eui = mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]

  regex= "^(([0-9A-Fa-f]{2}[-:.]){5}[0-9A-Fa-f]{2})|(([0-9A-Fa-f]{4}[-:.]){2}[0-9A-Fa-f]{4})$" # regexr.com/6enrc
  if re.search(regex, eui, re.MULTILINE):
    return {
      "status": "success",
      "eui": eui
    }
  return {"status": "error"}

def validate_hash(filename: str, filehash: str) -> dict:
  """ compare file with hash """
  import hashlib

  md5_hash = hashlib.md5()
  with open(filename, "rb") as a_file:
    try:
      content = a_file.read()
    except OSError:
      # error reading file
      return {"status": "error"}
  md5_hash.update(content)
  digest = md5_hash.hexdigest()

  # return result
  if digest != filehash:
    return {"status": "fail"}
  return {"status": "success"}

def check_exec_mode(secret: dict, crt_tab_object: object) -> bool:
  """ go into exec mode """

  for _ in range(6):
    crt_tab_object.Screen.Send(chr(13))
    result = crt_tab_object.Screen.WaitForStrings([")#", "#", "[yes/no]", ">", "Enter local username:", "terminate autoinstall? [yes]:", "Press RETURN to get started!", "<cleartext password>"], 15)
    if result == 0:
      # no switch detected
      return False
    if result == 1:
      # in config mode
      crt_tab_object.Screen.Send("end" + chr(13))
      return True
    if result == 2:
      # in priv exec mode
      return True
    if result == 3:
      # enter initial configuration dialog
      crt_tab_object.Screen.Send("no" + chr(13))
      crt_object.Sleep(3000)
    if result == 4:
      # in user exec mode
      crt_tab_object.Screen.Send("enable" + chr(13))
    if result == 5:
      # already provisioned
      if secret != {}:
        # use only when secret is defined
        crt_tab_object.Screen.Send(secret["local_cred"]["username"] + chr(13))
        crt_tab_object.Screen.WaitForString("Enter local password:")
        crt_tab_object.Screen.Send(secret["local_cred"]["password"] + chr(13))
      else:
        return False
    if result == 6:
      # terminate autoinstall
      crt_tab_object.Screen.Send("yes" + chr(13))
      crt_object.Sleep(1000)
    if result == 7:
      # press enter
      crt_tab_object.Screen.Send(chr(13))
      crt_object.Sleep(1000)
    if result == 8:
      # enter initial configuration dialog older switches
      crt_tab_object.Screen.Send("no" + chr(13))
      crt_object.Sleep(3000)
  # looping
  return False

def ping(ipaddress: str, systemenv: dict) -> dict:
  """ ping ip and return result """
  import subprocess

  # do the ping and catch return code
  result = subprocess.run(["ping", ipaddress, "-" + systemenv["pingOptions"], "2"], shell=True, capture_output=True, check=False, text=True)

  # return with result
  if result.returncode == 0:
    return {
      "status": "success",
      "output": result.stdout
    }
  return {"status": "error"}

def deswedify(text: str) -> str:
  """ replace swedish letters """

  small_oe = "\xf6"
  large_oe = "\xd6"
  small_aa = "\xe5"
  large_aa = "\xc5"
  small_ae = "\xe4"
  large_ae = "\xc4"

  notswedish = text.replace(small_oe, "o").replace(large_oe, "O").replace(small_aa, "a").replace(large_aa, "A").replace(small_ae, "a").replace(large_ae, "A")

  # finishing
  return notswedish

def excel_read_br(query: str, systemenv: dict, settings: dict) -> dict:
  """ read byggnadsregister and return select site details """
  import pandas as pd
  import os

  # set username
  username = os.getlogin()
  group = settings["usergroups"][username][1]

  # read the file to dataform
  br_file = os.path.join(systemenv["homePath"], *settings["onedrive"][group], *settings["byggnadsregister"]["path"])
  try:
    br_df = pd.read_excel(br_file, skiprows=2, index_col=None, header=None, usecols=[1,2,6,8])
  except OSError:
    return {"status": "error"}

  # search for sites in dataform using lowercase
  df_list = br_df.loc[br_df[1].str.lower().str.contains(query.lower(), na=False),1]
  # convert to dict
  df_listmenu = df_list.to_dict()

  # if no sites are returned
  if len(df_listmenu) == 0:
    return {"status": "notfound"}

  # construct menu from results
  for rownum, sitename in enumerate(df_listmenu):
    if rownum == 0:
      # very first row
      df_menu = "\n" + str(sitename) + "     " + df_listmenu[sitename]
    else:
      if len(str(sitename)) == 1:
        df_menu += "\n" + str(sitename) + "     " + df_listmenu[sitename]
      elif len(str(sitename)) == 2:
        df_menu += "\n" + str(sitename) + "   " + df_listmenu[sitename]
      elif len(str(sitename)) == 3:
        df_menu += "\n" + str(sitename) + " " + df_listmenu[sitename]

  # select site
  while True:
    df_site = crt_box_input(df_menu, "Select correct site", "")
    if df_site == "":
      # cancel or x
      return {"status": "canceled"}

    try:
      # get selected site from dataform
      df_choice = br_df.iloc[[int(df_site)]].to_dict(orient = "index")
    except (IndexError, ValueError):
      # cancel or row that does not exist
      crt_box_message("Wrong selection", "Error", "Stop")
    else:
      df_site = list(df_choice.values())[0] # remove first key
      return {
        "site": df_site,
        "status": "success"
      }

def add_vlan(vlansfile: str, vlanlist: str, crt_tab_object: object) -> dict:
  """ add vlans and name """

  # get all vlans and info
  vlaninfo = read_jsonfile(vlansfile)

  # get list of vlan numbers
  vlans = list(vlaninfo.keys())

  # walk through list and find match
  for i in vlanlist.split(","):
    if i in vlans:
      # vlan exist in vlan file
      crt_tab_object.Screen.Send("do sh vlan id " + i + chr(13))
      result = crt_tab_object.Screen.WaitForStrings(["active", "not found"])
      if result == 2:
        # does not exist by id
        crt_tab_object.Screen.Send("do sh vlan name " + vlaninfo[i]["name"] + chr(13))
        result = crt_tab_object.Screen.WaitForStrings(["active", "not found"])
        if result == 2:
          # does not exist by name
          crt_sendline("vlan " + i, crt_tab_object)
          crt_sendline("name " + vlaninfo[i]["name"], crt_tab_object)
          crt_sendline("exit", crt_tab_object)
        else:
          # exist by name
          crt_sendline("vlan " + i, crt_tab_object)
          crt_sendline("exit", crt_tab_object)
    else:
      return {"status": "error"}

  # finished
  return {"status": "success"}

def cisco_encrypt(password: str, typeofhash: int) -> str:
  """ make cisco type 5, 7, 8, 9 hashes """
  from passlib.hash import cisco_type7
  from passlib.hash import md5_crypt
  from backports.pbkdf2 import pbkdf2_hmac
  import random
  import base64
  import scrypt

  # translate standard base64 table to cisco base64 table used in type8 and type 9
  std_b64chars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  cisco_b64chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  b64table = str.maketrans(std_b64chars, cisco_b64chars)

  if typeofhash == 5:
    # create the hash
    return str(md5_crypt.using(salt_size=4).hash(password))

  if typeofhash == 7:
    # create the hash
    return str(cisco_type7.hash(password))

  if typeofhash == 8:
    # create random salt (cisco use 14 characters from custom b64 table)
    salt_chars=[]
    for _ in range(14):
      salt_chars.append(random.choice(cisco_b64chars))
    salt = "".join(salt_chars)
    # create the hash
    result = pbkdf2_hmac("sha256", password.encode(), salt.encode(), 20000, 32)
    # convert the hash from standard base64 to cisco base64
    return base64.b64encode(result).decode().translate(b64table)[:-1]

  if typeofhash == 9:
    # create random salt (cisco use 14 characters from custom b64 table)
    salt_chars=[]
    for _ in range(14):
      salt_chars.append(random.choice(cisco_b64chars))
    salt = "".join(salt_chars)
    # create the hash
    result = scrypt.hash(password.encode(), salt.encode(), 16384, 1, 1, 32)
    # convert the hash from standard base64 to cisco base64
    return base64.b64encode(result).decode().translate(b64table)[:-1]

  # finished
  return password

def ps_dns_record(inventory: str, ipaddress: str, settings: dict, action: str) -> dict:
  """ add or remove dns resource record with powershell """
  from pypsrp.client import Client
  import os

  # set username and group
  username = os.getlogin()
  group = settings["usergroups"][username][1]

  # type of action and user/pass
  if action == "remove":
    command = "Remove-DnsServerResourceRecord -Force -ZoneName " + settings["DNS"]["Name"][group] + " -RRType A -Name " + inventory + " -RecordData " + ipaddress
  elif action == "add":
    command = "Add-DnsServerResourceRecordA -ZoneName " + settings["DNS"]["Name"][group] + " -Name " + inventory + " -CreatePtr -IPv4Address " + ipaddress

  # connection details
  username = crt_box_input("Enter username", "Credentials to " + action + " DNS record", settings["ActiveDirectory"]["Prefix"])
  password = crt_box_input("Enter password", "Credentials to " + action + " DNS record", "", True)
  client = Client(settings["DNS"]["Master"], username = username, password = password, ssl = False)

  # execute and return result
  try:
    output, streams, had_errors = client.execute_ps(command)
  except Exception as error: # pylint: disable=undefined-variable disable=broad-except
    return {
      "output": None,
      "streams": None,
      "had_errors": True,
      "exception": error
    }
  else:
    return {
      "output": output,
      "streams": streams,
      "had_errors": had_errors,
      "exception": None
    }

def dns_query(query: str, settings: dict) -> dict:
  """ get and validate fqdn and ip address """
  import re
  import socket
  import os

  # set username and group
  username = os.getlogin()
  group = settings["usergroups"][username][1]

  if re.search("^[0-9]{4}$", query, re.MULTILINE):
    # inventory number

    # check if domain suffix is used
    if settings["DNS"]["Name"][group] in query:
      fqdn = query
    else:
      fqdn = query + "." + settings["DNS"]["Name"][group]

    try:
      ipadd = socket.gethostbyname(fqdn)
    except (socket.herror, socket.gaierror, TimeoutError) as error:
      result = {
        "status": "error",
        "error": str(error)
      }
    else:
      result = {
        "status": "success",
        "fqdn": fqdn,
        "ip": ipadd
      }
  elif re.search(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", query, re.MULTILINE): # regexr.com/5ke5o
    # ip address
    try:
      fqdn = socket.gethostbyaddr(query)[0]
    except socket.herror:
      # host not found, missing ptr
      result = {
        "status": "herror",
        "fqdn": "",
        "ip": query
      }
    except (socket.gaierror, TimeoutError) as error:
      result = {
        "status": "error",
        "error": str(error)
      }
    else:
      result = {
        "status": "success",
        "fqdn": fqdn,
        "ip": query
      }
  else:
    # misc resolve of hostname
    fqdn = query
    try:
      ipadd = socket.gethostbyname(fqdn)
    except (socket.herror, socket.gaierror, TimeoutError) as error:
      result = {
        "status": "error",
        "error": str(error)
      }
    else:
      result = {
        "status": "success",
        "fqdn": fqdn,
        "ip": ipadd
      }

  # finished
  return result

def dna_get_token(settings: dict, secret: dict) -> dict:
  """ get auth token from dna-center """
  import requests
  from requests.auth import HTTPBasicAuth

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }

  # query api
  url = "https://" + settings["DNAC"]["URL"] + ":" + settings["DNAC"]["APIport"] + "/dna/system/api/v1/auth/token"
  try:
    response = requests.post(url, auth = HTTPBasicAuth(secret["dnac"]["username"], secret["dnac"]["password"]), verify = settings["DNAC"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  data = response.json()
  status = response.status_code
  response.close()

  # return result
  if status == 200:
    return {
      "status": "success",
      "error": None,
      "token": data["Token"]
    }
  return {
    "status": "error",
    "error": data["error"],
    "token": None
  }

def dna_add_device(settings: dict, secret: dict, dna_token: str, ipaddress: str) -> dict:
  """ add new device to dna-center inventory """
  import requests

  # create payload
  payload = {
    "cliTransport": "SSH",
    "enablePassword": "",
    "ipAddress": [
        ipaddress.strip()
    ],
    "password": secret["dnac"]["password"],
    "snmpAuthPassphrase": secret["snmp"]["password"],
    "snmpAuthProtocol": "SHA",
    "snmpMode": "RO",
    "snmpPrivPassphrase": secret["snmp"]["password"],
    "snmpPrivProtocol": "AES128",
    "snmpRetry": "3",
    "snmpTimeout": "5",
    "snmpUserName": secret["snmp"]["username"],
    "snmpVersion": "V3",
    "type": "NETWORK_DEVICE",
    "userName": secret["dnac"]["username"]
  }

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Auth-Token": dna_token
  }

  # query api
  url = "https://" + settings["DNAC"]["URL"] + ":" + settings["DNAC"]["APIport"] + "/dna/intent/api/v1/network-device"
  try:
    response = requests.post(url, json = payload, verify = settings["DNAC"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  data = response.json()
  status = response.status_code
  response.close()

  # return result
  if str(status).startswith("2"):
    return {
      "status": "success",
      "taskId": data["response"]["taskId"]
    }
  return {"status": "error"}

def dna_get_device(settings: dict, dna_token: str, ipaddress: str) -> dict:
  """ get device id from dna center """
  import requests

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Auth-Token": dna_token
  }

  # query api
  url = "https://" + settings["DNAC"]["URL"] + ":" + settings["DNAC"]["APIport"] + "/dna/intent/api/v1/network-device?managementIpAddress=" + ipaddress.strip()
  try:
    response = requests.get(url, verify = settings["DNAC"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  data = response.json()
  status = response.status_code
  response.close()

  # return result
  if str(status).startswith("2"):
    if len(data["response"]) == 0:
      return {
        "status": "success",
        "deviceid": None
      }
    return {
      "status": "success",
      "deviceid": data["response"][0]["id"]
    }
  return {"status": "error"}

def dna_client_detail(settings: dict, dna_token: str, mac: str) -> dict:
  """ get client details from dna center """
  import requests

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Auth-Token": dna_token
  }

  # query api
  url = "https://" + settings["DNAC"]["URL"] + ":" + settings["DNAC"]["APIport"] + "/dna/intent/api/v1/client-detail?macAddress=" + mac
  try:
    response = requests.get(url, verify = settings["DNAC"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  data: dict = response.json()
  status = response.status_code
  response.close()

  # return result
  if str(status).startswith("2"):
    data["status"] = "success"
    return data
  return {"status": "error"}

def dna_delete_device(settings: dict, dna_token: str, dna_deviceid: str) -> dict:
  """ delete device from dna center """
  import requests

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Auth-Token": dna_token
  }

  # query api
  url = "https://" + settings["DNAC"]["URL"] + ":" + settings["DNAC"]["APIport"] + "/dna/intent/api/v1/network-device/" + dna_deviceid + "?cleanConfig=false"
  try:
    response = requests.delete(url, verify = settings["DNAC"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  status = response.status_code
  response.close()

  # return result
  if str(status).startswith("2"):
    return {"status": "success"}
  return {"status": "error"}

def dna_get_task(settings: dict, dna_token: str, dna_taskid: str) -> dict:
  """ get task details from id """
  import requests

  # define headers
  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Auth-Token": dna_token
  }

  # query api
  url = "https://" + settings["DNAC"]["URL"] + ":" + settings["DNAC"]["APIport"] + "/dna/intent/api/v1/task/" + dna_taskid
  try:
    response = requests.get(url, verify = settings["DNAC"]["verifycert"], headers = headers, timeout = 30)
  except requests.exceptions.Timeout:
    return {"status": "error"}
  response.keep_alive = False
  data = response.json()
  status = response.status_code
  response.close()

  # return result
  if str(status).startswith("2"):
    return {
      "status": "success",
      "response": data["response"]
    }
  return {"status": "error"}

def mainmenu1() -> None:
  """ Factory default """

  # create serial session
  serials = crt_connect_serial(checks["settings"], checks["systemenv"], False)
  if serials["status"] == "error":
    crt_box_message("Cannot create serial session", "Error", "Stop")
    return None
  if serials["status"] == "success":
    crt_tab_object = serials["crt_tab_object"]

  # set sync mode
  crt_tab_object.Screen.Synchronous = True

  # set session label
  crt_tab_object.Caption = "Factory default"

  # lock session to prevent accidental keyboard input
  crt_tab_object.Session.Lock()

  # verify connected device and mode
  if check_exec_mode(checks["secret"], crt_tab_object) is False:
    crt_box_message("No device detected", "Error", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    return None

  # determine model number
  model = get_model(checks["modelsfile"], crt_tab_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting!", "Error", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    return None

  if crt_box_yes_no("Do you wish to erase the whole device?", "Factory Default"):
    crt_tab_object.Screen.Send("delete /fo flash:/vlan.dat" + chr(13))
    crt_tab_object.Screen.Send("write memory" + chr(13))
    crt_tab_object.Screen.WaitForString("[OK]")
    crt_tab_object.Screen.Send("write erase" + chr(13))
    crt_tab_object.Screen.Send(chr(13))
    crt_tab_object.Screen.WaitForString("[OK]")
    crt_box_message("Reload device to finish the cleanup", "Factory Default", "Info")
    #crt_tab_object.Screen.WaitForString("#")

  # finished
  crt_tab_object.Session.Unlock()
  crt_tab_object.ResetCaption()
  return None

def mainmenu2() -> None:
  """ Provisioning of new device """
  import random
  import re
  import os
  import datetime

  # set variables
  group = checks["settings"]["usergroups"][checks["username"]][1]

  # verify that all needed servers are reachable
  if check_web_server(checks["settings"]["Solarwinds"]["URL"], checks["settings"]["Solarwinds"]["APIport"], checks["settings"]["Solarwinds"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "Error", "Stop")
    return None
  if check_web_server(checks["settings"]["ISE"]["PAN"]["URL"], checks["settings"]["ISE"]["PAN"]["APIport"], checks["settings"]["ISE"]["PAN"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "Error", "Stop")
    return None
  if ping(dns_query(checks["settings"]["DNS"]["Master"], checks["settings"])["ip"], checks["systemenv"])["status"] != "success":
    crt_box_message("No connection to DNS server", "Error", "Stop")
    return None

  # create serial session
  serials = crt_connect_serial(checks["settings"], checks["systemenv"], False)
  if serials["status"] == "error":
    crt_box_message("Cannot create serial session", "Error", "Stop")
  elif serials["status"] == "success":
    crt_tab_object = serials["crt_tab_object"]

  # get a point in time
  timestamp = datetime.datetime.now()

  # set numbers file
  numbersfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "provisioningfiles", "numbers.txt")
  if os.path.isfile(numbersfile) is False:
    # the file does not exist
    crt_box_message("Numbers file is missing, Exiting!", "Error", "Stop")
    crt_tab_object.Session.Disconnect()
    return None

  # set session label
  crt_tab_object.Caption = "Provisionering"

  # lock session to prevent accidental keyboard input
  crt_tab_object.Session.Lock()

  # verify connected device and mode
  if check_exec_mode(checks["secret"], crt_tab_object) is False:
    crt_box_message("No device detected", "Error", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    crt_tab_object.Session.Disconnect()
    return None

  # prevent provisioning of already provisioned device
  for _ in range(5):
    crt_tab_object.Screen.Send(chr(13))
    crt_tab_object.Screen.WaitForString(chr(13))
    result = crt_tab_object.Screen.ReadString("#", 3)
    if "Switch" in result:
      break
  else:
    crt_box_message("Cannot provision this device", "Error", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    crt_tab_object.Session.Disconnect()
    return None

  # shuffle order of lists
  random.shuffle(checks["settings"]["ISE"]["PSN"]["Nodes"])
  random.shuffle(checks["settings"]["ISE"]["MNT"]["Nodes"])
  random.shuffle(checks["settings"]["DNS"]["Servers"])
  random.shuffle(checks["settings"]["NTP"]["Peer"])

  # create tuple of upper case hostnamee and ip of psn
  list_psn = []
  for node_fqdn in checks["settings"]["ISE"]["PSN"]["Nodes"]:
    list_psn.append((node_fqdn.split(".")[0].upper(), dns_query(node_fqdn,checks["settings"])["ip"]))

  # log output on screen to logfile
  crt_log_path = os.path.join(checks["systemenv"]["homePath"], *checks["settings"]["onedrive"]["personal_documents"], *checks["settings"]["SecureCRT"]["path"], checks["settings"]["SecureCRT"]["logs"])
  if os.path.isdir(crt_log_path) is True:
    crt_tab_object.Session.Log(False) # stop logging
    crt_config_object = crt_tab_object.Session.Config # get config object
    crt_config_object.SetOption("Log Filename V2", os.path.join(crt_log_path, "Provisioning_" + timestamp.now().strftime("%Y%m%d") + ".log")) # define logfile
    crt_tab_object.Session.Log(True, True) # start logging and append
  else:
    # directory does not exist
    crt_box_message("Logfile cannot be created for this session!", "Error", "Warn")

  # begin provisioning
  crt_sendline("!!! starting provisioning " + timestamp.now().strftime("%Y-%m-%d %H:%M:%S"), crt_tab_object)

  # enter config mode
  crt_sendline("conf t", crt_tab_object)

  # disable autoinstall messages
  crt_sendline("no service config", crt_tab_object)

  # basic line config
  crt_sendline("line con 0", crt_tab_object)
  crt_sendline(" exec-timeout 0", crt_tab_object) # disable exec-timeout during script run
  crt_sendline(" length 0", crt_tab_object) # no pagination during script run
  crt_sendline(" logging synchronous", crt_tab_object)
  crt_sendline(" width 150", crt_tab_object)

  # back to exec mode
  crt_sendline("end", crt_tab_object)

  # determine model number
  model = get_model(checks["modelsfile"], crt_tab_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting!", "Error", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    crt_tab_object.Session.Disconnect()
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    crt_tab_object.Session.Disconnect()
    return None

  # determine if upgrade is needed
  version = get_version(crt_tab_object)
  if version["status"] == "error":
    # error reading version number
    crt_box_message("Problem determining version, Exiting", "Error", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    crt_tab_object.Session.Disconnect()
    return None
  if version["version"] == model["image"]["version"]:
    # running correct version
    upgrade = False
  else:
    # upgrade needed
    upgrade = True
    # set upgradeport
    if model["interfaces"]["access"] is False:
      upgradeport = model["interfaces"]["trunk"]["prefix"] + model["interfaces"]["trunk"]["first"]
    else:
      upgradeport = model["interfaces"]["access"]["prefix"] + model["interfaces"]["access"]["first"]
    crt_box_message("Upgrade needed, proceeding!", "Upgrade", "Info")

  # enter management vlan
  while True:
    vlan = crt_box_dialogue("", "Management vlan", "Vlan")
    if vlan["status"] == "fail":
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None
    networks = read_jsonfile(checks["networksfile"])
    if networks["status"] == "error":
      crt_box_message("Error reading networks file, Exiting!", "Error", "Stop")
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None
    if networks.get(vlan["text"]) is not None:
      network = networks[vlan["text"]]
      network["vlan"] = vlan["text"]
    else:
      crt_box_message("Unknown vlan, Exiting!", "Error", "Stop")
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None
    break

  # find free ipaddress
  result = sol_find_ip(network["vlan"], checks["secret"], checks["settings"])
  if result["status"] == "error":
    crt_box_message("Cannot allocate ip, Exiting!", "Error", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    crt_tab_object.Session.Disconnect()
    return None
  ipaddress = result["output"]

  # enter config mode
  crt_sendline("conf t", crt_tab_object)

  # set hostname and location
  if upgrade is False:
    hostname = ipaddress.split(".")[2] + "_" + ipaddress.split(".")[3]

    # get snmp location
    while True:
      br_search = crt_box_input("Search for name of site:", "Site", "")
      if br_search in ("", "Test"):
        # cancel or x
        br_location = "Gatan 0, Kungsbacka"
        break

      br_site = excel_read_br(br_search, checks["systemenv"], checks["settings"])
      if br_site["status"] == "error":
        crt_box_message("Error reading byggnadsregister file, manual input required", "Error", "Warn")
        br_location = "Gatan 0, Kungsbacka"
        break
      if br_site["status"] == "notfound":
        crt_box_message("No sites found, try again", "Error", "Warn")
      if br_site["status"] == "success":
        br_location = deswedify(br_site["site"][6] + ", " + br_site["site"][8])
        break

    # enter and validate location
    result = crt_box_dialogue(br_location, "", "Location")
    if result["status"] == "fail":
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None
    location = result["text"]

    # enter site name
    sitename = crt_box_dialogue(br_search.capitalize(), "", "Site")
    if sitename["status"] == "fail":
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None
    hostname += "_" + sitename["text"]

    # get inventory number
    for _ in range(3):
      if sitename["text"] == "Test":
        inventory = "0000"
        number = "success"
      else:
        # read file and return values
        with open(numbersfile, "r", encoding="UTF-8") as num_file:
          try:
            number = num_file.readlines()[0].strip()
          except OSError:
            number = "error"
          else:
            inventory = str(int(number) +1)

      if number != "error":
        # enter device number
        result = crt_box_dialogue(inventory, "", "Inventory")
        if result["status"] == "fail":
          crt_tab_object.Session.Unlock()
          crt_tab_object.ResetCaption()
          crt_tab_object.Session.Disconnect()
          return None

        if result["text"] == "0000":
          # this is a test unit, set and continue
          hostname += "_" + result["text"]
          break
        device_dict = dns_query(result["text"], checks["settings"])

        if device_dict["status"] == "success":
          crt_box_message("Inventory number already exist", "DNS", "Warn")
        else:
          if result["text"] == inventory:
            hostname += "_" + result["text"]
            with open(numbersfile, "w", encoding="UTF-8") as num_file:
              try:
                num_file.write(result["text"])
              except OSError:
                crt_box_message("Cannot save inventory number, Exising!", "DNS", "Stop")
                crt_tab_object.Session.Unlock()
                crt_tab_object.ResetCaption()
                crt_tab_object.Session.Disconnect()
                return None
            break
          hostname += "_" + result["text"]
          break
    else:
      # all attempts failed
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None

    # set snmp location
    crt_sendline("snmp-server location " + location, crt_tab_object)

    # create ssh key
    crt_sendline("hostname " + hostname, crt_tab_object)
    crt_sendline("ip domain name " + checks["settings"]["DNS"]["Name"][group], crt_tab_object)
    crt_tab_object.Screen.Send("crypto key gen rsa gen mod 2048" + chr(13))
    crt_tab_object.Screen.WaitForString("[OK]")

  # vtp
  crt_sendline("vtp domain " + checks["settings"]["VTP"], crt_tab_object)
  crt_sendline("vtp mode transparent", crt_tab_object)

  # create management vlan
  crt_sendline("vlan " + network["vlan"], crt_tab_object)
  crt_sendline("name " + network["name"], crt_tab_object)
  crt_sendline("exit", crt_tab_object) # exit vlan
  crt_sendline("interface vlan" + network["vlan"], crt_tab_object)
  crt_sendline("ip address " + ipaddress + " " + network["netmask"], crt_tab_object)
  if not model["image"]["version"].startswith("15.0"):
    # devices supporting ipv6
    crt_sendline("no ipv6 enable", crt_tab_object)
  crt_sendline("no shut", crt_tab_object)
  crt_sendline("exit", crt_tab_object) # exit interface config
  if model["layer3"]:
    # for L3 devices
    crt_sendline("ip routing", crt_tab_object)
    crt_sendline("ip route 0.0.0.0 0.0.0.0 " + network["gateway"], crt_tab_object)
  else:
    # for L2 devices
    crt_sendline("ip default-gateway " + network["gateway"], crt_tab_object)

  # back to exec mode
  crt_sendline("end", crt_tab_object)

  # do upgrade
  if upgrade:
    # begin upgrade
    crt_sendline("!!! begin upgrade " + timestamp.now().strftime("%Y-%m-%d %H:%M:%S"), crt_tab_object)

    # cleanup of flash
    if model["image"]["installmode"] is False:
      # make sure an arbitrary amount of free space exist on flash
      crt_tab_object.Screen.Send("dir flash: | inc bytes free" + chr(13))
      crt_tab_object.Screen.WaitForString("bytes total (")
      free = crt_tab_object.Screen.ReadString(" bytes free)")
      if int(free) < int(model["free"]):
        # cleanup needed, create directory listning
        crt_tab_object.Screen.Send("dir flash:" + chr(13))
        crt_tab_object.Screen.WaitForString("Directory of flash:/")
        listing = crt_tab_object.Screen.ReadString("#")
        binonflash = listing.split(chr(13))
        # walk through rows and catch image
        for i in binonflash:
          # NOTE: will remove active image as well
          findimage = re.search("([a-zA-Z0-9-_.]*.bin)", i) # regexr.com/5ipmd
          if findimage is not None and findimage[0] != model["image"]["filename"]:
            # delete image if not current
            crt_tab_object.Screen.Send("del /fo flash:/" + findimage[0] + chr(13))
            crt_tab_object.Screen.WaitForString("#")
    else:
      crt_tab_object.Screen.Send("install remove inactive" + chr(13))
      while True:
        result = crt_tab_object.Screen.WaitForStrings(["Do you want to remove the above files? [y/n]", "Switch 1 R0/0: install_engine: Completed install remove"])
        if result == 1:
          # cleanup needed
          crt_tab_object.Screen.Send("y")
        elif result == 2:
          break

    # make sure cable is disconnected
    while True:
      crt_tab_object.Screen.Send("sh int " + upgradeport + " | inc connect" + chr(13))
      result = crt_tab_object.Screen.WaitForStrings(["notconnect", "connected"])
      if result == 1:
        # not connected
        break
      if result == 2:
        # is connected
        crt_box_message("Disconnect cable from port " + upgradeport, "Upgrade", "Info")

    # enter config mode
    crt_sendline("conf t", crt_tab_object)

    # create trunk port
    crt_sendline("interface " + upgradeport, crt_tab_object)
    if model["model"].startswith("WS-C3560CG") or model["model"] == "WS-C3560-8PC-S":
      crt_sendline("switchport trunk encapsulation dot1q", crt_tab_object)
    crt_sendline("switchport mode trunk", crt_tab_object)
    crt_sendline("switchport trunk all vlan " + network["vlan"], crt_tab_object)
    crt_sendline("spanning-tree portfast trunk", crt_tab_object)
    if model["model"].startswith("C9") and model["model"] != "C9300-24S":
      # fix for error on these models
      crt_sendline("power inline never", crt_tab_object)

    # back to exec mode
    crt_sendline("end", crt_tab_object)

    # connect cable
    while True:
      crt_tab_object.Screen.Send("sh int " + upgradeport + " | inc connect" + chr(13))
      result = crt_tab_object.Screen.WaitForStrings(["notconnect", "connected"], 5)
      if result == 1:
        # not connected
        crt_box_message("Connect cable to port " + upgradeport, "Upgrade", "Info")
      elif result == 2:
        # is connected
        break

    # wait for device to converge
    while True:
      crt_object.Sleep(1000) # one second delay
      if ping(ipaddress, checks["systemenv"])["status"] == "success":
        break

    # copy image to flash
    for _ in range(10):
      # start copy
      crt_tab_object.Screen.Send("copy ftp://" + checks["settings"]["NAS"] + model["image"]["path"] + model["image"]["filename"] + " flash:" + chr(13))
      crt_tab_object.Screen.WaitForString("]?")
      crt_tab_object.Screen.Send(chr(13))

      # overwrite if exist
      result = crt_tab_object.Screen.WaitForStrings(["Accessing", "Do you want to over write? [confirm]"], 15)
      if result == 2:
        # file exist
        crt_tab_object.Screen.Send(chr(13))

      # continue if finished or try again
      result = crt_tab_object.Screen.WaitForStrings([" bytes/sec)", "(Timed out)"])
      if result == 1:
        # copy succeeded
        break
    else:
      # looping
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None

    # disconnect cable
    while True:
      crt_tab_object.Screen.Send("sh int " + upgradeport + " | inc connect" + chr(13))
      result = crt_tab_object.Screen.WaitForStrings(["notconnect", "connected"])
      if result == 1:
        # not connected
        break
      if result == 2:
        # is connected
        crt_box_message("Disconnect cable from port " + upgradeport, "Upgrade", "Info")

    # enter config mode
    crt_sendline("conf t", crt_tab_object)

    # cleanup network config
    crt_sendline("default interface " + upgradeport, crt_tab_object)
    crt_sendline("no int vlan" + network["vlan"], crt_tab_object)
    crt_sendline("no vlan " + network["vlan"], crt_tab_object)
    if model["layer3"]:
      # for L3 devices
      crt_sendline("default ip route *", crt_tab_object)
    else:
      # for L2 devices
      crt_sendline("default ip default-gateway", crt_tab_object)

    # verify image
    crt_tab_object.Screen.Send("do verify /md5 flash:/" + model["image"]["filename"] + " " + model["image"]["checksum"] + chr(13))
    result = crt_tab_object.Screen.WaitForStrings(["Verified ", "%Error verifying"])
    if result == 2:
      # checksum failed
      crt_box_message("Upgrade failed, Exiting!", "Error", "Stop")
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None

    # activate image
    if model["image"]["installmode"] is False: # classic mode
      # change boot variable
      crt_sendline("no boot system", crt_tab_object)
      crt_sendline("boot system flash:/" + model["image"]["filename"], crt_tab_object)

      # set exec timeout and length
      crt_sendline("line con 0", crt_tab_object)
      crt_sendline(" exec-timeout 15", crt_tab_object)
      crt_sendline(" length 40", crt_tab_object)

      # back to exec mode
      crt_sendline("end", crt_tab_object)

      # save config
      crt_tab_object.Screen.Send("write memory" + chr(13))
      crt_tab_object.Screen.WaitForString("[OK]")

      # reload and end
      crt_tab_object.Screen.Send("reload" + chr(13))
      crt_tab_object.Screen.WaitForString("[confirm]")
      crt_tab_object.Screen.Send(chr(13))
      crt_sendline("!!! ending upgrade " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), crt_tab_object)
      crt_box_message("Upgrade finished and device is reloading, Exiting!", "Upgrade", "Info")
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None
    if model["image"]["installmode"] is True: # install mode
      # change boot variable
      crt_sendline("no boot system", crt_tab_object)
      crt_sendline("boot system flash:packages.conf", crt_tab_object)
      crt_sendline("no boot manual", crt_tab_object)

      # set exec timeout and length
      crt_sendline("line con 0", crt_tab_object)
      crt_sendline(" exec-timeout 15", crt_tab_object)
      crt_sendline(" length 40", crt_tab_object)

      # back to exec mode
      crt_sendline("end", crt_tab_object)

      # save running
      crt_tab_object.Screen.Send("write memory" + chr(13))
      crt_tab_object.Screen.WaitForString("[OK]")

      # install image and end
      crt_tab_object.Screen.Send("install add file flash:/"+ model["image"]["filename"] + " activate commit" + chr(13))
      if crt_tab_object.Screen.WaitForStrings(["Please confirm you have changed boot config to flash:packages.conf [y/n]", "--- Starting initial file syncing ---"]) == 1:
        # convert from image
        crt_tab_object.Screen.Send("y")
      if crt_tab_object.Screen.WaitForStrings(["Do you want to proceed? [y/n]", "Same Image File-No Change"]) == 1:
        # image does not exist
        crt_tab_object.Screen.Send("y")
      crt_tab_object.Screen.WaitForString("SUCCESS: install_add_activate_commit")
      crt_tab_object.Screen.Send("!!! ending upgrade " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + chr(13))
      crt_box_message("Upgrade finished and device is reloading, Exiting!", "Upgrade", "Info")
      crt_tab_object.Session.Unlock()
      crt_tab_object.ResetCaption()
      crt_tab_object.Session.Disconnect()
      return None

  # reserve ip in sol
  result = sol_reserve_ip(ipaddress, checks["secret"], checks["settings"])
  if result["status"] != "success":
    crt_box_message("Failed to reserve IP, Exiting!", "Solarwinds", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    crt_tab_object.Session.Disconnect()
    return None

  # check if it exist by ip in ise
  result = ise_find_device_by_ip(ipaddress, checks["secret"], checks["settings"])
  if result["status"] == "error":
    crt_box_message("Error searching IP, Continuing!", "ISE", "Warn")
  elif result["result"] is True:
    crt_box_message("Device exist by IP, Exiting!", "ISE", "Info")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    crt_tab_object.Session.Disconnect()
    return None

  # check if it exist by name in ise
  result = ise_find_device_by_name(hostname, checks["secret"], checks["settings"])
  if result["status"] == "error":
    crt_box_message("Error searching Name, Continuing!", "ISE", "Warn")
  elif result["result"] is True:
    crt_box_message("Device exist by name, Exiting!", "ISE", "Stop")
    crt_tab_object.Session.Unlock()
    crt_tab_object.ResetCaption()
    crt_tab_object.Session.Disconnect()
    return None

  # create network device in ise
  result = ise_create_device(ipaddress, hostname, checks["secret"], checks["settings"], "Kommun")
  if result["status"] == "error":
    crt_box_message("Cannot add device. Check ISE, Continuing!", "ISE", "Warn")

  # add dns record
  for _ in range(2):
    result = ps_dns_record(hostname.split("_")[3], ipaddress, checks["settings"], "add")
    if result["had_errors"] is True:
      # powershell returned error
      crt_box_message("Cannot add DNS record, Continuing!", "DNS", "Warn")
    if result["had_errors"] is False:
      # all seems well
      break

  # enter config mode
  crt_sendline("conf t", crt_tab_object)

  ## all global configuration

  # misc stuff
  if model["model"].startswith("C1000"):
    crt_sendline("dying-gasp primary snmp-trap secondary syslog", crt_tab_object)

  # mtu
  if model["image"]["xe"] is True:
    crt_sendline("system mtu 8192", crt_tab_object)
  else:
    crt_sendline("system mtu jumbo 8192", crt_tab_object) # added 2022-09-23

  # auto qos
  if model["image"]["xe"] is False:
    crt_sendline("auto qos srnd4", crt_tab_object)
  if not model["image"]["version"].startswith("15.0") and not model["model"].startswith("IE") and not model["image"]["version"].startswith("15.2.2"):
    crt_sendline("auto qos global compact", crt_tab_object)

  # disabled on newer versions
  if model["image"]["version"].startswith("15.0"):
    crt_sendline("no vstack", crt_tab_object)

  # dns
  crt_sendline("ip domain lookup", crt_tab_object)
  for i in checks["settings"]["DNS"]["Servers"]:
    crt_sendline("ip name-server " + i, crt_tab_object)

  # password encrypt
  if model["master_encryption"] is True:
    crt_sendline("key config-key password-encrypt " + checks["secret"]["password_aes"], crt_tab_object)
    crt_sendline("password encryption aes", crt_tab_object)

  # aaa
  crt_sendline("aaa new-model", crt_tab_object)
  crt_sendline("username " + checks["secret"]["local_cred"]["username"] + " privilege 15 password 7 " + cisco_encrypt(checks["secret"]["local_cred"]["password"], 7), crt_tab_object)

  for i in list_psn:
    crt_sendline("tacacs server " + i[0], crt_tab_object)
    crt_sendline(" address ipv4 " + i[1], crt_tab_object)
    crt_sendline(" key 7 " + cisco_encrypt(checks["secret"]["tacacs"], 7), crt_tab_object)
  crt_sendline("aaa group server tacacs+ tac_auth", crt_tab_object)
  for i in list_psn:
    crt_sendline(" server name " + i[0], crt_tab_object)

  # smart license
  if model["smartlicense"] is True:
    crt_sendline("crypto pki trustpoint SLA-TrustPoint", crt_tab_object)
    crt_sendline("revocation-check none", crt_tab_object)
    crt_sendline("snmp-server enable traps smart-license", crt_tab_object)
    crt_sendline("license smart enable", crt_tab_object)
    crt_sendline("license smart utility", crt_tab_object)
    crt_sendline("license smart url cslu https://" + checks["settings"]["SSMS"]["URL"] + checks["settings"]["SSMS"]["uri_cslu"], crt_tab_object)
    crt_sendline("license smart transport clsu", crt_tab_object)
    crt_sendline("do license smart trust idtoken " + checks["secret"]["smarttoken"] + " local", crt_tab_object) # license smart trust idtoken xxx local force

  # vlans
  if network["quarantine"] is not False:
    crt_sendline("vlan " + network["quarantine"]["id"], crt_tab_object)
    crt_sendline("name " + network["quarantine"]["name"], crt_tab_object)
    crt_sendline("exit", crt_tab_object)
  if network["voice"] is not False:
    crt_sendline("vlan " + network["voice"]["id"], crt_tab_object)
    crt_sendline("name " + network["voice"]["name"], crt_tab_object)
    crt_sendline("exit", crt_tab_object)

    # snmp
    crt_sendline("snmp-server community " + checks["secret"]["ise_snmp"] + " RO snmp-access", crt_tab_object)
    for i in list_psn:
      crt_sendline("snmp-server host " + i[1] + " " + checks["secret"]["ise_snmp"] + " mac-notification snmp", crt_tab_object)

    # aaa
    for i in list_psn:
      crt_sendline("radius server " + i[0], crt_tab_object)
      crt_sendline(" address ipv4 " + i[1] + " auth-port 1645 acct-port 1646", crt_tab_object)
      crt_sendline(" key 7 " + cisco_encrypt(checks["secret"]["radius"], 7), crt_tab_object)
    crt_sendline("aaa group server radius ise_auth", crt_tab_object)
    for i in list_psn:
      crt_sendline(" server name " + i[0], crt_tab_object)

  # back to exec mode
  crt_sendline("end", crt_tab_object)

  # check for cluster
  prefixes = get_cluster(model, crt_tab_object)
  if prefixes["status"] == "error":
    crt_box_message("Error collecting cluster status, Exiting!", "Error", "Stop")
    return None

  # enter config mode
  crt_sendline("conf t", crt_tab_object)

  ## interfaces

  # access ports
  if "access" in prefixes:
    for cluster in prefixes["access"]:
      model["interfaces"]["access"]["prefix"] = cluster
      if network["voice"] is not False and model["interfaces"]["restrictedqos"] is not False:
        # devicees with restricted qos
        crt_sendline("interface range " + model["interfaces"]["access"]["prefix"] + model["interfaces"]["access"]["first"] + " - " + model["interfaces"]["restrictedqos"]["first"], crt_tab_object)
        port_access(model, network, crt_tab_object)
        crt_tab_object.Screen.Send(chr(13) + chr(13))
        crt_tab_object.Screen.WaitForString("(config-if-range)#" + chr(13))
        network["voice"] = False
        crt_sendline("interface range " + model["interfaces"]["access"]["prefix"] + model["interfaces"]["restrictedqos"]["last"] + " - " + model["interfaces"]["access"]["last"], crt_tab_object)
        port_access(model, network, crt_tab_object)
        crt_tab_object.Screen.Send(chr(13) + chr(13))
        crt_tab_object.Screen.WaitForString("(config-if-range)#" + chr(13))
      else:
        crt_sendline("interface range " + model["interfaces"]["access"]["prefix"] + model["interfaces"]["access"]["first"] + " - " + model["interfaces"]["access"]["last"], crt_tab_object)
        port_access(model, network, crt_tab_object)
        crt_tab_object.Screen.Send(chr(13) + chr(13))
        crt_tab_object.Screen.WaitForString("(config-if-range)#" + chr(13))

  # multigig (access) ports
  if "multigig" in prefixes:
    for cluster in prefixes["multigig"]:
      model["interfaces"]["multigig"]["prefix"] = cluster
      crt_sendline("interface range " + model["interfaces"]["multigig"]["prefix"] + model["interfaces"]["multigig"]["first"] + " - " + model["interfaces"]["multigig"]["last"], crt_tab_object)
      port_access(model, network, crt_tab_object)
      crt_tab_object.Screen.Send(chr(13) + chr(13))
      crt_tab_object.Screen.WaitForString("(config-if-range)#" + chr(13))

  # trunk ports
  if "trunk" in prefixes:
    for cluster in prefixes["trunk"]:
      model["interfaces"]["trunk"]["prefix"] = cluster
      crt_sendline("interface range " + model["interfaces"]["trunk"]["prefix"] + model["interfaces"]["trunk"]["first"] + " - " + model["interfaces"]["trunk"]["last"], crt_tab_object)
      port_trunk(model, crt_tab_object)
      crt_tab_object.Screen.Send(chr(13) + chr(13))
      crt_tab_object.Screen.WaitForString("(config-if-range)#" + chr(13))

  # detect network module on c9300
  if model["model"].startswith("C9300"):
    crt_tab_object.Screen.Send("exit" + chr(13))
    crt_tab_object.Screen.Send("do sh inv" + chr(13))
    crt_tab_object.Screen.WaitForString("NAME:")
    result = crt_tab_object.Screen.ReadString(")#")
    if "C9300-NM-8X" in result:
      crt_sendline("interface range te1/1/1 - 8", crt_tab_object)
      port_trunk(model, crt_tab_object)
      crt_tab_object.Screen.Send(chr(13) + chr(13))
      crt_tab_object.Screen.WaitForString(")#" + chr(13))

  # inactivate any unused interfaces
  crt_sendline("interface vlan1", crt_tab_object)
  crt_sendline("shut", crt_tab_object)
  crt_sendline("description DO_NOT_USE", crt_tab_object)
  crt_tab_object.Screen.Send(chr(13) + chr(13))
  crt_tab_object.Screen.WaitForString(")#" + chr(13))

  if model["interfaces"]["mgmtport"] is not False:
    crt_sendline("interface " + model["interfaces"]["mgmtport"], crt_tab_object)
    crt_sendline("shut", crt_tab_object)
    crt_sendline("description DO_NOT_USE", crt_tab_object)
    crt_tab_object.Screen.Send(chr(13) + chr(13))
    crt_tab_object.Screen.WaitForString(")#" + chr(13))

  if model["interfaces"]["notused"] is not False:
    for port_name in model["interfaces"]["notused"]:
      crt_sendline("interface range " + port_name, crt_tab_object)
      crt_sendline("shut", crt_tab_object)
      crt_sendline("description DO_NOT_USE", crt_tab_object)
      crt_tab_object.Screen.Send(chr(13) + chr(13))
      crt_tab_object.Screen.WaitForString(")#" + chr(13))

  # exit interface range
  crt_sendline("exit", crt_tab_object)

  # set exec timeout and length
  crt_sendline("line con 0", crt_tab_object)
  crt_sendline(" exec-timeout 15", crt_tab_object)
  crt_sendline(" length 40", crt_tab_object)

  # back to exec mode
  crt_sendline("end", crt_tab_object)

  # finished
  crt_sendline("!!! ending provisioning " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), crt_tab_object)
  crt_tab_object.Screen.Send("write memory" + chr(13))
  crt_tab_object.Screen.WaitForString("[OK]")
  crt_box_message("Provisioning finished!", "Finished", "Info")

  # clear log settings in case session is reused
  crt_tab_object.Session.Log(False) # stop logging to file
  crt_config_object.SetOption("Log Filename V2", "") # remove log file name
  crt_config_object.SetOption("Start Log Upon Connect",00000000) # do not start log upon connect
  crt_tab_object.Session.Unlock()
  crt_tab_object.ResetCaption()
  crt_tab_object.Session.Disconnect()
  return None

def mainmenu3() -> None:
  """ Add device for monitoring (will take a while) """
  import re

  # verify that all needed servers are reachable
  if check_web_server(checks["settings"]["Solarwinds"]["URL"], checks["settings"]["Solarwinds"]["APIport"], checks["settings"]["Solarwinds"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "Solarwinds", "Stop")
    return None
  if check_web_server(checks["settings"]["DNAC"]["URL"], checks["settings"]["DNAC"]["APIport"], checks["settings"]["DNAC"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "DNA-Center", "Stop")
    return None
  if ping(dns_query(checks["settings"]["DNS"]["Master"], checks["settings"])["ip"], checks["systemenv"]) == "success": # type: ignore[comparison-overlap]
    crt_box_message("No connection to DNS server", "Error", "Stop")
    return None

  # enter device info
  device = crt_box_input("Enter ip address or hostname of device", "Device info", "")
  if device == "":
    # cancel or x
    return None
  device = device.strip()
  if re.search(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", device, re.MULTILINE): # regexr.com/5ke5o
    # ip address
    device_dict = {"ip": device}
  elif re.search("^[0-9]{4}$", device, re.MULTILINE):
    # inventory number
    device_dict = dns_query(device, checks["settings"])
    if device_dict["status"] != "success":
      return None
  else:
    # wrong entry
    return None

  # device must be connected
  if ping(device_dict["ip"], checks["systemenv"])["status"] != "success":
    crt_box_message("Device unresponsive, Exiting!", "Error", "Stop")
    return None

  # add node to solarwinds
  while True:
    result = sol_add_node(device_dict["ip"], checks["secret"], checks["settings"])
    if result["status"] == "error":
      crt_box_message("Device discovery failed, Exiting!", "Solarwinds", "Stop")
      break
    nodeid = str(result["output"])

    result = sol_update_int(nodeid, checks["secret"], checks["settings"])
    if result["status"] != "success":
      crt_box_message("Update of interfaces failed", "Solarwinds", "Warn")
      break

    result = sol_update_poller(nodeid, checks["secret"], checks["settings"])
    if result["status"] != "success":
      crt_box_message("Update of poller failed", "Solarwinds", "Warn")
      break

    result = sol_manage_node(nodeid, checks["secret"], checks["settings"])
    if result["status"] != "success":
      crt_box_message("Update of NCM failed", "Solarwinds", "Warn")
      break

    result = sol_update_custom(nodeid, checks["secret"], checks["settings"])
    if result["status"] != "success":
      crt_box_message("Update of Custom Properties failed", "Solarwinds", "Warn")
      break

    crt_box_message("Successfully added device", "Solarwinds", "Info")
    break

  # add node to dna center
  while True:
    dna_token = dna_get_token(checks["settings"], checks["secret"])
    if dna_token["status"] == "error":
      crt_box_message("Error getting token", "DNA-Center", "Warn")
      break

    dna_deviceid = dna_add_device(checks["settings"], checks["secret"], dna_token["token"], device_dict["ip"])
    if dna_deviceid["status"] == "error":
      crt_box_message("Cannot add device", "DNA-Center", "Warn")
      break

    crt_box_message("Successfully added device", "DNA-Center", "Info")
    break

  # finished
  return None

def mainmenu4() -> None:
  """ Remove device from all systems """
  import ipaddress as ip
  import re

  # verify that all needed servers are reachable
  if check_web_server(checks["settings"]["Solarwinds"]["URL"], checks["settings"]["Solarwinds"]["APIport"], checks["settings"]["Solarwinds"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "Error", "Stop")
    return None
  if check_web_server(checks["settings"]["ISE"]["PAN"]["URL"], checks["settings"]["ISE"]["PAN"]["APIport"], checks["settings"]["ISE"]["PAN"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "ISE", "Stop")
    return None
  if check_web_server(checks["settings"]["DNAC"]["URL"], checks["settings"]["DNAC"]["APIport"], checks["settings"]["DNAC"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "DNA-Center", "Stop")
    return None

  # enter device info
  device = crt_box_input("Enter ip address or hostname of device", "Device info", "")
  if device == "":
    # cancel or x
    return None
  device = device.strip()
  if re.search(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", device, re.MULTILINE): # regexr.com/5ke5o
    # ip address
    device_dict = dns_query(device, checks["settings"])
    if device_dict["status"] == "herror":
      # no ptr
      inventory = crt_box_input("Enter inventory number", "Device info", "")
      device_dict["fqdn"] = inventory.strip()
    elif device_dict["status"] == "error":
      # error resolving
      return None
  elif re.search("^[0-9]{4}$", device, re.MULTILINE):
    # inventory number
    device_dict = dns_query(device, checks["settings"])
    if device_dict["status"] != "success":
      return None
  else:
    # wrong entry
    return None

  # make sure only valid addresses can be selected
  for i in checks["settings"]["Forbidden"]:
    if ip.IPv4Address(device_dict["ip"]) in ip.IPv4Network(i):
      crt_box_message("Forbidden ipaddress", "Error", "Stop")
      return None

  # one final question and verification
  if crt_box_yes_no("Are you sure you want to remove " + device_dict["ip"] + "?", "Remove node"):

    # remove node in solarwinds
    result = sol_delete_node(device_dict["ip"], checks["secret"], checks["settings"])
    if result["status"] == "error":
      crt_box_message("Problem removing node", "Solarwinds", "Warn")
    else:
      crt_box_message("Device has been removed", "Solarwinds", "Info")

    # remove node in ise
    result = ise_delete_device(device_dict["ip"], checks["secret"], checks["settings"])
    if result["status"] == "error":
      crt_box_message("Problem removing network device", "ISE", "Warn")
    else:
      crt_box_message("Device has been removed", "ISE", "Info")

    # remove dns record
    inventory = device_dict["fqdn"].split(".")[0]
    for _ in range(2):
      result = ps_dns_record(inventory, device_dict["ip"], checks["settings"], "remove")
      if result["exception"] is not None:
        # exception occurred
        crt_box_message("Exception message: {}".format(result["exception"]), "{}".format(type(result["exception"]).__name__), "Warn") # pylint: disable=consider-using-f-string
      if result["had_errors"] is True:
        # powershell returned error
        crt_box_message("Error removing DNS record", "DNS", "Warn")
      if result["exception"] is None and result["had_errors"] is False:
        # all seems well
        break
    crt_box_message("Device has been removed", "DNS", "Info")

    # remove node in dna-center
    while True:
      dna_token = dna_get_token(checks["settings"], checks["secret"])
      if dna_token["status"] == "error":
        crt_box_message("Error getting token", "DNA-Center", "Warn")
        break

      dna_deviceid = dna_get_device(checks["settings"], dna_token["token"], device_dict["ip"])
      if dna_deviceid["status"] == "error":
        crt_box_message("Error searching for device", "DNA-Center", "Warn")
        break
      if dna_deviceid["deviceid"] is None:
        crt_box_message("Device does not exist", "DNA-Center", "Warn")
        break

      result = dna_delete_device(checks["settings"], dna_token["token"], dna_deviceid["deviceid"])
      if result["status"] == "error":
        crt_box_message("Error deleteting device", "DNA-Center", "Warn")
        break

      crt_box_message("Device has been removed!", "DNA-Center", "Info")
      break

  # finished
  return None

def mainmenu8() -> None:
  """ Add KBN device to ISE """

  # verify that all needed servers are reachable
  if check_web_server(checks["settings"]["ISE"]["PAN"]["URL"], checks["settings"]["ISE"]["PAN"]["APIport"], checks["settings"]["ISE"]["PAN"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "Error", "Stop")
    return None

  # set ipaddress
  ipaddress = crt_box_dialogue("", "", "IP")
  if ipaddress["status"] == "fail":
    return None

  # set device name
  hostname = crt_box_input("Enter device name:", "Name", "")
  if hostname == "":
    # cancel or x
    return None

  # check if it exist by ip in ise
  result = ise_find_device_by_ip(ipaddress["text"], checks["secret"], checks["settings"])
  if result["status"] == "error":
    crt_box_message("Error searching IP, Continuing!", "ISE", "Warn")
  elif result["result"] is True:
    crt_box_message("Device exist by IP, Exiting!", "ISE", "Stop")
    return None

  # check if it exist by name in ise
  result = ise_find_device_by_name(hostname, checks["secret"], checks["settings"])
  if result["status"] == "error":
    crt_box_message("Error searching Name, Continuing!", "ISE", "Warn")
  elif result["result"] is True:
    crt_box_message("Device exist by name, Exiting!", "ISE", "Stop")
    return None

  # create network device in ise
  result = ise_create_device(ipaddress["text"], hostname, checks["secret"], checks["settings"], "Bredband")
  if result["status"] == "error":
    crt_box_message("Error adding device", "ISE", "Warn")
  elif result["status"] == "success":
    crt_box_message("Device successfully added", "ISE", "Warn")

  # finished
  return None

def mainmenu9() -> None:
  """ Upgrade of device """
  import re

  # enter device info
  device = crt_box_input("Enter ip address or hostname of device", "Device info", "")
  if device == "":
    # cancel or x
    return None

  # verify name or ip
  device = device.strip()
  if re.search(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", device, re.MULTILINE): # regexr.com/5ke5o
    # ip address
    device_dict = {"ip": device}
  elif re.search("^[0-9]{4}$", device, re.MULTILINE):
    # inventory number
    device_dict = dns_query(device, checks["settings"])
    if device_dict["status"] != "success":
      return None
  else:
    # wrong entry
    return None

  # set username and password
  ssh_cred = {}
  if checks["personalsettings"]["credentials"]["tacacs"] in ("False", ""):
    # configuration manager is not used
    ssh_cred["username"] = crt_box_input("Enter your username", "Tacacs", "")
    if ssh_cred["username"] == "":
      return None
    ssh_cred["password"] = crt_box_input("Enter password", "Tacacs", "", True)
    if ssh_cred["password"] == "":
      return None
    ssh_cred["ConfigManager"] = ""
  else:
    # configuation manager is used
    ssh_cred["username"] = ""
    ssh_cred["password"] = ""
    ssh_cred["ConfigManager"] = checks["personalsettings"]["credentials"]["tacacs"]

  # start ssh session
  ssh_session = crt_connect_ssh_start(device_dict["ip"], ssh_cred, False, {}, {}, False)
  if ssh_session["status"] != "success":
    crt_box_message("Error connecting to device", "Error", "Warn")
    return None
  crt_tab_object = ssh_session["crt_tab_object"]

  # set session label
  crt_tab_object.Caption = "Upgrade"

  # determine model number
  model = get_model(checks["modelsfile"], crt_tab_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting!", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None

  version = get_version(crt_tab_object)
  if version["status"] == "error":
    # error reading version number
    crt_box_message("Problem determining version, Exiting", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None
  if version["version"] == model["image"]["version"]:
    # running correct version
    crt_box_message("Upgrade not needed, Exiting!", "Upgrade", "Info")
    crt_connect_ssh_end(crt_tab_object, False)
    return None

  # cleanup of flash
  if model["image"]["installmode"] is False:
    # make sure an arbitrary amount of free space exist on flash
    crt_tab_object.Screen.Send("show flash: | inc bytes free" + chr(13))
    crt_tab_object.Screen.WaitForString("bytes total (")
    free = crt_tab_object.Screen.ReadString(" bytes free)")
    if int(free) < int(model["free"]):
      # cleanup needed, create directory listning
      crt_tab_object.Screen.Send("dir flash:" + chr(13))
      crt_tab_object.Screen.WaitForString("Directory of flash:/")
      listing = crt_tab_object.Screen.ReadString("#")
      binonflash = listing.split(chr(13))
      # walk through rows and catch image
      for i in binonflash:
        # NOTE: will remove active image as well
        findimage = re.search("([a-zA-Z0-9-_.]*.bin)", i) # regexr.com/5ipmd
        if findimage is not None and findimage[0] != model["image"]["filename"]:
          # delete image if not current
          crt_tab_object.Screen.Send("del /fo flash:/" + findimage[0] + chr(13))
          crt_tab_object.Screen.WaitForString("#")
  else:
    crt_tab_object.Screen.Send("install remove inactive" + chr(13))
    while True:
      result = crt_tab_object.Screen.WaitForStrings(["Do you want to remove the above files? [y/n]", "SUCCESS: install_remove"])
      if result == 1:
        # cleanup needed
        crt_tab_object.Screen.Send("y")
      elif result == 2:
        break

  # copy image to flash
  path = "ftp://" + checks["settings"]["NAS"] + model["image"]["path"] + model["image"]["filename"]
  for _ in range(10):
    # start copy
    crt_tab_object.Screen.Send(chr(13))
    crt_tab_object.Screen.WaitForString("#")
    crt_tab_object.Screen.Send("copy " + path + " flash:" + chr(13))
    crt_tab_object.Screen.WaitForString("]?")
    crt_tab_object.Screen.Send(chr(13))

    # overwrite if exist
    result = crt_tab_object.Screen.WaitForStrings(["Accessing", "Do you want to over write? [confirm]"], 15)
    if result == 2:
      # file exist
      crt_tab_object.Screen.Send(chr(13))

    # continue if finished or try again
    result = crt_tab_object.Screen.WaitForStrings([" bytes/sec)", "(Timed out)"])
    if result == 1:
      # copy succeeded
      break
  else:
    # looping
    crt_connect_ssh_end(crt_tab_object, False)
    return None

  # verify image
  crt_tab_object.Screen.Send("verify /md5 flash:/" + model["image"]["filename"] + " " + model["image"]["checksum"] + chr(13))
  result = crt_tab_object.Screen.WaitForStrings(["Verified ", "%Error verifying"])
  if result == 2:
    # checksum failed
    crt_box_message("Upgrade failed, Exiting!", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None
  crt_tab_object.Screen.Send(chr(13))
  crt_tab_object.Screen.WaitForString("#")

  # enter exec mode
  crt_tab_object.Screen.Send("conf t" + chr(13))

  # change boot variable
  crt_tab_object.Screen.Send("no boot system" + chr(13))
  crt_tab_object.Screen.Send("boot system flash:/" + model["image"]["filename"] + chr(13))

  # back to exec mode
  crt_tab_object.Screen.Send("end" + chr(13))

  # save config
  crt_tab_object.Screen.Send("write memory" + chr(13))
  crt_tab_object.Screen.WaitForString("[OK]")
  crt_tab_object.Screen.Send(chr(13))
  crt_tab_object.Screen.WaitForString("#")

  # enter time to reload device
  reload_time = crt_box_input("Enter time to reload, or none for no reload", "Reload", "05:00")

  # schedule reload
  if reload_time != "":
    crt_tab_object.Screen.Send("reload at " + reload_time + chr(13))
    crt_tab_object.Screen.WaitForString("[confirm]")
    crt_tab_object.Screen.Send(chr(13))
    crt_tab_object.Screen.WaitForString("#")

  # end ssh session
  crt_connect_ssh_end(crt_tab_object, False)

  # finished
  return None

def mainmenu10() -> None:
  """ Make one internal trunk port """

  # check for active connection
  if not crt_object.Session.Connected:
    crt_box_message("Sending data requires an active connection, Exiting!", "Error", "Stop")
    return None

  # lock session to prevent accidental keyboard input
  crt_object.Session.Lock()

  # set session config parameters
  crt_session_config(crt_object)

  # verify connected device and mode
  if check_exec_mode({}, crt_object) is False:
    crt_box_message("No device detected", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get modelno
  model = get_model(checks["modelsfile"], crt_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting script!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get management vlan
  for _ in range(3):
    crt_object.Screen.Send(r"sh ip int brie | inc [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" + chr(13))
    result = crt_object.Screen.WaitForString("Vlan", 5)
    if result != 0:
      break
  else:
    crt_box_message("Error collecting management information, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  management = crt_object.Screen.ReadString(chr(13)).split()

  # input interface name
  if model["interfaces"]["trunk"] is False:
    port_example = ""
  else:
    port_example = model["interfaces"]["trunk"]["prefix"] + model["interfaces"]["trunk"]["first"]
  interface = crt_box_dialogue(port_example, "", "Interface")
  if interface["status"] == "fail":
    crt_object.Session.Unlock()
    return None

  # enter config mode
  crt_sendline("conf t", crt_object)

  crt_sendline("default interface " + interface["text"], crt_object)
  crt_sendline("interface " + interface["text"], crt_object)
  crt_sendline("shut", crt_object)
  port_trunk(model, crt_object)
  crt_sendline("no shut", crt_object)

  # back to exec mode
  crt_sendline("end", crt_object)

  # saving
  crt_object.Screen.Send("write memory" + chr(13))
  crt_object.Screen.WaitForString("[OK]")

  # update interface in solarwinds
  if check_web_server(checks["settings"]["Solarwinds"]["URL"], checks["settings"]["Solarwinds"]["APIport"], checks["settings"]["Solarwinds"]["verifycert"]) is False:
    crt_box_message("Cannot update interface unpluggable setting\nPlease update the interface manually", "Solarwinds", "Info")
  else:
    result_update = sol_update_int2(management[1], interface["text"], False, checks["secret"], checks["settings"])
    if result_update["status"] != "success":
      crt_box_message("Error updating interface", "Solarwinds", "Info")

  # finished
  crt_object.Session.Unlock()
  crt_box_message("Provisioning finished!", "Finished", "Info")
  return None

def mainmenu11() -> None:
  """ Make one access port """

  # check for active connection
  if not crt_object.Session.Connected:
    crt_box_message("Sending data requires an active connection, Exiting!", "Error", "Stop")
    return None

  # lock session to prevent accidental keyboard input
  crt_object.Session.Lock()

  # set session config parameters
  crt_session_config(crt_object)

  # verify connected device and mode
  if check_exec_mode({}, crt_object) is False:
    crt_box_message("No device detected", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get modelno
  model = get_model(checks["modelsfile"], crt_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get management vlan
  for _ in range(3):
    crt_object.Screen.Send(r"sh ip int brie | inc [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" + chr(13))
    result = crt_object.Screen.WaitForString("Vlan", 5)
    if result != 0:
      break
  else:
    crt_box_message("Error collecting management information, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  management = crt_object.Screen.ReadString(chr(13)).split()

  networks = read_jsonfile(checks["networksfile"])
  if networks["status"] == "error":
    crt_box_message("Error reading networks file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if networks.get(management[0]) is not None:
    network = networks[management[0]]
    network["vlan"] = management[0]
  else:
    crt_box_message("Unknown vlan, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # input interface name
  if model["interfaces"]["access"] is False:
    port_example = ""
  else:
    port_example = model["interfaces"]["access"]["prefix"] + model["interfaces"]["access"]["first"]
  interface = crt_box_dialogue(port_example, "", "Interface")
  if interface["status"] == "fail":
    crt_object.Session.Unlock()
    return None

  # enter config mode
  crt_sendline("conf t", crt_object)

  crt_sendline("default interface " + interface["text"], crt_object)
  crt_sendline("interface " + interface["text"], crt_object)
  crt_sendline("shut", crt_object)
  port_access(model, network, crt_object)
  crt_sendline("no shut", crt_object)

  # back to exec mode
  crt_sendline("end", crt_object)

  # saving
  crt_object.Screen.Send("write memory" + chr(13))
  crt_object.Screen.WaitForString("[OK]")

  # update interface in solarwinds
  if check_web_server(checks["settings"]["Solarwinds"]["URL"], checks["settings"]["Solarwinds"]["APIport"], checks["settings"]["Solarwinds"]["verifycert"]) is False:
    crt_box_message("Cannot update interface unpluggable setting\nPlease update the interface manually", "Solarwinds", "Info")
  else:
    result_update = sol_update_int2(management[1], interface["text"], True, checks["secret"], checks["settings"])
    if result_update["status"] != "success":
      crt_box_message("Error updating interface", "Solarwinds", "Info")

  # finished
  crt_object.Session.Unlock()
  crt_box_message("Provisioning finished!", "Finished", "Info")
  return None

def mainmenu12() -> None:
  """ Make one KBN trunk port """

  # check for active connection
  if not crt_object.Session.Connected:
    crt_box_message("Sending data requires an active connection, Exiting!", "Error", "Stop")
    return None

  # lock session to prevent accidental keyboard input
  crt_object.Session.Lock()

  # set session config parameters
  crt_session_config(crt_object)

  # verify connected device and mode
  if check_exec_mode({}, crt_object) is False:
    crt_box_message("No device detected", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get modelno
  model = get_model(checks["modelsfile"], crt_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting script!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get management vlan
  for _ in range(3):
    crt_object.Screen.Send(r"sh ip int brie | inc [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" + chr(13))
    result = crt_object.Screen.WaitForString("Vlan", 5)
    if result != 0:
      break
  else:
    crt_box_message("Error collecting management information, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  management = crt_object.Screen.ReadString(chr(13)).split()

  networks = read_jsonfile(checks["networksfile"])
  if networks["status"] == "error":
    crt_box_message("Error reading networks file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if networks.get(management[0]) is not None:
    network = networks[management[0]]
    network["vlan"] = management[0]
  else:
    crt_box_message("Unknown vlan, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get list of vlans
  vlan_local = network["vlan"] + ","
  if network["quarantine"] is not False:
    vlan_local += network["quarantine"]["id"] + ","
  if network["voice"] is not False:
    vlan_local += network["voice"]["id"] + ","

  # verify input value
  result = crt_box_dialogue(vlan_local, "Trunk", "Vlans")
  if result["status"] == "fail":
    crt_object.Session.Unlock()
    return None
  vlan_all = result["text"]

  # input interface name
  if model["interfaces"]["trunk"] is False:
    port_example = ""
  else:
    port_example = model["interfaces"]["trunk"]["prefix"] + model["interfaces"]["trunk"]["first"]
  interface = crt_box_dialogue(port_example, "", "Interface")
  if interface["status"] == "fail":
    crt_object.Session.Unlock()
    return None

  # enter config mode
  crt_sendline("conf t", crt_object)

  # collect vlans to add to database
  vlan_add = set(vlan_all.split(",")) - set(vlan_local.split(",")) # remove predefined vlans
  if len(vlan_add) != 0: # added 2022-09-23
    result = add_vlan(checks["vlansfile"], (",").join(vlan_add), crt_object)
    if result["status"] == "error":
      crt_box_message("Error adding vlans, check config", "Error", "Stop")
      crt_sendline("end", crt_object)
      return None

  # set high stp prio to prevent from becoming root
  crt_sendline("no spanning-tree vlan 2-4094 priority 61440", crt_object) # added 2022-09-23

  # do the port
  crt_sendline("default interface " + interface["text"], crt_object)
  crt_sendline("interface " + interface["text"], crt_object)
  crt_sendline("shut", crt_object)
  port_trunk(model, crt_object)
  crt_sendline("description T2KBN", crt_object)
  crt_sendline("switchport trunk all vlan " + vlan_all, crt_object)
  crt_sendline("no shut", crt_object)

  # back to exec mode
  crt_sendline("end", crt_object)

  # saving
  crt_object.Screen.Send("write memory" + chr(13))
  crt_object.Screen.WaitForString("[OK]")

  # update interface in solarwinds
  if check_web_server(checks["settings"]["Solarwinds"]["URL"], checks["settings"]["Solarwinds"]["APIport"], checks["settings"]["Solarwinds"]["verifycert"]) is False:
    crt_box_message("Cannot update interface unpluggable setting\nPlease update the interface manually", "Solarwinds", "Info")
  else:
    result_update = sol_update_int2(management[1], interface["text"], False, checks["secret"], checks["settings"])
    if result_update["status"] != "success":
      crt_box_message("Error updating interface", "Solarwinds", "Info")

  # finished
  crt_object.Session.Unlock()
  crt_box_message("Provisioning finished!", "Finished", "Info")
  return None

def mainmenu13() -> None:
  """ Make one external access port """

  # check for active connection
  if not crt_object.Session.Connected:
    crt_box_message("Sending data requires an active connection, Exiting!", "Error", "Stop")
    return None

  # lock session to prevent accidental keyboard input
  crt_object.Session.Lock()

  # set session config parameters
  crt_session_config(crt_object)

  # verify connected device and mode
  if check_exec_mode({}, crt_object) is False:
    crt_box_message("No device detected", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get modelno
  model = get_model(checks["modelsfile"], crt_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting script!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get management vlan
  for _ in range(3):
    crt_object.Screen.Send(r"sh ip int brie | inc [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" + chr(13))
    result = crt_object.Screen.WaitForString("Vlan", 5)
    if result != 0:
      break
  else:
    crt_box_message("Error collecting management information, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  management = crt_object.Screen.ReadString(chr(13)).split()

  networks = read_jsonfile(checks["networksfile"])
  if networks["status"] == "error":
    crt_box_message("Error reading networks file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if networks.get(management[0]) is not None:
    network = networks[management[0]]
    network["vlan"] = management[0]
  else:
    crt_box_message("Unknown vlan, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # input interface name
  if model["interfaces"]["access"] is False:
    port_example = ""
  else:
    port_example = model["interfaces"]["access"]["prefix"] + model["interfaces"]["access"]["first"]
  interface = crt_box_dialogue(port_example, "", "Interface")
  if interface["status"] == "fail":
    crt_object.Session.Unlock()
    return None

  # input vlan
  vlan = crt_box_dialogue("", "Vlan number", "Vlan")
  if vlan["status"] == "fail":
    crt_object.Session.Unlock()
    return None

  # get list of vlans and info
  vlaninfo = read_jsonfile(checks["vlansfile"])

  # verify that vlan exist
  if vlan["text"] not in vlaninfo:
    crt_box_message("Unknown vlan id", "Error", "Warn")
    crt_object.Session.Unlock()
    return None

  # make sure it is a applicable port
  if vlaninfo[vlan["text"]]["profile"] is False:
    crt_box_message("Vlan cannot be used in a external port", "Error", "Warn")
    crt_object.Session.Unlock()
    return None

  # enter config mode
  crt_sendline("conf t", crt_object)

  # cannot add vlans
  result = add_vlan(checks["vlansfile"], vlan["text"], crt_object)
  if result["status"] == "error":
    crt_box_message("Error adding vlans, check config", "Error", "Warn")

  # ios xe
  if model["image"]["xe"] is True:
    crt_sendline("device-tracking policy " + vlaninfo[vlan["text"]]["policy"], crt_object)
    crt_sendline(" limit address-count " + vlaninfo[vlan["text"]]["usage"], crt_object)
    crt_sendline(" tracking enable", crt_object)
    crt_sendline("exit", crt_object)

  # write interface config
  crt_sendline("default interface " + interface["text"], crt_object)
  crt_sendline("interface " + interface["text"], crt_object)
  crt_sendline("shut", crt_object)
  crt_sendline("description *** " + vlaninfo[vlan["text"]]["name"].replace("#", "").lower(), crt_object)
  crt_sendline("switchport mode access", crt_object)
  crt_sendline("switchport access vlan " + vlan["text"], crt_object)
  crt_sendline("switchport nonegotiate", crt_object)
  crt_sendline("spanning-tree portfast", crt_object)
  crt_sendline("no cdp enable", crt_object)
  crt_sendline("no snmp trap link-status", crt_object)
  crt_sendline("no shut", crt_object)

  # back to exec mode
  crt_sendline("end", crt_object)

  # saving
  crt_object.Screen.Send("write memory" + chr(13))
  crt_object.Screen.WaitForString("[OK]")

  # update interface in solarwinds
  if check_web_server(checks["settings"]["Solarwinds"]["URL"], checks["settings"]["Solarwinds"]["APIport"], checks["settings"]["Solarwinds"]["verifycert"]) is False:
    crt_box_message("Cannot update interface unpluggable setting\nPlease update the interface manually", "Solarwinds", "Info")
  else:
    result_update = sol_update_int2(management[1], interface["text"], True, checks["secret"], checks["settings"])
    if result_update["status"] != "success":
      crt_box_message("Error updating interface", "Solarwinds", "Info")

  # finished
  crt_box_message("Provisioning finished!", "Finished", "Info")
  crt_object.Session.Unlock()
  return None

def mainmenu14() -> None:
  """ Make one ISE exception """

  # check for active connection
  if not crt_object.Session.Connected:
    crt_box_message("Sending data requires an active connection, Exiting!", "Error", "Stop")
    return None

  # lock session to prevent accidental keyboard input
  crt_object.Session.Lock()

  # set session config parameters
  crt_session_config(crt_object)

  # verify connected device and mode
  if check_exec_mode({}, crt_object) is False:
    crt_box_message("No device detected", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get modelno
  model = get_model(checks["modelsfile"], crt_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting script!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get management vlan
  for _ in range(3):
    crt_object.Screen.Send(r"sh ip int brie | inc [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" + chr(13))
    result = crt_object.Screen.WaitForString("Vlan", 5)
    if result != 0:
      break
  else:
    crt_box_message("Error collecting management information, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  management = crt_object.Screen.ReadString(chr(13)).split()

  networks = read_jsonfile(checks["networksfile"])
  if networks["status"] == "error":
    crt_box_message("Error reading networks file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if networks.get(management[0]) is not None:
    network = networks[management[0]]
    network["vlan"] = management[0]
  else:
    crt_box_message("Unknown vlan, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # input interface name
  if model["interfaces"]["trunk"] is False:
    port_example = ""
  else:
    port_example = model["interfaces"]["access"]["prefix"] + model["interfaces"]["access"]["first"]
  interface = crt_box_dialogue(port_example, "", "Interface")
  if interface["status"] == "fail":
    crt_object.Session.Unlock()
    return None

  # input vlan
  vlan = crt_box_dialogue("", "Vlan number", "Vlan")
  if vlan["status"] == "fail":
    crt_object.Session.Unlock()
    return None

  # enter config mode
  crt_sendline("conf t", crt_object)

  # check and add vlan
  result = add_vlan(checks["vlansfile"], vlan["text"], crt_object)
  if result["status"] == "error":
    crt_box_message("Error adding vlans, check config", "Error", "Stop")
    crt_sendline("end", crt_object)
    crt_object.Session.Unlock()
    return None

  crt_sendline("default int " + interface["text"], crt_object)
  crt_sendline("interface " + interface["text"], crt_object)
  crt_sendline("shut", crt_object)
  port_access(model, network, crt_object)
  crt_sendline("description ISE" + " vlan" + vlan["text"], crt_object)
  crt_sendline("switchport access vlan " + vlan["text"], crt_object)
  crt_sendline("no shut", crt_object)

  # back to exec mode
  crt_sendline("end", crt_object)

  # saving
  crt_object.Screen.Send("write memory" + chr(13))
  crt_object.Screen.WaitForString("[OK]")

  # finished
  crt_object.Session.Unlock()
  crt_box_message("Provisioning finished!", "Finished", "Info")
  return None

def mainmenu15() -> None:
  """ Default one port and set as free """

  # check for active connection
  if not crt_object.Session.Connected:
    crt_box_message("Sending data requires an active connection, Exiting!", "Error", "Stop")
    return None

  # lock session to prevent accidental keyboard input
  crt_object.Session.Lock()

  # set session config parameters
  crt_session_config(crt_object)

  # get modelno
  model = get_model(checks["modelsfile"], crt_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting script!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None

  # get management vlan
  for _ in range(3):
    crt_object.Screen.Send(r"sh ip int brie | inc [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" + chr(13))
    result = crt_object.Screen.WaitForString("Vlan", 5)
    if result != 0:
      break
  else:
    crt_box_message("Error collecting management information, Exiting!", "Error", "Stop")
    crt_object.Session.Unlock()
    return None
  management = crt_object.Screen.ReadString(chr(13)).split()

  # input interface name
  if model["interfaces"]["access"] is False:
    port_example = ""
  else:
    port_example = model["interfaces"]["access"]["prefix"] + model["interfaces"]["access"]["first"]
  interface = crt_box_dialogue(port_example, "", "Interface")
  if interface["status"] == "fail":
    crt_object.Session.Unlock()
    return None

  # enter config mode
  crt_sendline("conf t", crt_object)

  # write interface config
  crt_sendline("default interface " + interface["text"], crt_object)
  crt_sendline("interface " + interface["text"], crt_object)
  crt_sendline("shut", crt_object)
  crt_sendline("desc *** FREE", crt_object)

  # back to exec mode
  crt_sendline("end", crt_object)

  # saving
  crt_object.Screen.Send("write memory" + chr(13))
  crt_object.Screen.WaitForString("[OK]")

  # update interface in solarwinds
  if check_web_server(checks["settings"]["Solarwinds"]["URL"], checks["settings"]["Solarwinds"]["APIport"], checks["settings"]["Solarwinds"]["verifycert"]) is False:
    crt_box_message("Cannot update interface unpluggable setting\nPlease update the interface manually", "Solarwinds", "Info")
  else:
    result_update = sol_update_int2(management[1], interface["text"], False, checks["secret"], checks["settings"])
    if result_update["status"] != "success":
      crt_box_message("Error updating interface", "Solarwinds", "Info")

  # finished
  crt_box_message("Provisioning finished!", "Finished", "Info")
  crt_object.Session.Unlock()
  return None

def mainmenu20() -> None:
  """ Update Id group of endpoint """

  # verify that all needed servers are reachable
  if check_web_server(checks["settings"]["ISE"]["PAN"]["URL"], checks["settings"]["ISE"]["PAN"]["APIport"], checks["settings"]["ISE"]["PAN"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "Error", "Stop")
    return None

  # get the groups file and remove the result key
  groups = read_jsonfile(checks["groupsfile"])
  if groups["status"] == "error":
    crt_box_message("Error reading groups file, Exiting!", "Error", "Stop")
    return None
  groups.pop("status", None)

  # assemble the menu
  for number, name in enumerate(groups):
    if number == 0:
      # very first row
      menu = "  " + name + "  " + groups[name]["name"]
    else:
      if len(name) == 1:
        # fix for securecrt
        menu += "\n" + "  " + name + "  " + groups[name]["name"]
      else:
        menu += "\n" + name + "  " + groups[name]["name"]

  # print menu and wait for input
  result = crt_box_input(menu, "Select Id group", "")

  if result == "" or result not in groups:
    return None
  group_id = groups[result]["id"] # endpoint group id
  profile_id = groups[result]["profile"] # endpoint profile id

  # prompt for mac and validate
  result = crt_box_input("Enter one mac address or comma separated list:", "MAC", "")
  if result == "":
    # cancel or x
    return None
  vmacs = result.split(",") # verified mac
  for vmacs_row in vmacs:
    vmac = validate_mac(vmacs_row)
    # if correct format update the endpoint
    if vmac["status"] == "error":
      crt_box_message("MAC format error, Exiting!", "Error", "Warn")
      break

    result_update = ise_update_endpoint(vmac["eui"], group_id, profile_id, checks["secret"], checks["settings"])
    if result_update["status"] == "error":
      crt_box_message("Error communicating with server, Exiting!", "Error", "Warn")
    elif result_update["status"] == "not found":
      crt_box_message("Endpoint " + vmacs_row + " not found", "Error", "Warn")
    else:
      crt_box_message("Endpoint " + vmacs_row + " updated", "Success", "Warn")

  # finished
  return None

def mainmenu30() -> None:
  """ Show client details from mac """
  import datetime

  # verify that all needed servers are reachable
  if check_web_server(checks["settings"]["DNAC"]["URL"], checks["settings"]["DNAC"]["APIport"], checks["settings"]["DNAC"]["verifycert"]) is False:
    crt_box_message("No connection to webserver or certificate error", "Error", "Stop")
    return None

  # ask for mac address
  mac = crt_box_dialogue("", "", "MAC")
  if mac["status"] == "fail":
    return None

  # validate mac
  vmac = validate_mac(mac["text"])
  if vmac["status"] == "error":
    crt_box_message("MAC format error, Exiting!", "Error", "Stop")
    return None

  # get token
  dna_token = dna_get_token(checks["settings"], checks["secret"])
  if dna_token["status"] == "error":
    crt_box_message("Error getting token", "Error", "Warn")
    return None

  # get client details
  dna_client = dna_client_detail(checks["settings"], dna_token["token"], vmac["eui"])
  if dna_client["status"] == "error":
    crt_box_message("Error getting client details", "Error", "Warn")
    return None

  # show the details
  if len(dna_client["detail"]) == 0:
    # unknown client, no details
    crt_box_message("Unknown client", "Client details", "Info")
  else:
    # set time variables
    timestamp = datetime.datetime.now()
    client_timestamp = datetime.datetime.fromtimestamp(float(dna_client["detail"]["lastUpdated"])/1000)

    # general
    client_details = "Client is " + dna_client["detail"]["hostType"] + " and is " + dna_client["detail"]["connectionStatus"] + "\n"
    if dna_client["detail"]["connectionStatus"] == "DISCONNECTED":
      client_details += "Connected " + str((timestamp-client_timestamp).days) + " days ago \n"
    client_details += "Client ipadress is" + str(dna_client["detail"]["hostIpV4"]) + "\n"
    client_details += "Client is a " + str(dna_client["detail"]["subType"]) + "\n"
    client_details += "Client hostname is " + str(dna_client["detail"]["hostName"]) + "\n"
    client_details += "Client location is " + str(dna_client["detail"]["location"]) + "\n"
    client_details += "Logged in user " + str(dna_client["detail"]["userId"]) + "\n"
    client_details += "Connected to " + str(dna_client["detail"]["clientConnection"]) + "\n"

    # WIRED
    if dna_client["detail"]["hostType"] == "WIRED":
      client_details += "... on port " + dna_client["detail"]["port"] + "\n"

    # WIRELESS
    if dna_client["detail"]["hostType"] == "WIRELESS" and dna_client["detail"]["connectionStatus"] == "CONNECTED":
      client_details += "RSSI is " + dna_client["detail"]["rssi"] + "dB \n"
      client_details += "SNR is " + dna_client["detail"]["snr"] + "dB \n"
      client_details += "Datarate is " + dna_client["detail"]["dataRate"] + "\n"
      client_details += "Spatial Streams is " + dna_client["connectionInfo"]["spatialStream"] + "\n"
      client_details += "Wireless protocol is " + dna_client["connectionInfo"]["protocol"] + "\n"
      client_details += "Channel is " + dna_client["connectionInfo"]["channel"] + "\n"
      client_details += "Radio band is " + dna_client["connectionInfo"]["band"] + "\n"
      client_details += "Channel width is " + dna_client["connectionInfo"]["channelWidth"] + "\n"

    # display the details
    if dna_client["detail"]["hostType"] == "WIRED" and dna_client["detail"]["connectionStatus"] == "CONNECTED":
      client_details += "" + "\n"
      client_details += "Do you want to connect to this device?"
      result = crt_box_yes_no(client_details, "Client details")
    else:
      crt_box_message(client_details, "Client details", "Info")
      return None

    # make connection to device
    if result is True:
      device_dict = dns_query(dna_client["detail"]["clientConnection"].split("_")[3], checks["settings"])
      if device_dict["status"] != "success":
        return None

      # set username and password
      ssh_cred = {}
      if checks["personalsettings"]["credentials"]["tacacs"] not in ("False", ""):
        # configuation manager is used
        ssh_cred["username"] = ""
        ssh_cred["password"] = ""
        ssh_cred["ConfigManager"] = checks["personalsettings"]["credentials"]["tacacs"]

      # start ssh session
      ssh_session = crt_connect_ssh_start(device_dict["ip"], ssh_cred, False, {}, {}, True)
      if ssh_session["status"] != "success":
        crt_box_message("Error connecting to device", "Error", "Warn")
        return None

      # return value to exit script
      return None

  # finished
  return None

def mainmenu31() -> None:
  """ Show auth session on all access ports """
  import re

  # set username and password
  ssh_cred = {}
  if checks["personalsettings"]["credentials"]["tacacs"] in ("False", ""):
    # configuration manager is not used
    ssh_cred["username"] = crt_box_input("Enter your username", "Tacacs", "")
    if ssh_cred["username"] == "":
      return None
    ssh_cred["password"] = crt_box_input("Enter password", "Tacacs", "", True)
    if ssh_cred["password"] == "":
      return None
    ssh_cred["ConfigManager"] = ""
  else:
    # configuation manager is used
    ssh_cred["username"] = ""
    ssh_cred["password"] = ""
    ssh_cred["ConfigManager"] = checks["personalsettings"]["credentials"]["tacacs"]

  # enter device info
  device = crt_box_input("Enter ip address or hostname of device", "Device info", "")
  if device == "":
    # cancel or x
    return None
  device = device.strip()
  if re.search(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", device, re.MULTILINE): # regexr.com/5ke5o
    # ip address
    device_dict = {"ip": device}
  elif re.search("^[0-9]{4}$", device, re.MULTILINE):
    # inventory number
    device_dict = dns_query(device, checks["settings"])
    if device_dict["status"] != "success":
      return None
  else:
    # wrong entry
    return None

  # is it alive?
  if ping(device_dict["ip"], checks["systemenv"])["status"] != "success":
    crt_box_message("Device unresponsive, Exiting!", "Error", "Stop")
    return None

  # start ssh session
  ssh_session = crt_connect_ssh_start(device_dict["ip"], ssh_cred, False, {}, {}, False)
  if ssh_session["status"] != "success":
    crt_box_message("Error connecting to device", "Error", "Warn")
    return None
  crt_tab_object = ssh_session["crt_tab_object"]

  # determine model number
  model = get_model(checks["modelsfile"], crt_tab_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting!", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None

  # check for cluster
  prefixes = get_cluster(model, crt_tab_object)
  if prefixes["status"] == "error":
    crt_box_message("Error collecting cluster status, Exiting!", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None

  # create list of commands
  command = []
  if "access" in prefixes:
    for cluster in prefixes["access"]:
      model["interfaces"]["access"]["prefix"] = cluster
      for port_num in range(int(model["interfaces"]["access"]["first"]),int(model["interfaces"]["access"]["last"]) + 1):
        command.append("sh auth sess int " + model["interfaces"]["access"]["prefix"] + str(port_num) + " det | inc Interface|IPv4|MAC")

  if "multigig" in prefixes:
    for cluster in prefixes["multigig"]:
      model["interfaces"]["multigig"]["prefix"] = cluster
      for port_num in range(int(model["interfaces"]["multigig"]["first"]),int(model["interfaces"]["multigig"]["last"]) + 1):
        command.append("sh auth sess int " + model["interfaces"]["multigig"]["prefix"] + str(port_num) + " det | inc Interface|IPv4|MAC")

  # walk through list of commands and add to list
  output = []
  for i in command:
    crt_tab_object.Screen.Send(i.strip() + chr(13))
    crt_tab_object.Screen.WaitForString(chr(13))
    output.append(crt_tab_object.Screen.ReadString("#"))
    crt_object.Sleep(175) # 175ms delay

  # remove unwanted lines
  result = []
  selector = ":"
  for number in enumerate(output):
    for row in output[number[0]].split("\n"):
      if selector in row:
        result.append(row.strip())

  # add header
  table = "{:<20} {:<15} {:<20}".format("Interface", "MAC address", "IP address") + "\n" # pylint: disable=consider-using-f-string

  # add rows to table
  auth = []
  count = 0
  for row in result:
    auth.append(row.split(":")[1].strip())
    count += 1
    if count == 3:
      table += "{:<20} {:<15} {:<20}".format(auth[0], auth[1], auth[2]) + "\n" # pylint: disable=consider-using-f-string
      auth.clear()
      count = 0

  # end ssh session
  crt_connect_ssh_end(crt_tab_object, False)

  # print table
  crt_box_message(table, "Report", "Info")

  # finished
  return None

def mainmenu32() -> None:
  """ Show last input on all access ports """
  import re

  # set username and password
  ssh_cred = {}
  if checks["personalsettings"]["credentials"]["tacacs"] in ("False", ""):
    # configuration manager is not used
    ssh_cred["username"] = crt_box_input("Enter your username", "Tacacs", "")
    if ssh_cred["username"] == "":
      return None
    ssh_cred["password"] = crt_box_input("Enter password", "Tacacs", "", True)
    if ssh_cred["password"] == "":
      return None
    ssh_cred["ConfigManager"] = ""
  else:
    # configuration manager is used
    ssh_cred["username"] = ""
    ssh_cred["password"] = ""
    ssh_cred["ConfigManager"] = checks["personalsettings"]["credentials"]["tacacs"]

  # enter device info
  device = crt_box_input("Enter ip address or hostname of device", "Device info", "")
  if device == "":
    # cancel or x
    return None
  device = device.strip()
  if re.search(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", device, re.MULTILINE): # regexr.com/5ke5o
    # ip address
    device_dict = {"ip": device}
  elif re.search("^[0-9]{4}$", device, re.MULTILINE):
    # inventory number
    device_dict = dns_query(device, checks["settings"])
    if device_dict["status"] != "success":
      return None
  else:
    # wrong entry
    return None

  # is it alive?
  if ping(device_dict["ip"], checks["systemenv"])["status"] != "success":
    crt_box_message("Device unresponsive, Exiting!", "Error", "Stop")
    return None

  # start ssh session
  ssh_session = crt_connect_ssh_start(device_dict["ip"], ssh_cred, False, {}, {}, False)
  if ssh_session["status"] != "success":
    crt_box_message("Error connecting to device", "Error", "Warn")
    return None
  crt_tab_object = ssh_session["crt_tab_object"]

  # determine model number
  model = get_model(checks["modelsfile"], crt_tab_object)
  if model["status"] == "nomatch":
    crt_box_message("Unknown device, Exiting!", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None
  if model["status"] == "error":
    crt_box_message("Error reading models file, Exiting!", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None

  # check for cluster
  prefixes = get_cluster(model, crt_tab_object)
  if prefixes["status"] == "error":
    crt_box_message("Error collecting cluster status, Exiting!", "Error", "Stop")
    crt_connect_ssh_end(crt_tab_object, False)
    return None

  # create list of commands
  command = []
  interface = []
  if "access" in prefixes:
    for prefix in prefixes["access"]:
      for port_num in range(int(model["interfaces"]["access"]["first"]),int(model["interfaces"]["access"]["last"]) + 1):
        interface.append(prefix + str(port_num))
        command.append("show interface " + interface[-1] + " | inc Last input")

  if len(prefixes["multigig"]) != 0:
    for prefix in prefixes["interfaces"]["multigig"]:
      for port_num in range(int(model["interfaces"]["multigig"]["first"]),int(model["interfaces"]["multigig"]["last"]) + 1):
        interface.append(prefix + str(port_num))
        command.append("show interface " + interface[-1] + " | inc Last input")

  # walk through list of commands and add to list
  output = []
  for i in command:
    crt_tab_object.Screen.Send(i.strip() + chr(13))
    crt_tab_object.Screen.WaitForString(chr(13))
    output.append(crt_tab_object.Screen.ReadString("#"))
    crt_object.Sleep(175) # 175ms delay

  # remove unwanted lines
  result = []
  selector = "output"
  for number in enumerate(output):
    for row in output[number[0]].split("\n"):
      if selector in row:
        result.append(row.strip())

  # add header
  table = "{:<10} {:<15}".format("Interface", "Result") + "\n" # pylint: disable=consider-using-f-string

  # add rows to table
  for port, row in zip(interface, result):
    table += "{:<10} {:<15}".format(port, row) + "\n" # pylint: disable=consider-using-f-string

  # end ssh session
  crt_connect_ssh_end(crt_tab_object, False)

  # print table
  crt_box_message(table, "Report", "Info")

  # finished
  return None

def mainmenu40() -> None:
  """ Connect all serial ports and exit """

  # create serial sessions
  serials = crt_connect_serial(checks["settings"], checks["systemenv"], True)
  if serials["status"] == "error":
    crt_box_message("Cannot create serial session", "Error", "Stop")
    return None

  # finished
  return None

def mainmenu41() -> None:
  """ Connect one RDP session and exit """

  # create rdp session
  device = crt_box_input("Enter ipaddress or hostname", "Devicename", "")
  if device != "":
    crt_connect_rdp(device, checks["personalsettings"]["credentials"]["rdp"])

  # finished
  return  None

def mainmenu42() -> None:
  """ Connect one SSH session and exit """
  import re

  # verify name or ip
  device = crt_box_input("Enter ipaddress or hostname", "Devicename", "")
  device = device.strip()
  if re.search(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", device, re.MULTILINE): # regexr.com/5ke5o
    # ip address
    device_dict = {"ip": device}
  elif re.search("^[0-9]{4}$", device, re.MULTILINE):
    # inventory number
    device_dict = dns_query(device, checks["settings"])
    if device_dict["status"] != "success":
      return None
  else:
    # wrong entry
    return  None

  # set username and password
  ssh_cred = {}
  if checks["personalsettings"]["credentials"]["tacacs"] not in ("False", ""):
    # configuation manager is used
    ssh_cred["username"] = ""
    ssh_cred["password"] = ""
    ssh_cred["ConfigManager"] = checks["personalsettings"]["credentials"]["tacacs"]

  # start ssh session
  ssh_session = crt_connect_ssh_start(device_dict["ip"], ssh_cred, False, {}, {}, True)
  if ssh_session["status"] != "success":
    crt_box_message("Error connecting to device", "Error", "Warn")
    return None

  # finished
  return  None

def mainmenu50() -> None:
  """ Run quickfix on multiple devices """
  import re

  # set username and password
  ssh_cred = {}
  if checks["personalsettings"]["credentials"]["tacacs"] in ("False", ""):
    # configuration manager is not used
    ssh_cred["username"] = crt_box_input("Enter your username", "Tacacs", "")
    if ssh_cred["username"] == "":
      return None
    ssh_cred["password"] = crt_box_input("Enter password", "Tacacs", "", True)
    if ssh_cred["password"] == "":
      return None
    ssh_cred["ConfigManager"] = ""
  else:
    # configuation manager is used
    ssh_cred["username"] = ""
    ssh_cred["password"] = ""
    ssh_cred["ConfigManager"] = checks["personalsettings"]["credentials"]["tacacs"]

  # read file with ipaddresses
  file_ip = crt_object.Dialog.FileOpenDialog(title="File containing ipaddresses", filter="Text Files (*.txt)|*.txt||")
  if file_ip == "":
    return None
  with open(file_ip, "r", encoding="UTF-8") as ip_file:
    try:
      ip_list = ip_file.readlines()
    except OSError:
      crt_box_message("Error reading file, Exiting!", "Error", "Stop")
      return None

  # verify ipaddresses
  if not re.search(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip_list[0], re.MULTILINE): # regexr.com/5ke5o
    crt_box_message("Cannot verify ipaddress, Exiting!", "Error", "Stop")
    return None

  # read file with commands
  file_cmd = crt_object.Dialog.FileOpenDialog(title="File containing commands", filter="Text Files (*.txt)|*.txt||")
  if file_cmd == "":
    return None
  with open(file_cmd, "r", encoding="UTF-8") as cmd_file:
    try:
      cmd_list = cmd_file.readlines()
    except OSError:
      crt_box_message("Error reading file, Exiting!", "Error", "Stop")
      return None

  # walk through list of devices
  for device in ip_list:
    # is it alive?
    if ping(device.strip(), checks["systemenv"])["status"] != "success":
      crt_box_message("Device unresponsive, Exiting!", "Error", "Stop")
      return None

    # start ssh session
    ssh_session = crt_connect_ssh_start(device.strip(), ssh_cred, False, checks["systemenv"], checks["settings"], False)
    if ssh_session["status"] != "success":
      crt_box_message("Error connecting to device", "Error", "Warn")
      return None
    crt_tab_object = ssh_session["crt_tab_object"]

    # walk through list of commands and add to list
    output = []
    for i in cmd_list:
      crt_tab_object.Screen.Send(i.strip() + chr(13))
      crt_tab_object.Screen.WaitForString(chr(13))
      output.append(crt_tab_object.Screen.ReadString("#"))
      crt_object.Sleep(175) # 175ms delay

    # end sessions
    crt_connect_ssh_end(crt_tab_object, False)

    # detect faulty commands
    for row in output:
      if "Invalid input detected at" in row.strip():
        crt_box_message("Invalid command found, Exiting!", "Error", "Stop")
        return None
      if "Unrecognized command" in row.strip():
        crt_box_message("Invalid command found, Exiting!", "Error", "Stop")
        return None

  # finished
  return None

def mainmenu98() -> None:
  """ About """
  import webbrowser

  # open new tab in default browser
  webbrowser.open(checks["settings"]["doc_url"][checks["settings"]["usergroups"][checks["username"]][1]], new=2)

  # finished
  return None

def pre_checks() -> dict:
  """ checking prereqs and set variables """
  import os
  import webbrowser
  import platform
  import pkg_resources
  import re
  import datetime
  import subprocess
  import sys

  # get a point in time
  timestamp = datetime.datetime.now()

  # verify version of securecrt
  crt_version = re.split(r"\.|\s", crt_object.Version)
  if not (int(crt_version[0]) == 9 and int(crt_version[1]) in (2,3,4)): # 9.2 - 9.4
    crt_box_message("Unsupported SecureCRT version, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # verify version of python
  py_version = platform.python_version_tuple()
  if not (int(py_version[0]) == 3 and int(py_version[1]) in (9,10)): # 3.9 - 3.10
    crt_box_message("Unsupported Python version, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # set global option for single instance
  if crt_object.Config.GetOption("Single Instance") != 1:
    crt_object.Config.SetOption("Single Instance", 1)
    crt_object.Config.Save()

  # set global option for update from 9.3
  if (int(crt_version[0]) == 9 and int(crt_version[1]) >= 3):
    if crt_object.Config.GetOption("Check For Updates At Startup") != 1:
      crt_object.Config.SetOption("Check For Updates At Startup", 1)
      crt_object.Config.Save()

  # show running script in tab
  if crt_object.Config.GetOption("Show Script Indicator") != 1:
    crt_object.Config.SetOption("Show Script Indicator", 1)
    crt_object.Config.Save()

  # supported operating systems and its specific settings
  if platform.system() == "Windows":
    # windows
    systemenv = {
      "homePath": os.environ["USERPROFILE"], # home directory of user
      "pyExec": "py", # binary for python
      "comPort": "Com Port", # setting for com port
      "prompt": ">", # ending of prompt
      "pingOptions": "n" # options for ping
    }
  else:
    # none of the above
    crt_box_message("Unsupported operating system, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # set settings file
  settingsfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "provisioningfiles", "settings.json") # path to file with all settings
  if os.path.isfile(settingsfile) is False:
    crt_box_message("Settings file is missing, Exiting!", "Error", "Stop")
    return {"status": "error"}
  # read settings
  settings = read_jsonfile(settingsfile)
  if settings["status"] == "error":
    crt_box_message("Error reading settings file, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # set and verify username
  username = os.getlogin()
  if settings["usergroups"].get(username) is None:
    crt_box_message("Unknown or invalid username, Exiting!", "Error", "Stop")
    return {"status": "error"}
  group = settings["usergroups"][username][1]

  # set path to securecrt directory
  crt_path = os.path.join(systemenv["homePath"], *settings["onedrive"]["personal_documents"], *settings["SecureCRT"]["path"])

  # verify that required base dir for securecrt exist
  if os.path.isdir(crt_path) is False:
    os.mkdir(crt_path)
  # verify that required dir for script exist
  if os.path.isdir(os.path.join(crt_path, settings["SecureCRT"]["provisioning"])) is False:
    os.mkdir(os.path.join(crt_path, settings["SecureCRT"]["provisioning"]))
  # verify that required dir for logging in securecrt exist
  if os.path.isdir(os.path.join(crt_path, settings["SecureCRT"]["logs"])) is False:
    os.mkdir(os.path.join(crt_path, settings["SecureCRT"]["logs"]))
  # verify that required dir for backup in securecrt exist
  if os.path.isdir(os.path.join(crt_path, settings["SecureCRT"]["backup"])) is False:
    os.mkdir(os.path.join(crt_path, settings["SecureCRT"]["backup"]))

  # verify that infra teams channel files are synced
  if os.path.isdir(os.path.join(systemenv["homePath"], *settings["onedrive"][group])) is False:
    crt_box_message("Infra Teams files are not synced, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # upgrade python if needed
  if int(py_version[2]) < settings["Python"]["version3" + py_version[1]]:
    crt_box_message("Python needs to be upgraded, Exiting!", "Error", "Stop")
    update_file = os.path.join(systemenv["homePath"], *settings["onedrive"][settings["usergroups"][username][0]], *settings["Python"]["path"], settings["Python"]["filename" + platform.system() + "3" + py_version[1]])
    subprocess.Popen([update_file, "/passive", "InstallAllUsers=1", "PrependPath=1", "Include_launcher=1", "InstallLauncherAllUsers=1"], shell=True) # pylint: disable=consider-using-with
    crt_object.Quit() # quit securecrt

  # set secrets key file and validate it
  secretskeyfile = os.path.join(crt_path, settings["SecureCRT"]["provisioning"], "secret.key") # full path to key file from settings
  if os.path.isfile(secretskeyfile) is False:
    crt_box_message("Secret key file is missing! Downloading...\nSave it as " + secretskeyfile, "Error", "Stop")
    webbrowser.open(settings["secretskeyfile"][settings["usergroups"][username][0]]["url"], new=2)
    return {"status": "error"}
  result = validate_hash(secretskeyfile, settings["secretskeyfile"][group]["hash"])
  if result["status"] == "fail":
    # hash mismatch
    crt_box_message("Secret key file is outdated! Downloading...\nSave it as " + secretskeyfile, "Error", "Stop")
    webbrowser.open(settings["secretskeyfile"][settings["usergroups"][username][0]]["url"], new=2)
    return {"status": "error"}
  if result["status"] == "error":
    # error reading file
    return {"status": "error"}
  # set personal settings file
  personalsettingsfile = os.path.join(crt_path, settings["SecureCRT"]["provisioning"], "personalsettings.json") # full path to personal settings file
  if os.path.isfile(personalsettingsfile) is False:
    # file does not exist
    personalsettings = {} # create dict
  else:
    # read personal settings
    personalsettings = read_jsonfile(personalsettingsfile)
    if personalsettings["status"] == "error":
      crt_box_message("Error reading personal settings file, Exiting!", "Error", "Stop")
      return {"status": "error"}

  # temp migrate old settings by removing them
  if isinstance(personalsettings.get("lastrun"), list):
    personalsettings.pop("lastrun")
  if isinstance(personalsettings.get("lastrun_backup"), list):
    personalsettings.pop("lastrun_backup")

  # get lastrun values and add missing items
  if personalsettings.get("lastrun") is None:
    # first element missing
    personalsettings["lastrun"] = {} # create dict
  if "update" not in personalsettings.get("lastrun", ""):
    lastrun_update = datetime.date(1970, 1, 1)
  else:
    lastrun_update = datetime.date(personalsettings["lastrun"]["update"][0], personalsettings["lastrun"]["update"][1], personalsettings["lastrun"]["update"][2])
  if "backup" not in personalsettings.get("lastrun", ""):
    lastrun_backup = datetime.date(1970, 1, 1)
  else:
    lastrun_backup = datetime.date(personalsettings["lastrun"]["backup"][0], personalsettings["lastrun"]["backup"][1], personalsettings["lastrun"]["backup"][2])

  # get credential values and add missing keys
  if personalsettings.get("credentials") is None:
    # first element missing
    personalsettings["credentials"] = {} # create dict

    # temp migrate old settings by translating them
    if "ConfigManager" in personalsettings:
      # migrate
      personalsettings["credentials"]["tacacs"] = personalsettings["ConfigManager"]
      personalsettings.pop("ConfigManager")
    result = put_personal_settings(personalsettingsfile, personalsettings)
    if result["status"] != "success":
      # error in writing personal settingsfile
      crt_box_message("Error writing personal settings", "Error", "Warn")

  # configuration manager for ssh
  if personalsettings["credentials"].get("tacacs") in (None, ""):
    # not previously set
    ctitle = crt_box_input("Please enter label for SSH credentials, or cancel for none.\nType False to never use this feature", "Credentials", "")
    # set config manager title and save file
    personalsettings["credentials"]["tacacs"] = ctitle
    if personalsettings["credentials"]["tacacs"].capitalize() == "False":
      personalsettings["credentials"]["tacacs"] = "False"
    result = put_personal_settings(personalsettingsfile, personalsettings)
    if result["status"] != "success":
      # error in writing personal settingsfile
      crt_box_message("Error writing personal settings", "Error", "Warn")

  # configuration manager for rdp
  #if personalsettings["credentials"].get("rdp") in (None, ""):
  #  ctitle = crt_box_input("Please enter label for RDP credentials, or cancel for none.\nType False to never use this feature", "Credentials", "")
  #  # set config manager title and save file
  #  personalsettings["credentials"]["rdp"] = ctitle
  #  if personalsettings["credentials"]["rdp"].capitalize() == "False":
  #    personalsettings["credentials"]["rdp"] = "False"
  #  result = put_personal_settings(personalsettingsfile, personalsettings)
  #  if result["status"] != "success":
  #    # error in writing personal settingsfile
  #    crt_box_message("Error writing personal settings", "Error", "Warn")

  # verify required packages
  installed = set(pkg_resources.working_set.by_key.keys()) # currently installed packages
  required = {"requests", "python-certifi-win32", "cryptography", "orionsdk", "pyserial", "pip", "openpyxl", "pandas", "passlib", "backports.pbkdf2", "scrypt", "pypsrp"} # required packages
  missing = required - installed # get whats missing only
  if len(missing) != 0:
    # packages are missing
    if ping(settings["testhost"], systemenv)["status"] == "success":
      # internet access exist so install missing package
      crt_box_message("Missing packages will be installed now", "Error", "Warn")
      command = [systemenv["pyExec"] + " -m pip install " + " ".join(missing)]
      result_install = crt_connect_cmd(command, "Install modules", systemenv, settings)
      if result_install["status"] == "success":
        crt_box_message("Missing packages installed, restart SecureCRT!", "Packages", "Info")
      else:
        crt_box_message("Missing packages not installed", "Error", "Stop")
    else:
      # missing internet access
      crt_box_message("Missing packagess cannot be installed without internet access, Exiting!", "Error", "Stop")
    crt_object.Quit() # quit securecrt

  # upgrade packages
  datediff = timestamp.date() - lastrun_update # get diff from last run
  if datediff.days > 31 and ping(settings["testhost"], systemenv)["status"] == "success":
    # more than 31 days since last update and online
    crt_box_message("Package update will be performed now, please wait", "Update", "Info")
    command = [systemenv["pyExec"] + " -m pip install --upgrade " + " ".join(required)]
    result_upgrade = crt_connect_cmd(command, "Upgrade modules", systemenv, settings)
    if result_upgrade["status"] == "success":
      personalsettings["lastrun"]["update"] = timestamp.year, timestamp.month, timestamp.day # update lastrun to todays date
      result = put_personal_settings(personalsettingsfile, personalsettings) # write new personal settings file
      if result["status"] != "success":
        # error in writing personal settingsfile
        crt_box_message("Error writing personal settings", "Error", "Warn")
      crt_box_message("Packages upgraded, restart SecureCRT!", "Packages", "Info")
      crt_object.Quit() # quit securecrt
    else:
      crt_box_message("Packages not upgraded", "Error", "Warn")

  # create backup
  datediff = timestamp.date() - lastrun_backup # get diff from last run
  if datediff.days > 31:
    crt_object.Config.SetOption("Single Instance", 0) # need to be multithreaded
    # more than 31 days since last backup
    backupfilename = os.path.join(crt_path, settings["SecureCRT"]["backup"], "ScriptBackup_" + crt_object.Version.replace(r"(", "").replace(r")", "") + "_" + timestamp.strftime("%Y%m%d-%H%M%S") + ".xml")
    command = ["\"" + sys.executable + "\"" + " /EXPORT " + "\"" + backupfilename + "\""]
    result_backup = crt_connect_cmd(command, "Backup", systemenv, settings)
    if result_backup["status"] == "success":
      personalsettings["lastrun"]["backup"] = timestamp.year, timestamp.month, timestamp.day # update lastrun to todays date
      result = put_personal_settings(personalsettingsfile, personalsettings) # write new personal settings file
      if result["status"] != "success":
        # error in writing personal settingsfile
        crt_box_message("Error writing personal settings", "Error", "Warn")
    else:
      crt_box_message("No backup run", "Error", "Warn")
    crt_object.Config.SetOption("Single Instance", 1)

  # set secretsfile
  secretsfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "provisioningfiles", "secrets_json.enc") # path to file with encrypted passwords and keys
  if os.path.isfile(secretsfile) is False:
    # the file does not exist
    crt_box_message("Secret file is missing, Exiting!", "Error", "Stop")
    return {"status": "error"}
  # read secrets
  secret = get_secrets(secretsfile, secretskeyfile)
  if secret["status"] == "error":
    # error reading settings
    crt_box_message("Error reading secrets file, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # set models file
  modelsfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "provisioningfiles", "models.json")  # path to file with valid models and upgrade info
  if os.path.isfile(modelsfile) is False:
    # the file does not exist
    crt_box_message("Models file is missing, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # set networks file
  networksfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "provisioningfiles", "networks.json") # path to file with management networks
  if os.path.isfile(networksfile) is False:
    # the file does not exist
    crt_box_message("Networks file is missing, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # set groups file
  groupsfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "provisioningfiles", "groups.json") # path to file with id groups
  if os.path.isfile(groupsfile) is False:
    # the file does not exist
    crt_box_message("Groups file is missing, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # set vlans file
  vlansfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "provisioningfiles", "vlans.json") # path to file with vlan id and name
  if os.path.isfile(vlansfile) is False:
    # the file does not exist
    crt_box_message("Vlans file is missing, Exiting!", "Error", "Stop")
    return {"status": "error"}

  # finished
  return {
    "status": "success",
    "settings": settings,
    "secret": secret,
    "personalsettings": personalsettings,
    "modelsfile": modelsfile,
    "networksfile": networksfile,
    "groupsfile": groupsfile,
    "vlansfile": vlansfile,
    "systemenv": systemenv,
    "username": username
  }

###
# start script
###

mainmenu_header = (
  "=====================================\n"
  " Version: 2022.11.1\n"
  " Author: fredrik.karlsson@kungsbacka.se\n"
  " For public use only!\n"
  "=====================================\n"
)

# handle if script is run outside of securecrt
try:
  # fix for code validators
  crt_object = crt # type: ignore[name-defined]
except NameError:
  # name crt is not defined
  print(mainmenu_header)
  print("Script not run from SecureCRT, Exiting!")
else:
  # check prereqs and run main menu if ok
  checks = pre_checks()
  while checks["status"] == "success":
    # operations parameters
    mainmenu_list = {
      "1": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "2": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "3": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "4": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "8": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "9": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "10": {
        "permission": ["it-dept"],
        "space": True,
        "break": False
      },
      "11": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "12": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "13": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "14": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "15": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "20": {
        "permission": ["it-dept"],
        "space": True,
        "break": False
      },
      "30": {
        "permission": ["it-dept"],
        "space": True,
        "break": False
      },
      "31": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "32": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "40": {
        "permission": ["it-dept"],
        "space": True,
        "break": True
      },
      "41": {
        "permission": ["it-dept"],
        "space": False,
        "break": False
      },
      "42": {
        "permission": ["it-dept"],
        "space": False,
        "break": True
      },
      "50": {
        "permission": ["it-dept"],
        "space": True,
        "break": False
      }
    }
    # define variables
    mainmenu_group = checks["settings"]["usergroups"][checks["username"]][1]

    # get input and assemble menu if needed
    if crt_object.Arguments.Count != 0:
      # command line input detected
      mainmenu = crt_object.Arguments[0]
    else:
      # gui is needed
      for item in mainmenu_list.items():
        if mainmenu_group in item[1]["permission"]: # type: ignore[operator]
          indent = " " * ((len(max(mainmenu_list.keys(), key=len)) - len(item[0])) * 2) # set indentation based on the menu number length
          if "mainmenu_body" not in globals():
            # this is the first row
            mainmenu_body = "\nSelect operation:"
          if item[1]["space"] is True:
            # one empty row above
            mainmenu_body += "\n"
          mainmenu_body += "\n" + indent + item[0] + "   " + globals()["mainmenu" + item[0]].__doc__.strip()

      # print permanent operations
      mainmenu_body += "\n\n" + " " * ((len(max(mainmenu_list.keys(), key=len)) - 2) * 2) + "98" + "   " + globals()["mainmenu98"].__doc__.strip()
      mainmenu_body += "\n" + " " * ((len(max(mainmenu_list.keys(), key=len)) - 2) * 2) + "99" + "   " + "Exit"

      # print menu and wait for input
      mainmenu = crt_box_input(mainmenu_header + mainmenu_body, "Cisco Provisioning Script", "")

    # evaluate permanent operations
    if mainmenu in ("99", ""):
      # cancel or exit
      break
    if mainmenu == "98":
      mainmenu_list.update({"98": {"break": False, "permission": [mainmenu_group]}}) # add to get though processing below
      mainmenu98()

    # validate and run operation
    if mainmenu not in mainmenu_list:
      # not a valid option
      crt_box_message("Not a valid operation", "Error", "Stop")
    elif mainmenu_group not in mainmenu_list[mainmenu]["permission"]: # type: ignore[operator]
      # no permission
      crt_box_message("No permission to this operation", "Error", "Stop")
    else:
      # call function
      globals()["mainmenu" + mainmenu]()
      if crt_object.Arguments.Count != 0:
        # exit if started with argument
        break
      if mainmenu_list[mainmenu]["break"]:
        # break out of script
        break

    # delete menu to start over
    del mainmenu_body

###
# end script
###
