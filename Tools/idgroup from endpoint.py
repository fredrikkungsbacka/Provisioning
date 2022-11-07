# $language = "Python3"
# $interface = "1.0"

import requests, json, os, platform
from requests.auth import HTTPBasicAuth
	
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

if platform.system() == "Windows":
  # windows
  systemEnv = {
    "homePath": os.environ["USERPROFILE"],
  }

mac = "38:C9:86:49:4A:BA"

ScriptsDir = os.path.join(systemEnv["homePath"], "Documents", "Scripts", "CiscoProvisioning")
SettingsFile = os.path.join(systemEnv["homePath"], "Documents", "Scripts", "CiscoProvisioning", "provisioningfiles", "settings.json")
settings = read_jsonfile(SettingsFile)
SecureCRTpath = os.path.join(systemEnv["homePath"], "Documents", *settings["SecureCRT"]["path"])
SecretsKeyFile = os.path.join(SecureCRTpath, settings["SecureCRT"]["provisioning"], "secret.key")
SecretsFile = os-path.join(ScriptsDir, "provisioningfiles", "secrets_json.enc")
secret = get_secrets(SecretsFile, SecretsKeyFile)

url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/endpoint?filter=mac.EQ." + mac
response = requests.get(url, auth = HTTPBasicAuth(secret["ise_provis"]["username"], secret["ise_provis"]["password"]), verify = True, headers = {"Accept": "application/json"})
response.keep_alive = False
jsonData = json.loads(response.text)
status = response.status_code
response.close()

id = jsonData["SearchResult"]["resources"][0]["id"]
url = "https://" + settings["ISE"]["PAN"]["URL"] + ":" + settings["ISE"]["PAN"]["APIport"] + "/ers/config/endpoint/" + id
response = requests.get(url, auth = HTTPBasicAuth(secret["ise_provis"]["username"], secret["ise_provis"]["password"]), verify = True, headers = {"Accept": "application/json"})
response.keep_alive = False
endpointData = json.loads(response.text)
status = response.status_code
response.close()
			
print(endpointData["ERSEndPoint"]["groupId"])
print(endpointData["ERSEndPoint"]["profileId"])
#print(endpointData["ERSEndPoint"])
