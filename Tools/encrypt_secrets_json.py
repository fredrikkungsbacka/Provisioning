# $language = "Python3"
# $interface = "1.0"

import json, os, platform
from cryptography.fernet import Fernet

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

ScriptsDir = os.path.join(systemEnv["homePath"], "Documents", "Scripts", "CiscoProvisioning", "Tools")
SettingsFile = os.path.join(systemEnv["homePath"], "Company", "Scripts", "CiscoProvisioning", "provisioningfiles", "settings.json")
settings = read_jsonfile(SettingsFile)
SecureCRTpath = os.path.join(systemEnv["homePath"], "Documents", *settings["SecureCRT"]["path"])
SecretsKeyFile = os.path.join(SecureCRTpath, settings["SecureCRT"]["provisioning"], "secret.key")
SecretsFile = os.path.join(ScriptsDir, "secrets_json.enc")

funcKey = open(SecretsKeyFile, "rb").read()
fernet = Fernet(funcKey)

with open(os.path.join(ScriptsDir, "secrets.json"), "rb") as json_file:
  original = json.load(json_file)

encrypted = fernet.encrypt(str(json.dumps(original)).encode())

with open(SecretsFile, "wb") as encrypted_file:
  encrypted_file.write(encrypted)

