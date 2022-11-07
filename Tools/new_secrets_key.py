# $language = "Python3"
# $interface = "1.0"

import os, platform
from cryptography.fernet import Fernet

if platform.system() == "Windows":
  # windows
  systemEnv = {
    "homePath": os.environ["USERPROFILE"],
  }

ScriptsDir = os.path.join(systemEnv["homePath"], "Documents", "Scripts", "CiscoProvisioning", "Tools")
SecretsKeyFile = os.path.join(ScriptsDir, "secret.key")

key = Fernet.generate_key()

with open(SecretsKeyFile, "wb") as key_file:
  key_file.write(key)
