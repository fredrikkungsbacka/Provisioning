# $language = "Python3"
# $interface = "1.0"

#==========================================================================
#
# Description:	Provisioning, upgrade and change of Cisco devices using SecureCRT over serial and SSH
# Author:				FRKA/DC/SE
version = 			"2.0.0 (Beta)"
# Legal:				For Kungsbacka internal use only!
# Comment:			Read instructions in Teams Infra channel
#
#==========================================================================

import os

iseserver = "ise-pan-01.infra.local"
solserver = "mgmt099.kba.local"
nas = "nas001.infra.local"
SecretFile = (os.environ["USERPROFILE"]) + r"\Kungsbacka kommun\SE Digitalt center - Infra\Switchkonfiguration\secret.enc"
SecretKeyFile = (os.environ["USERPROFILE"]) + r"\OneDrive - Kungsbacka kommun\Dokument\SecureCRT\Provisioning\secret.key"
SecretFileUrl = "https://kungsbackakommun-my.sharepoint.com/:u:/g/personal/fredrik_karlsson_kungsbacka_se/EaY44pIvM7tGkCBj_P3ktz0BWlBvj9v-025xgnd5oHzEwA?e=RBlxt5"
ModelsFile  = (os.environ["USERPROFILE"]) + r"\Kungsbacka kommun\SE Digitalt center - Infra\Switchkonfiguration\modelno.csv"
NetworksFile = (os.environ["USERPROFILE"]) + r"\Kungsbacka kommun\SE Digitalt center - Infra\Switchkonfiguration\networks.csv"

###
# nothing to edit below this line
###

def Secrets(funcFile, funcKeyFile):
	# reads secrets file, decrypt and populate variables
	import os.path
	from cryptography.fernet import Fernet
	if os.path.isfile(funcKeyFile):
		funcKey = open(funcKeyFile, "rb").read()
	else:
		return ["missingKey"]
	if os.path.isfile(funcFile):
		fernet = Fernet(funcKey)
		result = []
		with open(funcFile, "rb") as csvfile:
			for row in csvfile:
				row = fernet.decrypt(row)
				result.append(row.decode())
				result = [result.strip() for result in result] # remove ending \n
		return result
	else:
		return ["missingFile"]

def SOLFindIP(funcVlan):
	# returns next available ip on vlan from ipam
	import requests, json
	from requests.auth import HTTPBasicAuth
	jsonDict = {
		"query": "SELECT TOP 1 I.DisplayName FROM IPAM.IPNode I WHERE Status=2 AND I.Subnet.VLAN=" + funcVlan,
		"parameters": {
			"p": "9"
		}
	}
	url = "https://" + solserver + ":17778/SolarWinds/InformationService/v3/Json/Query"
	response = requests.post(url, json = jsonDict, auth = HTTPBasicAuth(iseuser[0], iseuser[1]), verify = False)
	response.keep_alive = False
	jsonData = json.loads(response.text)
	status = response.status_code
	response.close()
	if status == 200:
		return jsonData["results"][0]["DisplayName"]
	else:
		return "Error"

def SOLReserveIP(funcIP):
	# reserve ip in ipam
	import requests
	jsonDict = [
		funcIP,
		"Reserved"
	]
	from requests.auth import HTTPBasicAuth
	url = "https://" + solserver + ":17778/SolarWinds/InformationService/v3/Json/Invoke/IPAM.SubnetManagement/ChangeIPStatus"
	response = requests.post(url, json = jsonDict, auth = HTTPBasicAuth(iseuser[0], iseuser[1]), verify = False)
	response.keep_alive = False
	status = response.status_code
	response.close()
	if status == 200:
		return "True"
	else:
		return "Error"

def ISEFindDeviceByName(funcName):
	# return if name exist or not from ise
	import requests, json
	from requests.auth import HTTPBasicAuth
	url = "https://" + iseserver + ":9060/ers/config/networkdevice?filter=name.EQ." + funcName
	response = requests.get(url, auth = HTTPBasicAuth(iseuser[0], iseuser[1]), verify = False, headers = {"Accept": "application/json"})
	response.keep_alive = False
	jsonData = json.loads(response.text)
	status = response.status_code
	response.close()
	if status == 200:
		if jsonData["SearchResult"]["total"] == 1:
			return "True"
		else:
			return "False"
	else:
		return "Error"

def ISEFindDeviceByIP(funcIP):
	# return if ip exist or not from ise
	import requests, json
	from requests.auth import HTTPBasicAuth
	url = "https://" + iseserver + ":9060/ers/config/networkdevice?filter=ipaddress.EQ." + funcIP
	response = requests.get(url, auth = HTTPBasicAuth(iseuser[0], iseuser[1]), verify = False, headers = {"Accept": "application/json"})
	response.keep_alive = False
	jsonData = json.loads(response.text)
	status = response.status_code
	response.close()
	if status == 200:
		if jsonData["SearchResult"]["total"] == 1:
			return "True"
		else:
			return "False"
	else:
		return "Error"

def ISECreateDevice(funcIP, funcName):
	# create device in ise
	import requests
	jsonDict = {
		"NetworkDevice": {
			"name": funcName,
			"authenticationSettings": {
				"networkProtocol": "RADIUS",
				"radiusSharedSecret": secret[1],
				"enableKeyWrap": False,
				"dtlsRequired": False,
				"keyInputFormat": "ASCII",
				"enableMultiSecret": False
			},
			"snmpsettings": {
				"version": "ONE",
				"roCommunity": secret[10],
				"pollingInterval": 600,
				"linkTrapQuery": True,
				"macTrapQuery": True,
				"originatingPolicyServicesNode": "Auto"
			},
			"tacacsSettings": {
				"sharedSecret": secret[0],
				"connectModeOptions": "OFF",
				"previousSharedSecret": secret[0],
				"previousSharedSecretExpiry": 0
			},
			"profileName": "Cisco",
			"coaPort": 1700,
			"NetworkDeviceIPList": [ 
				{
				"ipaddress": funcIP,
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
	from requests.auth import HTTPBasicAuth
	url = "https://" + iseserver + ":9060/ers/config/networkdevice"
	response = requests.post(url, json = jsonDict, auth = HTTPBasicAuth(iseuser[0], iseuser[1]), verify = False)
	response.keep_alive = False
	status = response.status_code
	response.close()
	if status == 201:
		return "True"
	else:
		return "Error"

def Model(funcFile):
	# determine model and return variables
	import os.path, csv
	global modelno, ports, image, upgradeport
	modelno = "nomatch"
	crt.Screen.Send("sh ver | inc Model [nN]umber" + chr(13))
	crt.Screen.WaitForString(": ")
	modelno = crt.Screen.ReadString(chr(13))
	if os.path.isfile(funcFile):
		with open(funcFile) as csvfile:
			csvreader = csv.reader(csvfile, delimiter=";")
			for row in csvreader:
				if row[0] == modelno:
					row = [row.strip() for row in row] # remove ending \n
					ports = row[1].split(",")
					image = row[2].split(",")
					upgradeport = row[3]
	else:
		modelno = "missing"

def BoxOkCancel(Message, Title):
	# ok/cancel button
	import tkinter
	from tkinter import messagebox
	window = tkinter.Tk()
	window.wm_withdraw()
	window.attributes('-topmost', True)
	response = messagebox.askokcancel(Title, Message)
	## ok = True
	## cancel = False
	return response

def BoxYesNo(Message, Title):
	# yes/no button
	import tkinter
	from tkinter import messagebox
	window = tkinter.Tk()
	window.wm_withdraw()
	window.attributes('-topmost', True)
	response = messagebox.askyesno(Title, Message)
	## yes = True
	## no = False
	return response

def BoxInfo(Message, Title):
	# ok button
	import tkinter
	from tkinter import messagebox
	window = tkinter.Tk()
	window.wm_withdraw()
	window.attributes('-topmost', True)
	response = messagebox.showinfo(Title, Message)

def FreeMem():
	# return free memory on flash
	crt.Screen.Send("dir flash: | inc bytes free" + chr(13))
	crt.Screen.WaitForString("(")
	result = crt.Screen.ReadString(" bytes free)")
	return int(result)

def FindImage(strLine):
	# regex find image in string
	import re
	result = re.search("([a-zA-Z0-9-_.]*.bin)", strLine)
	if result == None:
		return "nomatch"
	else:
		return result[0]

def CleanFlash():
	# remove not used images
	crt.Screen.Send("dir flash:" + chr(13))
	crt.Screen.WaitForString("Directory of flash:/")
	result = crt.Screen.ReadString("#")
	binonflash = result.split(chr(13))
	for i in binonflash:
		result = FindImage(i)
		if result != "nomatch" and result != image[0]:
			crt.Screen.Send("del /fo flash:/" + result + chr(13))
			crt.Screen.WaitForString("#")

def VerifyIs2Int(strLine):
	# regex verify two digits
	import re
	result = re.search("^[0-9]{1,2}$", strLine,re.MULTILINE)
	if result == None:
		return False
	else:
		return True

def VerifyIsSite(strLine):
	# regex verify site name
	import re
	result = re.search("^\w+$", strLine,re.MULTILINE)
	if result == None:
		return False
	else:
		return True

def VerifyIsInv(strLine):
	# regex verify inventory number
	import re
	result = re.search("^[0-9]{4}$", strLine,re.MULTILINE)
	if result == None:
		return False
	else:
		return True

def VerifyIsLoc(strLine):
	# regex verify snmp location
	import re
	result = re.search("^(\w+\s\d+,\s\w+)$", strLine,re.MULTILINE)
	if result == None:
		return False
	else:
		return True

def VerifyIsInt(strLine):
	# regex verify interface name
	import re
	result = re.search("(((([Tt]en)|[Ff]orty){0,1}([Gg]igabit|[Ff]ast)[Ee]thernet)|([TtGgFf][eiaow])|(TwentyFiveGigE))([0-1]\/[0-9]{1,2}(\/[0-9]{0,2}){0,1})", strLine)
	if result == None:
		return False
	else:
		return True
		
def GetNetwork(funcVID, funcFile):
	# read networks file and populate variables
	import os.path, csv
	if os.path.isfile(funcFile):
		with open(funcFile) as csvfile:
			csvreader = csv.reader(csvfile, delimiter=",")
			for row in csvreader:
				if row[0] == funcVID:
					row = [row.strip() for row in row] # remove ending \n
					return row
			return ["nomatch"]
	else:
		return ["missing"]

def Management():
	# collect and config management settings
	global hostname
	crt.Screen.Send("conf t" + chr(13))
	crt.Screen.Send("vtp domain KBA" + chr(13))
	crt.Screen.Send("vtp mode transparent" + chr(13))

	# no upgrade needed
	if upgrade == False:
		ipoctet = ipaddress.split(".")
		switchname = [ipoctet[2], ipoctet[3]]

		while True:
			result = crt.Dialog.Prompt("Enter sitename:", "Sitename", "Stadshuset")
			if VerifyIsSite(result):
				switchname.append(result)
				break
			else:
				BoxInfo("Faulty sitename, please try again", "Hostname")

		while True:
			result = crt.Dialog.Prompt("Enter devicenumber:", "Devicenumber", "0000")
			if VerifyIsInv(result):
				switchname.append(result)
				break
			else:
				BoxInfo("Faulty device number, please try again", "Hostname")

		hostname = switchname[0] + "_" + switchname[1] + "_" + switchname[2] + "_" + switchname[3]
		BoxInfo("Allocated hostname: " + hostname, "Hostname")
		crt.Screen.Send("hostname " + hostname + chr(13))

		while True:
			result = crt.Dialog.Prompt("Enter address:", "SNMP Location", "Storgatan 37, Kungsbacka")
			if VerifyIsLoc(result):
				crt.Screen.Send("snmp-server location " + result + chr(13))
				break
			else:
				BoxInfo("Faulty location, please try again", "Hostname")
		
		crt.Screen.Send("ip domain-name infra.local" + chr(13))
		crt.Screen.Send("crypto key gen rsa gen mod 2048" + chr(13))
		crt.Screen.WaitForString("[OK]")
		crt.Screen.Send("ip ssh version 2" + chr(13))

	crt.Screen.Send("vlan " + network[0] + chr(13))
	crt.Screen.Send("name MGMT" + chr(13))
	crt.Screen.Send("exit" + chr(13))
	crt.Screen.Send("interface vlan" + network[0] + chr(13))
	crt.Screen.Send("ip address " + ipaddress + " " + network[1] + chr(13))
	crt.Screen.Send("no ip proxy-arp" + chr(13))
	if not ((modelno == "WS-C3560-8PC-S") or (modelno == "WS-C2960G-24TC-L") or (modelno == "WS-C2960-24TC-L") or (modelno == "WS-C2960-24TT-L") or (modelno == "WS-C2960PD-8TT-L") or (modelno == "WS-C2960-8TC-L")):
		# devices supporting ipv6
		crt.Screen.Send("no ipv6 enable" + chr(13))
	crt.Screen.Send("no shut" + chr(13))
	crt.Screen.Send("exit" + chr(13))

	if modelno == "WS-C2960S-24PS-L" or modelno == "WS-C2960X-24PS-L" or modelno == "WS-C2960G-24TC-L" or modelno == "WS-C2960-24TC-L" or modelno == "WS-C2960-24TT-L" or modelno == "WS-C2960PD-8TT-L" or modelno == "WS-C2960-8TC-L":
		# for L2 devices
		crt.Screen.Send("ip default-gateway " + network[2] + chr(13))
	else:
		# for L3 devices
		crt.Screen.Send("ip routing" + chr(13))
		crt.Screen.Send("ip route 0.0.0.0 0.0.0.0 " + network[2] + chr(13))

	crt.Screen.Send("end" + chr(13))

def OnlySerialConnected():
	# verify that we are using an active serieal session
	if not crt.Session.Connected:
		BoxInfo("Sending data requires an active connection", "Error")
		return False
	elif not crt.Session.RemotePort == 0:
		BoxInfo("Only serial connection allowed", "Error")
		return False

def CheckExecMode():
	# go into exec mode
	while True:
		crt.Screen.Send(chr(13))
		result = crt.Screen.WaitForStrings([")#", "#", ">", "[yes/no]"])
		if result == 1:
			# in config mode
			crt.Screen.Send("end" + chr(13))
			break
		elif result == 2:
			# in priv exec mode
			break
		elif result == 3:
			# in user exec mode
			crt.Screen.Send("enable" + chr(13))
			break
		elif result == 4:
			# first start up
			crt.Screen.Send(chr(13))
			crt.Screen.Send("no" + chr(13))
			crt.Screen.Send("enable" + chr(13))
			crt.Screen.Send(chr(13))
			break			

def FactoryDefault():
	# a compleate factory default
	if BoxYesNo("Do you wish to erase the whole switch?", "Factory Default") == True:
		crt.Screen.Send("delete /fo flash:/vlan.dat" + chr(13))
		crt.Screen.Send("write memory" + chr(13))
		crt.Screen.Send("write erase" + chr(13))
		crt.Screen.Send(chr(13))
		crt.Screen.WaitForString("[OK]")
		BoxInfo("Reload switch to finish the cleanup, Exiting script!", "Factory Default")
		return None

def DoUpgrade():
	# do the upgrade
	while True:
		crt.Screen.Send("sh int " + upgradeport + " | inc connect" + chr(13))
		if crt.Screen.WaitForStrings(["notconnect", "connected"]) == 2:
			BoxInfo("Disconnect cable!", "Upgrade")
		else:
			break

	# create trunk port
	crt.Screen.Send("conf t" + chr(13))
	crt.Screen.Send("interface " + upgradeport + chr(13))
	if modelno == "WS-C3560CG-8PC-S" or modelno == "WS-C3560CG-8TC-S" or modelno == "WS-C3560-8PC-S":
		crt.Screen.Send("switchport trunk encapsulation dot1q" + chr(13))
	crt.Screen.Send("switchport mode trunk" + chr(13))
	crt.Screen.Send("switchport trunk all vlan " + network[0] + chr(13))
	if modelno == "C9300-24P" or modelno == "C9200L-24P-4G" or modelno == "C9200L-24P-4X":
	  crt.Screen.Send("no power inline" + chr(13))
	crt.Screen.Send("end" + chr(13))

	while True:
		crt.Screen.Send("sh int " + upgradeport + " | inc connect" + chr(13))
		if crt.Screen.WaitForStrings(["notconnect", "connected"]) == 1:
			BoxInfo("Connect cable to first port Now!", "Upgrade")
		else:
			break
			
	while True:
		# fix issue with timeout
		crt.Sleep(5000) # five seconds
		crt.Screen.Send("copy ftp://" + nas + image[2] + image[0] + " flash:" + chr(13))
		crt.Screen.WaitForString("]?")
		crt.Screen.Send(chr(13))
		if crt.Screen.WaitForStrings([" bytes/sec)", "(Timed out)"]) == 1:
			break

	while True:
		crt.Screen.Send("sh int " + upgradeport + " | inc connect" + chr(13))
		if crt.Screen.WaitForStrings(["notconnect", "connected"]) == 2:
			BoxInfo("Disconnect cable!", "Upgrade")
		else:
			break

	crt.Screen.Send("conf t" + chr(13))
	crt.Screen.Send("default interface " + upgradeport + chr(13))
	crt.Screen.Send("no int vlan" + network[0] + chr(13))
	crt.Screen.Send("no vlan " + network[0] + chr(13))
	if modelno == "WS-C2960S-24PS-L" or modelno == "WS-C2960X-24PS-L" or modelno == "WS-C2960G-24TC-L" or modelno == "WS-C2960-24TC-L" or modelno == "WS-C2960-24TT-L" or modelno == "WS-C2960PD-8TT-L" or modelno == "WS-C2960-8TC-L":
		# for L2 devices
		crt.Screen.Send("default ip default-gateway" + chr(13))
	else:
		# for L3 devices
		crt.Screen.Send("default ip route *" + chr(13))
		
	crt.Screen.Send("do verify /md5 flash:/" + image[0] + " " + image[1] + chr(13))
	if crt.Screen.WaitForStrings(["Verified ", "%Error verifying"]) == 1:
		crt.Screen.Send("no boot system" + chr(13))
		crt.Screen.Send("boot system flash:/" + image[0] + chr(13))
		crt.Screen.Send("end" + chr(13))
		crt.Screen.Send("write memory" + chr(13))
		crt.Screen.WaitForString("[OK]")
		return True
	else:
		return False

def SendLine(strLine):
	# send line to console followed by enter and wait for serial buffer
	crt.Screen.Send(strLine + chr(13))
	crt.Sleep(175) # 175ms

def Global():
	# all generic global configuration
	# services
	SendLine("service tcp-keepalives-in")
	SendLine("service tcp-keepalives-out")
	SendLine("service timestamps debug datetime localtime")
	SendLine("service timestamps log datetime localtime")
	SendLine("service password-encryption")
	SendLine("no service udp-small-servers")
	SendLine("no service tcp-small-servers")
	SendLine("no service pad")
	SendLine("no service finger")

	# misc
	SendLine("no ip source-route")
	SendLine("no ip gratuitous-arps")
	SendLine("no ip finger")
	SendLine("ip subnet-zero")

	# disabled on newer versions
	if modelno == "WS-C2960G-24TC-L" or modelno == "WS-C2960-24TT-L" or modelno == "WS-C2960-24TC-L" or modelno == "WS-C2960PD-8TT-L" or modelno == "WS-C2960-8TC-L" or modelno == "WS-C3560-8PC-S":
		SendLine("no vstack")

	# gui
	SendLine("no ip http server")
	SendLine("no ip http secure-server")

	# energywise
	SendLine("energywise domain switch secret " + secret[6])

	# srnd version
	if not ((modelno == "C9300-24P") or (modelno == "C9200L-24P-4G") or (modelno == "C9200L-24P-4X") or (modelno == "C9300-24S")):
		SendLine("auto qos srnd4")

	# time
	SendLine("clock timezone CET 1")
	SendLine("clock summer-time CEDT recurring last Sun Mar 2:00 last Sun Oct 3:00")
	SendLine("ntp logging")
	SendLine("ntp server 10.128.100.60")

	# errdisable
	SendLine("errdisable recovery cause all")
	SendLine("errdisable recovery interval 300")
	SendLine("errdisable detect cause all")
	SendLine("no errdisable recovery cause bpduguard")
	SendLine("no errdisable recovery cause storm-control")

	# spanning-tree
	SendLine("spanning-tree portfast bpduguard default")
	SendLine("spanning-tree mode rapid-pvst")
	SendLine("no spanning-tree optimize bpdu transmission")

	# dns
	SendLine("ip domain-lookup")
	SendLine("ip name-server 10.128.150.10")
	SendLine("ip name-server 10.128.150.11")

	# dhcp snooping
	SendLine("ip dhcp snooping vlan 2-4094")
	SendLine("no ip dhcp snooping information option")
	SendLine("ip dhcp snooping")

	# password encrypt
	SendLine("key config-key password-encrypt " + secret[7])
	SendLine("password encryption aes")

	# aaa
	SendLine("aaa new-model")
	SendLine("username " + localuser[0] + " privilege 15 secret " + localuser[1])
	SendLine("aaa authentication attempts login 2")
	SendLine("aaa authentication fail-message X")
	SendLine("Local authentication failed")
	SendLine("X")
	SendLine("aaa authentication password-prompt " + chr(34) + "Enter local password: " + chr(34))
	SendLine("aaa authentication username-prompt "  + chr(34) + "Enter local username: " + chr(34))
	SendLine("aaa authentication login local_auth local")
	SendLine("aaa authorization exec local_auth local")
	SendLine("tacacs server ISE-PSN-01")
	SendLine(" address ipv4 10.128.100.67")
	SendLine(" key 0 " + secret[0])
	SendLine("tacacs server ISE-PSN-02")
	SendLine(" address ipv4 10.128.100.68")
	SendLine(" key 0 " + secret[0])
	SendLine("tacacs server ISE-PSN-03")
	SendLine(" address ipv4 10.128.100.76")
	SendLine(" key 0 " + secret[0])
	SendLine("aaa group server tacacs+ tac_auth")
	SendLine(" server name ISE-PSN-01")
	SendLine(" server name ISE-PSN-02")
	SendLine("aaa authentication login default group tac_auth local")
	SendLine("aaa authentication enable default none")
	SendLine("aaa authorization exec default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 0 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 1 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 2 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 3 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 4 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 5 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 6 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 7 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 8 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 9 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 10 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 11 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 12 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 13 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 14 default group tac_auth if-authenticated")
	SendLine("aaa authorization commands 15 default group tac_auth if-authenticated ")
	SendLine("aaa accounting commands 0 default start-stop group tac_auth")
	SendLine("aaa accounting commands 1 default start-stop group tac_auth")
	SendLine("aaa accounting commands 2 default start-stop group tac_auth")
	SendLine("aaa accounting commands 3 default start-stop group tac_auth")
	SendLine("aaa accounting commands 4 default start-stop group tac_auth")
	SendLine("aaa accounting commands 5 default start-stop group tac_auth")
	SendLine("aaa accounting commands 6 default start-stop group tac_auth")
	SendLine("aaa accounting commands 7 default start-stop group tac_auth")
	SendLine("aaa accounting commands 8 default start-stop group tac_auth")
	SendLine("aaa accounting commands 9 default start-stop group tac_auth")
	SendLine("aaa accounting commands 10 default start-stop group tac_auth")
	SendLine("aaa accounting commands 11 default start-stop group tac_auth")
	SendLine("aaa accounting commands 12 default start-stop group tac_auth")
	SendLine("aaa accounting commands 13 default start-stop group tac_auth")
	SendLine("aaa accounting commands 14 default start-stop group tac_auth")
	SendLine("aaa accounting commands 15 default start-stop group tac_auth")
	SendLine("aaa authorization config-commands")

	# line and vty
	SendLine("ip access-list sta vty-access")
	SendLine(" permit 10.128.0.0 0.0.255.255")
	SendLine(" permit 10.30.1.112")
	SendLine(" permit 10.144.200.0 0.0.1.255")
	SendLine(" permit 10.144.202.0 0.0.1.255")
	SendLine(" permit 10.155.104.0 0.0.0.255")
	SendLine("line con 0")
	SendLine(" exec-timeout 5 0")
	SendLine(" logging synchronous")
	SendLine(" login authentication local_auth")
	SendLine(" privilege level 15")
	SendLine(" no password")
	SendLine(" length 40")
	SendLine("line vty 0 15")
	SendLine(" no privilege level 15")
	SendLine(" exec-timeout 5 0")
	SendLine(" logging synchronous")
	SendLine(" no password")
	SendLine(" access-class vty-access in vrf-also")
	SendLine(" length 40")

	# banner
	SendLine("banner motd X")
	SendLine("#")
	SendLine("# | |/ /                    | |              | |")
	SendLine("# | ' /_   _ _ __   __ _ ___| |__   __ _  ___| |")
	SendLine("# |  <| | | | '_ \ / _` / __| '_ \ / _` |/ __| |/ / _` |")
	SendLine("# | . \ |_| | | | | (_| \__ \ |_) | (_| | (__|   < (_| |")
	SendLine("# |_|\_\__,_|_| |_|\__, |___/_.__/ \__,_|\___|_|\_\__,_|")
	SendLine("# | |/ /            __/ |")
	SendLine("# | ' / ___  _ __ _|___/")
	SendLine("# |  < / _ \| '_ ` _ \| '_ ` _ \| | | | '_ "+ chr(92))
	SendLine("# | . \ (_) | | | | | | | | | | | |_| | | | |")
	SendLine("# |_|\_\___/|_| |_| |_|_| |_| |_|\__,_|_| |_|")
	SendLine("#")
	SendLine("# [WARNING]")
	SendLine("# If you are not authorised to access this system")
	SendLine("# exit IMMEDIATELY.")
	SendLine("#")
	SendLine("# Unauthorised access to this system is forbidden by")
	SendLine("# national, and international laws.")
	SendLine("#")
	SendLine("# By entry into this system you acknowledge that you")
	SendLine("# are authorised to access it and have the level of")
	SendLine("# privilege at which you subsequently operate on")
	SendLine("# this system")
	SendLine("#")
	SendLine("# You consent by entry into this system to the")
	SendLine("# monitoring of your activities")
	SendLine("#")
	SendLine("#####################################################")
	SendLine("X")

	# snmp
	SendLine("snmp-server contact Infra NOC")
	SendLine("ip access-list sta snmp-access")
	SendLine(" permit 10.128.100.0 0.0.3.255")
	SendLine(" permit 10.30.1.112")
	SendLine("snmp-server group " + snmpuser[0] + " v3 priv access snmp-access")
	SendLine("snmp-server group " + snmpuser[0] + " v3 priv context vlan- match prefix access snmp-access")
	SendLine("snmp-server group " + snmpuser[0] + " v3 priv read NPMView write NPMView")
	SendLine("snmp-server user " + snmpuser[0] + " " + snmpuser[0] + " v3 auth sha " + snmpuser[1] + " priv aes 128 " + snmpuser[1] + " access snmp-access")
	SendLine("snmp-server view NPMView iso included")
	SendLine("snmp-server ifindex persist")
	SendLine("snmp-server contact Infra NOC")
	SendLine("snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart")
	SendLine("snmp-server enable traps transceiver all")
	SendLine("snmp-server enable traps auth-framework")
	SendLine("snmp-server enable traps cpu threshold")
	SendLine("snmp-server enable traps storm-control trap-rate 1")
	SendLine("snmp-server enable traps stpx")
	SendLine("snmp-server enable traps port-security")
	SendLine("snmp-server enable traps envmon")
	SendLine("snmp-server enable traps mac-notification")
	SendLine("snmp-server enable traps errdisable")
	SendLine("snmp-server enable traps mac-notification change move threshold")
	SendLine("snmp-server enable traps errdisable")
	SendLine("snmp-server enable traps auth-framework sec-violation")
	if modelno == "C9300-24P" or modelno == "C9200L-24P-4G" or modelno == "C9200L-24P-4X" or modelno == "C9300-24S":
		SendLine("snmp-server enable traps smart-license")
	SendLine("snmp-server host 10.30.1.112 version 3 priv " + snmpuser[0])
	SendLine("snmp-server host 10.128.101.112 version 3 priv " + snmpuser[0])
	SendLine("snmp-server trap link ietf")
	SendLine("snmp-server host 10.128.100.67 " + secret[10] + " mac-notification snmp")
	SendLine("snmp-server host 10.128.100.68 " + secret[10] + " mac-notification snmp")
	SendLine("snmp-server community " + secret[10] + " RO snmp-access")

	# c9k stuff
	if modelno == "C9200L-24P-4G" or modelno == "C9200L-24P-4X" or modelno == "C9300-24P" or modelno == "C9300-24S":
		SendLine("do license smart register idtoken " + secret[5])
		SendLine("system mtu 8192")
		SendLine("license smart transport callhome")
		SendLine("call-home")
		SendLine(" contact-email-addr noc@kungsbacka.se")
		SendLine(" profile CiscoTAC-1")
		SendLine("  active")
		SendLine("  destination transport-method http")
		SendLine("  no destination transport-method email")

def GlobalISE():
	# vlans
	SendLine("vlan " + network[3])
	SendLine(" name SCCM")
	SendLine("vlan " + network[4])
	SendLine(" name #VOICE")
	SendLine("exit")

	# radius
	SendLine("radius server ISE-PSN-01")
	SendLine(" address ipv4 10.128.100.67 auth-port 1645 acct-port 1646")
	SendLine(" key 0 " + secret[1])
	SendLine("radius server ISE-PSN-02")
	SendLine(" address ipv4 10.128.100.68 auth-port 1645 acct-port 1646")
	SendLine(" key 0 " + secret[1])
	SendLine("radius server ISE-PSN-03")
	SendLine(" address ipv4 10.128.100.76 auth-port 1645 acct-port 1646")
	SendLine(" key 0 " + secret[1])
	SendLine("aaa group server radius ise_auth")
	SendLine(" server name ISE-PSN-01")
	SendLine(" server name ISE-PSN-02")
	SendLine(" load-balance method least-outstanding")
	SendLine("aaa authentication dot1x default group ise_auth")
	SendLine("aaa authentication dot1x ise_auth group ise_auth")
	SendLine("aaa authorization network default group ise_auth")
	SendLine("aaa authorization network ise_auth group ise_auth")
	SendLine("aaa authorization network auth-list group ise_auth")
	SendLine("aaa authorization auth-proxy default group ise_auth")
	SendLine("aaa accounting auth-proxy default start-stop group ise_auth")
	SendLine("aaa accounting dot1x default start-stop group ise_auth")
	SendLine("aaa accounting update newinfo periodic 2880")
	SendLine("aaa accounting system default start-stop group ise_auth")
	SendLine("radius-server attribute 6 on-for-login-auth")
	SendLine("radius-server attribute 6 support-multiple")
	SendLine("radius-server attribute 8 include-in-access-req")
	SendLine("radius-server attribute 25 access-request include")
	SendLine("radius-server attribute 31 send nas-port-detail")
	SendLine("radius-server attribute 31 mac format ietf upper-case")
	SendLine("radius-server vsa send accounting")
	SendLine("radius-server vsa send authentication")
	SendLine("radius-server dead-criteria time 5 tries 3")
	SendLine("radius-server deadtime 2")
	SendLine("radius-server retry method reorder")

	# coa
	SendLine("aaa server radius dynamic-author")
	SendLine(" client 10.128.100.68 server-key 0 " + secret[2])
	SendLine(" client 10.128.100.67 server-key 0 " + secret[2])
	SendLine(" auth-type all")
	SendLine(" ignore session-key")
	SendLine(" ignore server-key")
	SendLine("authentication critical recovery delay 1000")
	SendLine("authentication mac-move permit")
	SendLine("access-session template monitor")
	SendLine("no macro auto monitor")

	# device-sensor
	SendLine("cdp run")
	SendLine("device-sensor filter-list cdp list cdp-list")
	SendLine(" tlv name device-name")
	SendLine(" tlv name address-type")
	SendLine(" tlv name capabilities-type")
	SendLine(" tlv name platform-type")
	SendLine("device-sensor filter-spec cdp include list cdp-list")
	SendLine("lldp run")
	SendLine("device-sensor filter-list lldp list lldp-list")
	SendLine(" tlv name port-id")
	SendLine(" tlv name port-description")
	SendLine(" tlv name system-name")
	SendLine(" tlv name system-description")
	SendLine(" tlv name system-capabilities")
	SendLine(" tlv name management-address")
	SendLine("device-sensor filter-spec lldp include list lldp-list")
	SendLine("device-sensor notify all-changes")
	if not ((modelno == "WS-C2960G-24TC-L") or (modelno == "WS-C2960-24TC-L") or (modelno == "WS-C2960-24TT-L") or (modelno == "WS-C2960PD-8TT-L") or (modelno == "WS-C2960-8TC-L")):
		SendLine("device-sensor accounting")

	# activate dot1x
	SendLine("dot1x system-auth-control")
	SendLine("dot1x critical eapol")

	# mac notif
	SendLine("mac address-table notification change interval 30")
	SendLine("mac address-table notification change")
	SendLine("mac address-table notification mac-move")

	# logging
	SendLine("logging on")
	SendLine("logging buffered 16384 debugging")
	SendLine("logging snmp-authfail")
	SendLine("logging rate-limit console 10 except errors")
	SendLine("no logging console")
	SendLine("no logging message-counter syslog")
	SendLine("no logging origin-id")
	SendLine("logging monitor informational")
	SendLine("logging host 10.128.100.65 transport udp port 20514")
	SendLine("logging host 10.128.100.66 transport udp port 20514")
	SendLine("logging discriminator ISE facility drops AUTHMGR|EPM|DOT1X|MAB")
	SendLine("logging buffered discriminator ISE")
	SendLine("logging host 10.30.1.112 discriminator ISE")
	SendLine("logging host 10.128.101.112 discriminator ISE")

	# ip device tracker
	if modelno == "C9200L-24P-4G" or modelno == "C9200L-24P-4X" or modelno == "C9300-24P" or modelno == "C9300-24S":
		SendLine("device-tracking policy kba-access")
		SendLine(" limit address-count 5")
		SendLine("device-tracking policy kba-trunk")
		SendLine(" trusted-port")
		SendLine(" device-role switch")
		SendLine(" no protocol ndp")
		SendLine(" no protocol arp")
		SendLine(" no protocol dhcp4")
		SendLine("device-tracking tracking auto-source")
	else:
		SendLine("ip device tracking")
		SendLine("ip device tracking probe delay 15")
		SendLine("ip device tracking probe use-svi")
		if not ((modelno == "WS-C3560-8PC-S") or (modelno == "WS-C2960G-24TC-L") or (modelno == "WS-C2960-24TC-L") or (modelno == "WS-C2960-24TT-L") or (modelno == "WS-C2960PD-8TT-L") or (modelno == "WS-C2960-8TC-L")):
			SendLine("ip device tracking probe auto-source override")

def WaitForCommand():
	# wait for a range command to finish
	crt.Screen.Send(chr(13) + chr(13))
	crt.Screen.WaitForString("(config-if-range)#" + chr(13))

def Trunk():
	# trunk port
	if modelno == "WS-C3560CG-8PC-S" or modelno == "WS-C3560CG-8TC-S":
		SendLine("switchport trunk encapsulation dot1q")
		SendLine("ip device tracking maximum 0")
		SendLine("nmsp attachment suppress")
	elif modelno == "WS-C3560-8PC-S":
		SendLine("switchport trunk encapsulation dot1q")
		SendLine("ip device tracking maximum 1")
		SendLine("nmsp attachment suppress")
	elif modelno == "C9200L-24P-4G" or modelno == "C9200L-24P-4X" or modelno == "C9300-24P" or modelno == "C9300-24S":
		SendLine("device-tracking attach-policy kba-trunk")
	elif modelno == "WS-C2960S-24PS-L" or modelno == "WS-C2960X-24PS-L" or modelno == "WS-C3560CX-8PC-S"or modelno == "WS-C3560CX-12PC-S" or modelno == "WS-C3560CX-8TC-S" or modelno == "WS-C3560CX-12TC-S":
		SendLine("ip device tracking maximum 0")
		SendLine("nmsp attachment suppress")
	elif modelno == "WS-C2960-24TC-L" or modelno == "WS-C2960-24TT-L" or modelno == "WS-C2960G-24TC-L" or modelno == "WS-C2960PD-8TT-L"or modelno == "WS-C2960-8TC-L":
		SendLine("ip device tracking maximum 1")
		SendLine("nmsp attachment suppress")
	SendLine("description TRUNK")
	SendLine("switchport mode trunk")
	SendLine("storm-control broadcast level 5.00 2.00")
	SendLine("storm-control multicast level 5.00 2.00")
	SendLine("storm-control action trap")
	SendLine("auto qos voip trust")
	SendLine("ip dhcp snooping trust")

def PortISE():
	# access port
	SendLine("description *** ise")
	SendLine("switchport mode access")
	SendLine("switchport access vlan " + network[3])
	SendLine("switchport voice vlan " + network[4])
	SendLine("switchport port-security maximum 5")
	SendLine("switchport port-security maximum 2 vlan access")
	SendLine("switchport port-security")
	SendLine("switchport port-security violation restrict")
	SendLine("switchport port-security aging time 30")
	SendLine("authentication control-direction in")
	SendLine("authentication event fail action authorize vlan " + network[3])
	SendLine("authentication event server dead action authorize")
	SendLine("authentication event server alive action reinitialize")
	SendLine("authentication host-mode multi-domain")
	SendLine("authentication order mab dot1x")
	SendLine("authentication priority dot1x mab")
	SendLine("authentication port-control auto")
	SendLine("authentication open")
	SendLine("authentication periodic")
	SendLine("authentication timer reauthenticate server")
	if modelno == "WS-C3560-8PC-S" or modelno == "WS-C2960G-24TC-L" or modelno == "WS-C2960-24TC-L" or modelno == "WS-C2960-24TT-L" or modelno == "WS-C2960PD-8TT-L" or modelno == "WS-C2960-8TC-L":
		SendLine("authentication timer inactivity server")
	else:
		SendLine("authentication timer inactivity server dynamic")
	SendLine("authentication violation replace")
	SendLine("mab")
	SendLine("snmp trap mac-notification change added")
	SendLine("snmp trap mac-notification change removed")
	SendLine("no snmp trap link-status")
	SendLine("dot1x pae authenticator")
	SendLine("storm-control broadcast level 5.00")
	SendLine("storm-control multicast level 5.00")
	SendLine("storm-control action trap")
	SendLine("storm-control action shutdown")
	SendLine("ip dhcp snooping limit rate 20")
	SendLine("spanning-tree portfast")
	SendLine("spanning-tree bpduguard enable")
	SendLine("spanning-tree guard root")
	SendLine("auto qos voip cisco-phone")
	if modelno == "C9200L-24P-4G" or modelno == "C9200L-24P-4X" or modelno == "C9300-24P":
		SendLine("device-tracking attach-policy kba-access")
	else:
		SendLine("ip device tracking maximum 5")

def UnusedInt():
	# configure unused interfaces
	SendLine("int vlan1")
	SendLine("shut")
	SendLine("description DO_NOT_USE")
	if modelno == "C9200L-24P-4G" or modelno == "C9200L-24P-4X" or modelno == "C9300-24P" or modelno == "C9300-24S":
		SendLine("interface Gi0/0")
		SendLine("shut")
		SendLine("description DO_NOT_USE")
	if modelno == "C9300-24P" or modelno == "C9300-24S":
		SendLine("interface range Gi1/1/1 - 4")
		SendLine("shut")
		SendLine("description DO_NOT_USE")
		SendLine("interface range Fo1/1/1 - 2")
		SendLine("shut")
		SendLine("description DO_NOT_USE")
		SendLine("interface range Twe1/1/1 - 2")
		SendLine("shut")
		SendLine("description DO_NOT_USE")
		if not C9300NM8X:
			SendLine("interface range Te1/1/1 - 8")
			SendLine("shut")
			SendLine("description DO_NOT_USE")
	if modelno == "WS-C2960S-24PS-L" or modelno == "WS-C2960X-24PS-L":
		SendLine("interface fa0")
		SendLine("shut")
		SendLine("description DO_NOT_USE")

def mainMenu2():
	# main script
	import webbrowser
	global upgrade, ipaddress, network, secret, localuser, snmpuser, iseuser
	
	# read secrets file
	secret = Secrets(SecretFile, SecretKeyFile)
	if secret[0] == "missingKey":
		BoxInfo("Secretkeyfile is missing!" + "\n" "Save this in location: " + SecretKeyFile, "Error")
		webbrowser.open(SecretFileUrl, new=2)
		return None
	elif secret[0] == "missingFile":
		BoxInfo("Secretfile is missing, Exiting script!", "Error")
		return None
	else:
		localuser = secret[3].split(";")
		snmpuser = secret[4].split(";")
		iseuser = secret[9].split(";")
	
	# basic line config
	crt.Screen.Send("conf t" + chr(13))
	crt.Screen.Send("line con 0" + chr(13))
	crt.Screen.Send(" exec-timeout 60 0" + chr(13))
	crt.Screen.Send(" length 0" + chr(13))
	crt.Screen.Send(" logging synchronous" + chr(13))
	crt.Screen.Send("end" + chr(13))

	# determine model number
	Model(ModelsFile)
	if modelno == "missing":
		BoxInfo("Modelsfile is missing, Exiting script!", "Error")
		return None
	elif modelno == "nomatch":
		BoxInfo("Unknown switch, Exiting script!", "Error")
		return None
	
	# make sure enough free space exist on flash
	if modelno == "C9300-24P" or modelno == "C9200L-24P-4G" or modelno == "C9200L-24P-4X" or modelno == "C9300-24S":
		if FreeMem() < 1000000000:
			CleanFlash()
	else:
		if FreeMem() < 25000000:
			CleanFlash()
	
	# check for latest image
	crt.Screen.Send("sh boot" + chr(13))
	crt.Screen.WaitForString("flash:")
	result = crt.Screen.ReadString(chr(13))
	if FindImage(result) == image[0]:
		upgrade = False
	else:
		upgrade = True
		BoxInfo("Upgrade needed, proceeding!", "Upgrade")
	
	# enter management vlan
	while True:
		result = crt.Dialog.Prompt("Enter vlan:", "Management vlan", "00")
		if VerifyIs2Int(result):
			network = GetNetwork(result, NetworksFile)
			break
		else:
			BoxInfo("No valid vlan entered, please try again", "Management Vlan")
	if network[0] == "nomatch":
		BoxInfo("Unknown vlan, Exiting script!", "Error")
		return None
	elif network[0] == "missing":
		BoxInfo("Missing networksfile, Exiting script!", "Error")
		return None
	
	# find free ipaddress
	ipaddress = SOLFindIP(network[0])
	if ipaddress == "Error":
		BoxInfo("Cannot allocate ip, Exiting script!", "Error")
		return None
	else:
		BoxInfo("Allocated ipaddress: " + ipaddress, "IPaddress")
	
	# make management interface
	Management()
	
	# do upgrade or register in sol and ise
	if upgrade == True:
		result = DoUpgrade()
		if result == True:
			CleanFlash()
			BoxInfo("Reload switch to finish the upgrade, Exiting script!", "Upgrade")
			return None
		elif result == False:
			BoxInfo("Upgrade failed, Exiting script!", "Upgrade")
			return None
	else:
			result = SOLReserveIP(ipaddress)
			if result == "True":
				BoxInfo("Sucessfully reserved ipaddress, continuing!", "IPAM")
			else:
				BoxInfo("Cannot reserve ipaddress, continuing!", "IPAM")
	
			if BoxYesNo("Do you wish to add this device to ISE?", "ISE"):
				result = ISEFindDeviceByIP(ipaddress)
				if result == "True":
					BoxInfo("Switch exist by IP, Exiting script!", "ISE")
					return None
				elif result == "Error":
					BoxInfo("Error searching IP, Continuing", "ISE")
	
				result = ISEFindDeviceByName(hostname)
				if result == "True":
					BoxInfo("Switch exist by name, Exiting script!", "ISE")
					return None
				elif result == "Error":
					BoxInfo("Error searching Name, Continuing", "ISE")
	
				result = ISECreateDevice(ipaddress, hostname)
				if result =="True":
					BoxInfo("Sucessfully added device, continuing!", "ISE")
				else:
					BoxInfo("Cannot add device. Check ISE, continuing!", "ISE")
	
	# detect 8*10gb card
	if modelno == "C9300-24S" or modelno == "C9300-24P":
		crt.Screen.Send("sh inv" + chr(13))
		crt.Screen.WaitForString("NAME:")
		strCap = crt.Screen.ReadString("#")
		result = re.search("C9300-NM-8X", strCap)
		if result == None:
			C9300NM8X = False
		else:
			C9300NM8X = True
	
	# time to do all configs
	crt.Screen.Send("conf t" + chr(13))
	
	# all generic global conf
	Global()
	
	# all ise specific global conf
	GlobalISE()
	
	if modelno == "C9300-24S":
		SendLine("interface range gi1/0/" + ports[0] + " - " + ports[1])
		Trunk()
		WaitForCommand()
		if C9300NM8X == True:
			SendLine("interface range te1/1/" + ports[2] + " - " + ports[3])
			Trunk()
			WaitForCommand()
	elif modelno == "C9200L-24P-4G":
		SendLine("interface range gi1/0/" + ports[0] + " - " + ports[1])
		PortISE()
		WaitForCommand()
		SendLine("interface range gi1/1/" + ports[2] + " - " + ports[3])
		Trunk()
		WaitForCommand()
	elif modelno == "C9200L-24P-4X" :
		SendLine("interface range gi1/0/" + ports[0] + " - " + ports[1])
		PortISE()
		WaitForCommand()
		SendLine("interface range te1/1/" + ports[2] + " - " + ports[3])
		Trunk()
		WaitForCommand()
	elif modelno == "C9300-24P":
		SendLine("interface range gi1/0/" + ports[0] + " - " + ports[1])
		PortISE()
		WaitForCommand()
		if C9300NM8X == True:
			SendLine("interface range te1/1/" + ports[2] + " - " + ports[3])
			Trunk()
			WaitForCommand()
	elif modelno == "WS-C2960S-24PS-L" or modelno == "WS-C2960X-24PS-L":
		SendLine("interface range gi1/0/" + ports[0] + " - " + ports[1])
		PortISE()
		WaitForCommand()
		SendLine("interface range gi1/0/" + ports[2] + " - " + ports[3])
		Trunk()
		WaitForCommand()
	elif modelno == "WS-C3560CX-8PC-S" or modelno == "WS-C3560CX-12PC-S" or modelno == "WS-C3560CX-8TC-S" or modelno == "WS-C3560CX-12TC-S" or modelno == "WS-C3560CG-8PC-S" or modelno == "WS-C3560CG-8TC-S":
		SendLine("interface range gi0/" + ports[0] + " - " + ports[1])
		PortISE()
		WaitForCommand()
		SendLine("interface range gi0/" + ports[2] + " - " + ports[3])
		Trunk()
		WaitForCommand()
	elif modelno == "WS-C2960G-24TC-L":
		SendLine("interface range gi0/" + ports[0] + " - " + ports[1])
		PortISE()
		WaitForCommand()
		SendLine("interface range gi0/" + ports[2] + " - " + ports[3])
		Trunk()
		WaitForCommand()
	elif modelno == "WS-C3560-8PC-S" or modelno == "WS-C2960-24TC-L" or modelno == "WS-C2960-24TT-L" or modelno == "WS-C2960PD-8TT-L" or modelno == "WS-C2960-8TC-L":
		SendLine("interface range fa0/" + ports[0] + " - " + ports[1])
		PortISE()
		WaitForCommand()
		SendLine("interface range gi0/" + ports[2] + " - " + ports[3])
		Trunk()
		WaitForCommand()
	
	# fix any unused interfaces
	UnusedInt()

	# ending	
	Ending()
	
def Ending():
	# ending
	crt.Screen.Send("end" + chr(13))
	crt.Screen.Send("write memory" + chr(13))
	crt.Screen.WaitForString("[OK]")
	BoxInfo("Provisioning finished!", "Finished")
	return None

def mainMenu14():
	while True:
		result = crt.Dialog.Prompt("Enter portname:", "Interface name", "gi1/0/24")
		if VerifyIsInt(result):
			crt.Screen.Send("conf t" + chr(13))
			crt.Screen.Send("default interface " + result + chr(13))
			crt.Screen.Send("interface " + result + chr(13))
			vlan = crt.Dialog.Prompt("Enter vlan:", "Vlan number")
			crt.Screen.Send("description *** ise" + " vlan" + vlan + chr(13))
			crt.Screen.Send("switchport access vlan " + vlan + chr(13))
			Ending()
			return None
		else:
			BoxInfo("Wrong portname", "Interface name")
			return None

def mainMenu13():
	Model(ModelsFile)
	if modelno == "missing":
		BoxInfo("modelsfile is missing, Exiting script!", "Error")
		return None
	elif modelno == "nomatch":
		BoxInfo("Unknown switch, Exiting script!", "Error")
		return None
	while True:
		result = crt.Dialog.Prompt("Enter portname:", "Interface name", "gi1/0/24")
		if VerifyIsInt(result):
			crt.Screen.Send("conf t" + chr(13))
			crt.Screen.Send("default interface " + result + chr(13))
			crt.Screen.Send("interface " + result + chr(13))
			vlan = crt.Dialog.Prompt("Enter vlan:", "Vlan number")
			crt.Screen.Send("description *** external" + chr(13))
			crt.Screen.Send("switchport mode access" + chr(13))
			crt.Screen.Send("switchport access vlan " + vlan + chr(13))
			crt.Screen.Send("switchport nonegotiate" + chr(13))
			crt.Screen.Send("switchport port-security maximum 1000" + chr(13))
			crt.Screen.Send("switchport port-security" + chr(13))
			crt.Screen.Send("switchport port-security violation restrict" + chr(13))
			crt.Screen.Send("switchport port-security aging time 30" + chr(13))
			crt.Screen.Send("no snmp trap link-status" + chr(13))
			crt.Screen.Send("storm-control broadcast level 5.00" + chr(13))
			crt.Screen.Send("storm-control multicast level 5.00" + chr(13))
			crt.Screen.Send("storm-control action trap" + chr(13))
			crt.Screen.Send("storm-control action shutdown" + chr(13))
			crt.Screen.Send("spanning-tree portfast" + chr(13))
			crt.Screen.Send("spanning-tree bpduguard enable" + chr(13))
			crt.Screen.Send("spanning-tree bpdufilter enable" + chr(13))
			crt.Screen.Send("spanning-tree guard root" + chr(13))
			crt.Screen.Send("no cdp enable" + chr(13))
			if modelno == "C9200L-24P-4G" or modelno == "C9200L-24P-4X" or modelno == "C9300-24P":
				crt.Screen.Send("device-tracking attach-policy kba-access" + chr(13))
			else:
				crt.Screen.Send("ip device tracking maximum 5" + chr(13))
			Ending()
			return None
		else:
			BoxInfo("Wrong portname", "Interface name")
			return None

def mainMenu12():
	global network
	Model(ModelsFile)
	if modelno == "missing":
		BoxInfo("modelsfile is missing, Exiting script!", "Error")
		return None
	elif modelno == "nomatch":
		BoxInfo("Unknown switch, Exiting script!", "Error")
		return None
	crt.Screen.Send("sh ip int brie | inc 10.12[48]" + chr(13))
	crt.Screen.WaitForString("Vlan")
	result = crt.Screen.ReadString(chr(32))
	network = GetNetwork(result, NetworksFile)
	if network[0] == "nomatch":
		BoxInfo("Unknown vlan, Exiting script!", "Error")
		return None
	elif network[0] == "missing":
		BoxInfo("Missing networksfile, Exiting script!", "Error")
		return None
	vlans = crt.Dialog.Prompt("Enter comma seperated list of vlans:", "vlan numbers", "2310,53," + network[0] + ",")
	while True:
		result = crt.Dialog.Prompt("Enter portname:", "Interface name", "gi1/0/24")
		if VerifyIsInt(result):
			crt.Screen.Send("conf t" + chr(13))
			crt.Screen.Send("default interface " + result + chr(13))
			crt.Screen.Send("interface " + result + chr(13))
			Trunk()
			crt.Screen.Send("description T2KBN" + chr(13))
			crt.Screen.Send("switchport trunk all vlan " + vlans + chr(13))
			# crt.Screen.Send("speed nonegotiate" + chr(13)) #c3560cx?
			Ending()
			return None
		else:
			BoxInfo("Wrong portname", "Interface name")
			return None

def mainMenu11():
	global network
	Model(ModelsFile)
	if modelno == "missing":
		BoxInfo("modelsfile is missing, Exiting script!", "Error")
		return None
	elif modelno == "nomatch":
		BoxInfo("Unknown switch, Exiting script!", "Error")
		return None
	crt.Screen.Send("sh ip int brie | inc 10.12[48]" + chr(13))
	crt.Screen.WaitForString("Vlan")
	result = crt.Screen.ReadString(chr(32))
	network = GetNetwork(result, NetworksFile)
	if network[0] == "nomatch":
		BoxInfo("Unknown vlan, Exiting script!", "Error")
		return None
	elif network[0] == "missing":
		BoxInfo("Missing networksfile, Exiting script!", "Error")
		return None
	while True:
		result = crt.Dialog.Prompt("Enter portname:", "Interface name", "gi1/0/24")
		if VerifyIsInt(result):
			crt.Screen.Send("conf t" + chr(13))
			crt.Screen.Send("default interface " + result + chr(13))
			crt.Screen.Send("interface " + result + chr(13))
			PortISE()
			Ending()
			return None
		else:
			BoxInfo("Wrong portname", "Interface name")
			return None

def mainMenu10():
	Model(ModelsFile)
	if modelno == "missing":
		BoxInfo("modelsfile is missing, Exiting script!", "Error")
		return None
	elif modelno == "nomatch":
		BoxInfo("Unknown switch, Exiting script!", "Error")
		return None
	while True:
		result = crt.Dialog.Prompt("Enter portname:", "Interface name", "gi1/0/24")
		if VerifyIsInt(result):
			crt.Screen.Send("conf t" + chr(13))
			crt.Screen.Send("default interface " + result + chr(13))
			crt.Screen.Send("interface " + result + chr(13))
			Trunk()
			Ending()
			return None
		else:
			BoxInfo("Wrong portname", "Interface name")
			return None

##
## start main menu
##
crt.Screen.Synchronous = False

while True:
	mainMenu = crt.Dialog.Prompt("Select operation:" + "\n" +
															"[1] Run Factory Default" + "\n" +
															"[2] Run Provisioning" + "\n" +
															"[10] Make one internal trunk port" + "\n" +
															"[11] Make one ISE accessport" + "\n" +
															"[12] Make one KBN trunk port" + "\n" +
															"[13] Make one external access port" + "\n" +
															"[14] Make one ISE exception" + "\n" +
															"[98] Reload now" + "\n" +
															"[99] Exit",
															"Cisco Provisioning Script " + version)

	if mainMenu == "1":
		# factory default
		if OnlySerialConnected() == False:
			break
		CheckExecMode()
		FactoryDefault()

	elif mainMenu == "2":
		# provisioning
		if OnlySerialConnected() == False:
			break
		CheckExecMode()
		mainMenu2()
	
	elif mainMenu == "10":
		# Make one internal trunk port
		CheckExecMode()
		mainMenu10()
	
	elif mainMenu == "11":
		# Make one ISE accesport
		CheckExecMode()
		mainMenu11()

	elif mainMenu == "12":
		# Make one KBN trunk port
		CheckExecMode()
		mainMenu12()
	
	elif mainMenu == "13":
		# Make one external access port
		CheckExecMode()
		mainMenu13()

	elif mainMenu == "14":
		# Make ISE exception
		CheckExecMode()
		mainMenu14()

	elif mainMenu == "98":
		# reload now
		if OnlySerialConnected() == False:
			break
		CheckExecMode()
		crt.Screen.Send("reload" + chr(13))
		crt.Screen.Send(chr(13))

	elif mainMenu == "99":
		# exit
		break

	elif mainMenu == "":
		# cancel
		break

##
## end main menu
##
