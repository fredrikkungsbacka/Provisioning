# Changelog
All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog (https://keepachangelog.com/en/1.1.0/), and this project adheres to Calendar Versioning (https://calver.org/).

<details>

<summary> Template </summary>

## Version

### Added
- New features

### Changed
- Changed behaviour

### Fixed
- Fixed bugs

### Caveat
- Things to take note off

### Security
- Security related fixes and changes

### Removed
- Removed features

</details>

## 2026.1.1
- Coming soon!

## 2025.12.1
### Changed
- Added timeout for cable check in device_upgrade().
- Netmask and gateway is read fron Solarwinds
### Added
- BPDUfilter on kbn-trunk.
- Support for running inside a Vmware host.
### Fixed
- Add_vlan() did not detect vlan name correctly.
- Support for Passbolt v5 API
### Removed
- "logging snmp-authfail" is deprecated.

## 2025.9.1
### Changed
- Passbolt key file can be both .asc and .txt.

## 2025.8.1
### Fixed
- Regex used is not synced with regexr.com.
- Some ignored validation errors from Mypy were finally fixed.
- Some ignored validation errors from Pylint were finally fixed.
- Comments in cert_create_pfx() mentioned csr when it should be pfx.
- Cleaned up req().
- crt_config_object was named crt_object_config at some places.
- "authentication open" is needed with IOS-XE
### Changed
- mainmenu() now dynamically creates mainmenu_list from doc string in the global functions.
- Hash used in cert_create_pfx() is now using SHA256.
- cisco_encrypt() now using fever modules.
- For missing Teams folders a web page is now opened to make the sync.
- Username passwords are entered with a 9 type of hash.
- Logging to file is disabled as standard.
### Added
- "no errdisable detect cause gbic-invalid".
- Support for SecureCRT 9.7.
- Support for Python 3.14.

## 2025.4.1
### Changed
- Restructured install and update of modules in pre_checks().
- Required modules moved to settings.json.
- Rewritten user group part in pre_checks() and settings.json.
- Removed group names as a string in permissions for menulist.
### Fixed
- Corrected detection of domain name in mainmenu3().
### Added
- Added support for unsupported SFPs.

## 2025.3.1
### Changed
- Optimized code for certificate bundle.
- Optimized error checking in checks().
- SSH cipher, mac and key exchange is optimized in crt_session_config().
- You can now use domain suffix in mainmenu3()
### Fixed
- Problem detecting port description in menuitem16()
### Removed
- Removed support for SecureCRT 9.5

## 2025.1.1
### Changed
- Changes in quarantine vlan.
### Added
- Function sol_find_unmanaged().
- Function sol_remanage_node().
- Menu item 6 that can remanage all nodes that responds.
### Fixed
- EEM applet was not detected correctly in menuitem12().

## 2024.12.1
### Added
- Dialogue to approve the hostname when using menu number 2.

## 2024.11.3
### Fixed
- Misspelling in qos setting caused a crash.
- Change in mtu jumbo threw an error.

## 2024.11.2
### Fixed
- pb_get_secret() didnt format device secrets as it should.

## 2024.11.1
### Changed
- IOx is now a variable in the models JSON file.
- Using the API gateway function on all ISE calls.
- Login to Passbolt is now retried three times before giving up.
- TOTP dialog is now retried three times before giving up.
- Passbolt functions are optimized.
- Line send delay when using SSH is increased.
### Fixed
- Vlan detection failed when device contains multiple L3 interfaces.
- Vlan detection failed in function add_vlan() when string matched multiple vlans.
- Fixed errors, warnings and notices from updated Pylint.
- When using range in 11-16 an error occured that the interface was not updated in Solarwinds.
- The function sol_update_int_unplug2() had a bad variable declaration in argument 2.
- Errors in add_vlan() when adding certain vlans.
- "file prompt quiet" prevented upgrade of device.
- dns_query() failed when using hostname only.
- Increased line send delay.

## 2024.10.1
### Added
- Support for SecureCRT 9.6.
- Support for Python 3.12.
- Creation of certificate now validates if directories or files exist.
### Removed
- Upgrade of Python is removed from script.
### Changed
- Functions using serial now share the same function.
### Fixed
- ps_dns_record didnt return a string when returning an error.
- Inconsistency in the use of url in settings.json.
- All errors derived from an try/except are converted to string.

## 2024.8.1
### Added
- Source interface for tacacs.
- Source interface for SNMP traps.
- Source interface for syslog.
### Removed
- "ip device tracking probe delay 15".
- References to 15.0 code.
- Models running 15.0 code.
### Changed
- Rewritten the function add_vlan to better handle renaming of preexisting vlans.
- Line send delay is increased to 100ms.
- Using translate() and a dict instead of something homebrewed.
- deswedify() changed name to trans_character().
- port-security should not be enabled together with dot1x on access ports.
- pb_decrypt() now have error handling.
### Fixed
- New version of Pylint threw warning E0606.
- Revisited and fixed older verification errors from mypy.
- App-interfaces was added for monitoring.

## 2024.5.6
### Fixed
- Cleaned up everything that mentioned object id and where it was validated
- Removed redundant code in input validation
- Misspelling of variable

## 2024.5.5
### Changed
- CA bundle file can now be specified per service
- Restructured checks dict to be tiered
### Fixed
- LM-number not recognized when adding device for monitoring
- Cannot verify DNS-record when using LM-number

## 2024.5.4
### Changed
- No longer using computer certificate storage but a certificate bundle file
- Using URL as input in check_web_server instead of fqdn

## 2024.5.3
### Changed
- Quickfix now continues if no responce from device
### Added
- Quickfix now prompts to save result

## 2024.5.2
### Fixed
- Problems with verification of installed modules after modification in Python
- Issue with local shell/cmd where enter was misinterpreted
### Changed
- The Setuptools package is no longer used, replaced by importlib.metadata

## 2024.5.1
### Removed
- Temporary option 99 is removed
### Added
- Support for Application Hosting
- Support for new switch model C9300X-24Y
- Support for deployment switches
### Changed
- About detects whether the internet is reachable or not
- Key for url and port was standardized in settings.json and script
- Import of modules fully in accordance with PEP-8
- Added Unlock and ResetCaption to mainmenu()
- Character delay for series sessions changes and becomes faster
- Offline management of Passbolt now in all menu items
- Swaps banner mod for banner exec
- The number of VTY lines is increased to 32 for IOS-XE
### Fixed
- Validation of LM numbers failed
- Waiting time in crt_sendline was counted incorrectly
- check_exec_mode could be terminated after a single attempt
- Empty rows in the building register crash when these are interpreted as incorrect object types
- When searching for site in building registers and selecting cancel, the script crashes with KeyError
- Formatting of the popular name takes place after approval

## 2024.3.3
### Removed
- Removed support for SecureCRT 9.4
### Changed
- Nowadays uses part of the LM number in the host name instead of the whole
### Fixed
- Fixed a path when creating CSR

## 2024.3.2
### Fixed
- When adding for monitoring from option 2, the variable type failed
### Added
- When making a trunk, it is verified that the interface is not connected
- Installing the cryptography module
- Extended permission management
- Installs modules based on group affiliation
### Changed
- Timeout for WaitforString and ReadString agreed throughout the script
- Improvements when management vlan is detected
- Cleaned up the list of modules that are installed, and made some depending on group permissions
### Removed
- OpenSSL.crypto.PKCS12 is no longer supported, stops using the pyOpenSSL module

## 2024.3.1
### Added
- DHCP relay agent for external access port is now added when needed
- Dialogue for ip address, address and popular name for site
### Fixed
- Line send delay was missing for cmd
- WaitForString in the context of CMD was handled incorrectly due to bug
- Error handling from crt_box_dialogue was inconsistent
- WaitForStrings has a delay when the crt object is not used, which caused matching to often be missed
- The get_model function could sometimes mismatch on command
- Delay in crt_sendline miscalculated if the next command was a crt function
### Changed
- Total rewriting of excel_read_br to be able to rewrite strings with unusual characters

## 2024.2.2
### Fixed
- Problem with referencing the building register file name in settings.json
- Payload incorrect on discovery in Solarwinds due to incorrect placement of new feature

## 2024.2.1
### Added
- Support for SecureCRT 9.5
- Check_web_server has been speeded up
- Lookup in the building register is redone
- New hostname default
- When the age of a Passbolt AD account password approaches 30 days before the mandatory change, the user will be prompted once a day until it is changed.
- It is now possible to add endpoints without having previously connected to the network
- Warning about a new node in Solarwinds is in ignore list
- New feature for backup of shared resources in Passbolt
### Fixed
- Unpluggable was put wrong on access ports (10-15)
- The use of User-Agent was inconsistent and partially inaccurate against RFC
- End of session in case of error against Passbolt was not handled
- Enhanced logging when removing from Solarwinds
- Stopped handling serial ports when an invalid port was encountered
- The PID and VID of the Cisco USB Adapter are no longer presented by Windows
### Changed
- "Remove node…" renamed to "Delete node…"
- Copyright removed as not required since 2000

## 2023.10.2
### Added
- Support for RESTCONF
- Verification of user data from Passbolt
### Fixed
- Loop when device is added for monitoring in DNA Center
- Energywise on devices without support for it fails
- Corrected parts of the code for Passbolt according to the design philosophy
- Error in generating csr
- Multiple errors when generating pfx
- After renaming in option five, login fails as location is not set correctly
### Security
- Increased security for NETCONF-YANG
- Increased separation of the use of the variable secret

## 2023.10.1
### Added
- Removes backup of SecureCRT as it requires more advanced management than is worthwhile
- Optimized the code for the integration with Passbolt
- Catalyst 9300-24U support
### Fixed
- Had missed adding Passbolt for option 43
- Could get an error when install remove inactive is complete as the line was cut while the system was waiting
- Source interface could not be set correctly for ip http client
- Crash when the wrong password was retrieved from Passbolt for Powershell
### Security
- Higher and configurable security when using Powershell

## 2023.9.4
### Added
- Reduced exposure of login credentials between modules
- Range can now be used for interface configuration
### Fixed
- Certain characters in the password of an SSH session cause SecureCRT to stop the script
- Missing exception when retry in requests
- Misspelling in option 3 created a crash

## 2023.9.3
### Fixed
- Missed installation of the pgpy module
- sol_delete_node could crash when node is deleted in Solarwinds that is already deleted
- There was a risk that Passbolt passphrase could be saved by mistake
- Authentication errors in requests caused a crash
- Wrong password in Passbolt caused a crash
- Problems creating SSH sessions when passwords are too complex due to special characters

## 2023.9.2
### Added
- Cleared out values based on group affiliation
### Fixed
- Backup failed as "Single Instance" could not be set

## 2023.9.1
### Added
- Instead of handling an encrypted file with keys and passwords, these are now retrieved in an integration with Passbolt
- Is given the option to connect a trunk port when device is added for monitoring from option 2
- Uses User instead of Device credentials in Solarwinds
- Devices added for monitoring via provisioning are added as unmanaged by default
- Smart licensing directly to Cisco instead of your own satellite
- Improved error handling in requests
- Requests are now more robust in case of transient communication issues, retrying multiple times
### Fixed
- Added a timeout in case crt_connect_cmd cannot detect completed command
- Stuck on clearing flash on IOS-XE
- Bug in SecureCRT crashing application and/or script after a new serial session
- Bug in option 14 where suggestions were not given when trunk ports did not exist
### Caveat
- A bug causes the script and/or application to crash when you do an unlock on all tabs and then use the tab object.
  This means that the command that unlocked all the tabs must be removed. Also means that if a tab is locked and the script talks to it, the script crashes with the explanation that the tab is locked.

## 2023.8.1
### Added
- Support for adding KBN devices to the monitoring
- New and more secure access management
- Support for Python 3.11.
- All parts that use requests now share a common function for this so that all calls have the same properties
- Option 2 detects if the horizontal stack is active, and cancels if it is
- New structure for objects and values in sessions
- Now get a question after provisioning if the switch should be added for monitoring
- Removes option 99, takes up space and is not used
- Better error messages from the check_web_server feature
### Fixed
- A bug in option 3 that left a locked tab
- Cleaned up a couple of details that violated the design philosophy of the script
- Errors in crt_connect_cmd that caused the tab to be closed prematurely and the log did not contain information
- A bug in option 60 caused it to crash when canceling
- Didn't detect major version of Python correctly
- Error in option 12 regarding eem script
- Had missed detection of OS and platform when updating Python
- Key error downloading updated key
- Get_stack does not detect switches where the virtual stack must be activated correctly
### Removed
- Removing support for 3.9
- Stops using OrionSDK in favor of the more general requests, as it is poorly updated and lacks a lot of features
- Removes support for SecureCRT version 9.3
### Changed
- Limit LLDP on trunks and external access port. This boils down the table to only the devices that are visible on a local access port

## 2023.5.1
### Added
- Integration med Cisco Firepower Management Center
- Better handling of errors when decoding json files
- Extended handling of invalid VLANs when KBN trunk is created
### Fixed
- Invalid names in modules for Solarwinds according to pylint

## 2023.4.4
### Added
- When provisioning a new device and the ip or name already exists, the vlan interface is removed and the hostname is cleared
- Options that create trunks did not provide a port example when the switch has a module for trunks
### Fixed
- Redefinition of built-in function (exit)
- Got to learn about deepcopy() to fix an issue with putting multiple devices in sequence in ISE
### Changed
- Storm-control of multicast was increased to 20% on access ports

## 2023.4.3
### Added
- Template for new units in ISE is now set in settings.json
- New option to connect serial port with 115200 baud
### Fixed
- Has been inconsistent with how central variables are used by subfunctions
- Description for ports not to be used was not put in settings.json
- The function put_personal_settings used the wrong code table
- Menu 20 had the wrong icon in the dialogs

## 2023.4.2
### Added
- The cisco_encrypt function now uses the hashlib module instead of scrypt, which is deprecated
- Speeded up write-to-screen by not reading session config every time the function crt_sendline invoked
- The header in the menu is now built completely dynamically as cli and gui have different spacing for characters
- Removed dialog when session closes or shuts down
### Fixed
- Error in verifying servers in option 3
- Cisco_encrypt found to format Cisco Type 8 and 9 keys incorrectly
### Removed
- Support for SecureCRT version 9.2 is removed

## 2023.4.1
### Fixed
- Two bugs from previous version fixed
- Bug in option 40 caused the dialog to loop when an error occurred
- The vlan add feature didn't clear junk characters in the list
- A bug in the upgrade module affected ISL-compatible devices. Nowadays I use port_trunk to create a trunk port
- The name change feature was never really visible when it was launched. Fixed this as well as verification of new hostname in the function

## 2023.3.2
### Added
- Enables DOM monitoring on models that support this
- Support for USB adapters from SiLabs
- Support for C9200CX
### Fixed
- Removes control of confreg, as that value can be displayed intermittently
- 1000 switches have a different syntax for jumboframes
- In sol_update_custom there was a unique value that was moved to settings
- Removed stack-oid as separate value, it's an effect of stackwise
- Support for Netconf only for IOS-XE

## 2023.3.1
### Added
- Status messages to cli for several of the control functions
- Network modules in switches are now retrieved from models.json instead of in the code
### Fixed
- Bug in menu in option 20 fixed
- Forgot to migrate snmp contact to settings.json
- SNMP contact fanns dubbelt
### Removed
- Removes support for Python 3.10 as a module does not support this

## 2023.2.3
### Added
- Better error messages for series sessions

## 2023.2.2
### Added
- Added a previously separate tool
- Option 20 menu is now built in the same way as the main menu
- Certificate issuance and management features are now added
- Verifies configuration records in options 2 and 9
- Can now manually enter ip or accept default address in option 2
- Removed unnecessary loops, and standardized the use of get_model
### Fixed
- Error upgrading IOS-XE created infinite loop
- Reuse of open tabs with series sessions could fail in some cases
- Checking the number of serial ports should only check approved adapters from the list
### Changed
- Reload at the end of alternative 2
### Security
- Mitigerar CVE-2023-20076

## 2023.2.1
### Added
- Upgrade breaks out as a feature that can be reused, this reduces complexity
- The menu is broken out as a function to be reused in other scripts
- Error message if too many USB adapters are connected (>1)
- Upgrading no longer removes active image
- Made some functions that collect information more robust
- Handles faulty USB serial driver
### Fixed
- Crash when updating interface if Solarwinds is not reachable
- Error at prompt for overwriting existing error could loop upgrade
- Mishandling of get_stack had fallen away
- "ip routing" is not available on IE-3300
- Error handling when creating series session in option 2 has been removed

## 2023.1.6
### Added
- New option to save active session to Session Manager

## 2023.1.5
### Fixed
- Resync to DNA Center failed as payload was incorrect
- KBN trunk cannot use ADD, so the EEM script must be removed and appended
- EEM is not supported by all models

## 2023.1.4
### Added
- Warning when interface is updated on a device that is not set up in Solarwinds, has now been removed
- New option to rename a device in all systems, and also on the device itself via SSH
### Fixed
- Found an issue with detecting certain text in a session, which made a difference between SSH and serial sessions. This means that the same latency that serial sessions have for each character is also applied to SSH and Local Shell sessions.
### Changed
- Extended logging to buffer
- Stops logging ntp
- Power budget for IE3300 was too low

## 2023.1.3
### Added
- Option two doesn't shut down the session for long

## 2023.1.2
### Fixed
- (Connection timed out) when upgrading
- Removed collection of output at Local Shell, this gave intermittent problems to end session
### Changed
- Added EEM script when provisioning that prevents common mistakes

## 2023.1.1
### Added
- The variables username and group are now set via the systemsv
- Speeded up ssh and serial sessions
- Removes migrations of settings from previous versions
- Sets various emulation and color settings for all sessions
### Fixed
- Input dialog missing strip
- Bug in option 13 that crashed the script on switch with IOS-XE
- Sometimes a completed command was not detected in CMD

## 2.11.7
### Fixed
- Errors when installing and updating modules due to characters from certain modules

## 2.11.6
### Fixed
- Optimized charging of external modules
### Removed
- python-certifi-win32 module is no longer supported, replaced with pip-system-certs

## 2.11.5
### Fixed
- Serial port management could fail in option 40
### Removed
- RDP sessions via script are from SecureCRT version 9.4 no longer supported

## 2.11.4
### Added
- Restricted QoS on access port disappears
- Completely redesigned how stacks are handled and fixed some bugs along the way
- Added global metadata to docstring
- Multigig is migrated into the access port instead
### Fixed
- A bug sneaked in from the previous version related to the detection of interfaces in clusters
- Changed the use of the term cluster to stack, meaning different things

## 2.11.3
### Added
- Support for NETCONF
- Support for WS-C3560CX-12PD with multigig trunk ports
### Fixed
- Detection if switch is connected in menu 2 could fail at times
- Screen Sync could be faulty in some cases
- The feature get_model could crash occasionally for unknown reasons

## 2.11.2
### Added
- Updating modules can now be postponed
- Verification if a switch is connected occurs before removal with option 4
- Multiple-choice questions have been given a facelift
### Fixed
- Option 3 did not take into account that the description on the port could have different strings

## 2.11.1
### Added
- For an external access port, a shut/no shut is now also made
- New option to clear a port and mark as FREE
- Activera scriptindicator and tab
- The code behind the menu now automatically formats the columns and retrieves description from the functions
- Will launch in a public version that lacks privacy elements
- The "description" on a port now derives its value from settings.json
- Support for IEM-3300-8S expansion module
- When provisioning, it is verified that no port is connected
### Fixed
- In menu 11, the word ISE is removed as it could not only produce ISE access ports
- Smart license transport cslu was misspelled

## 2.10.3
### Added
- Setting session options for RDP
- How the menu is created is completely rewritten
- When a trunk port is created (internal and against kbn) a shut/no shut is now made
- Option 13, external access port, has received vlan id validation
- Json file for vlan now contains more information used by different parts
- Optimized how json files load
### Fixed
- When port configurations are performed (10-14), no unlock is made by the tab when an error occurs

## 2.10.2
### Added
- Possibility of group settings based on logged in user
- Verification of logged in user against the list of approved
### Fixed
- Structured about personnel settings and migration
- Terminates ssh sessions incorrectly in reports and upgrade when an error occurs
- Single Instance was incorrect on startup
- Crash in report 32 if no multigig ports exist
- Auth prompt valid only in ssh sessions

## 2.10.1
### Added
- Backup of SecureCRT configuration every month
- Necessary directory structure is created if it is missing
- New menu options for connecting SSH and RDP
### Fixed
- Time spent in the script could differ in different parts
- Improved and uniform detection of values in personalsettings
- Suspects an issue when updating Python modules when the resolution of the screen is poor
### Changed
- Device classifier is now enabled by default

## 2.9.5
### Added
- Quickfix terminates if an incorrect command is encountered
- Applies protocol NO-OP to all SSH sessions
- Possibility of logging of all ssh sessions
- Rewritten how SSH sessions are handled to make reports faster by reusing sessions
- Support for SecureCRT 9.4 (Internal pre-beta evaluation)
### Changed
- Sets the highest possible STP priority by default
- When configuring KBN trunk port, the high STP priority is removed so that the switch becomes root
### Fixed
- Misunderstanding with a function in the API caused a tab where scripts are running, still trying to close (as of 2022.9.2)
- Inconsistent allusion in text and comments

## 2.9.4
### Fixed
- Cleaned up a couple of forgotten lines for tests
- The crt_connect_ssh feature now cleans entered values from junk characters
- In crt_connect_ssh, some commands could be detected incorrectly so that the script paused
### Added
- Restructured models.json with a new hierarchical structure for all interfaces
- New feature to send commands to multiple devices based on external lists (quickfix)
### Changed
- Smart license has been changed, new configuration reflects this

## 2.9.3
### Added
- When a trunk or access port is created, the unpluggable is simultaneously set in Solarwinds

## 2.9.2
### Fixed
- The ping function was validated incorrectly in a couple of places
- Changed inconsistent responses from some features
- Tab where scripts are running cannot be closed

## 2.9.1
### Fixed
- The profile name for Config Manager was incorrect if modules were upgraded while Config Manager was not actively used
- Clarified which account to use for DNS
- Missing DNS master verification before provisioning and removing device

## 2.7.1
### Added
- New version numbering based on date and a running version number
- Verifies local sync of shared files from Infra's teams channel
- Optimized the management of installed modules
- Enables automatic updating (New in SecureCRT 9.3)
- Support for C9200L-24PXG-4X switch
- Function to prevent timeout on both serial and ssh sessions when dialogues are left for a longer period of time
- Support for Python 3.10
- Code is now also verified with Mypy
- Multigig support in combination with StackWise
- The tab of the sessions is named according to what they are currently used for
- Support for all known Prolific and FTDI chipsets
- Installing Python
- Optimized the transfer of tasks between modules for SSH
- Managing idle timeouts in all sessions
### Fixed
- Log file when provisioning is not created correctly
- Checking clusters can return different spellings
- Incorrect encoding when reading groups.json
- Corrected the code after verification with Mypy
- "Auto qos global compact" is supported from 15.2.7
- SNMP location now allows more combinations
- Sets the delay setting in sessions so that the prerequisites in the script are correct when executed
### Removed
- Removes support for SecureCRT 9.0 and 9.1
- Removes support for Python 3.8
- Removes support for MacOS, but retains the ability to scale to other OS in the future

## 2.6.8
### Added
- All subfiles of the script are now gathered in a library
- Support for SecureCRT 9.3
- Support for IE-3300
### Fixed
- Automatic asset number failed when entering one, as well as support for testing

## 2.6.7
### Added
- New function for manual upgrade and verification of the software in one switch
- Verification of asset number so that it is not reused
- The next available asset number is suggested in the dialog, and verified before it is allocated
### Fixed
- When removing the switch, it may be wrong if you specify ip
- ise_delete_device could crash under special circumstances

## 2.6.6
### Fixed
- Handles crash when incorrect username is entered for DNS server
- Error occurred when image is already on switch with install mode
- Screen.Synchronous = True removed, didn't help...
- crt_sendline now always have a 175ms delay for each row. The dynamic variant can fail at times, probably due to serial buffer errors

## 2.6.5
### Added
- Can be started as a script with arguments via the SecureCRT Button Bar, and then directly launch a menu item and exit the script afterwards
### Fixed
- Cleaned up a forgotten function

## 2.6.4
### Added
- Replace the function that queries the session database from ISE with DNA-Center instead. Provides more and more reliable information

## 2.6.3
### Added
- Speeded up responses in dialogs where you can choose between hostname and ip address by not waiting for DNS lookup for ip

## 2.6.2
### Added
- Menu item 41 disappears. Switch is instead indicated in the first dialog in the menu

## 2.6.1
### Added
- Better documentation in port_trunk
- New menu item that connects a switch with ssh
### Fixed
- Corrected typos in comments
- Clarified variable name in put_personal_settings
- Rate-limit for API calls to DNA Center

## 2.6.0
### Added
- Accelerated module installation and update, reducing the number of SecureCRT reboots
- Adds switch to DNA Center
- Removing the switch in DNA-Center
- Improved handling of structure errors in json files
- Simplified management of ISE nodes in settings.json
- The code is verified and corrected with Pylint
- Structured return of value and status from functions
- About in the menu that takes the user to the system documentation
- Verification of the existence of a local library structure
- The places that use "sh ip int brie" have a better regex match
- Verification that a certificate is trusted is now done through a variable in settings.json
- Screen.Synchronous = True, used to prevent buffer errors
### Fixed
- The wrong variable was used in DNS_query when entering ip address
- The documentation for Screen.WaitForString in SecureCRT is incorrect, returns an integer and not a Booelska value as it should
- Timeout on API requests so as not to get stuck in an infinite loop
- The add_vlans function receives the wrong list of vlan
- Menu 12 has an infinite while-loop
- The get_cluster function gave errors if not used via ssh
### Changed
- "logging monitor debug"

## 2.5.5
### Added
- The options go, locks the session when the script is executed to avoid accidental input
- After the introduction of DNS, you can now enter both hostname, fqdn and ip address in the dialogs

## 2.5.4
### Added
- Also adds PTR in DNS
- Cleaned up the appearance of menus with input
- Locks the session when provisioning to prevent accidental input
### Fixed
- Some endpoints didn't send all the info which crashed the script

## 2.5.3
### Added
- Uniform all input dialogues
- Clearer information boxes
- New option 30 provides the ability to see where a device is connected through its mac. You are also given the option to connect to the switch that the device connects to if it is wired.
### Changed
- aaa accounting update newinfo periodic 15 (Changed from 2880 minutes)

## 2.5.2
### Added
- Add and remove DNS RR for the switch's inventory number via PowerShell
- ISEFindDeviceByIP now also returns hostname if ip exists
- Input of names on site becomes stricter to handle DNS names correctly

## 2.5.1
### Fixed
- If you leave the switch for more than 60 minutes with a dialog, the exec timeout will cause the script to fail to move forward when the prompt is changed
- Error in detection of previously provisioned switch

## 2.5.0
### Fixed
- Improved and uniform verification of connected device in ConnectSSH
- Managed to use type hints in an inconsistent way, cleaned this up
- Used default values in functions to an excessive extent, which causes problems when troubleshooting
- The bug in SerialConnect from 2.4.2 was never really solved, became wrong under other circumstances instead. This is now solved by rewriting pretty much the entire function
- Cleaned up how paths are specified in settings.json which was inconsistently stated
- CheckExecMode could sometimes fail on older switches that took time after the first dialog
- New dialog in CLI was not handled by CheckExecMode
- Uses ping instead of verifyinternet (which is removed) as this created a step 22 with the requirement for requests
- An error occurred while upgrading the C9300-24S
- Discovered that serial buffer could still discard characters, but very rarely. Added 25ms delay for each line in SendLine
- An error could occur when upgrading where the image is already on the flash
### Added
- Support for Credentials Manager when using SecureCRT version 9.2
- Option 13 now adds the vlanet and names it
- Improved error handling of SSH sessions
- Verification of model numbers when factory default occurs to avoid the wrong type of devices being cleared
- Review of functions in the code through unified naming and consolidation
- City network trunk can now not be created if you enter vlan that does not exist via the city network
- Sets the global setting "Single Instance" and the default session setting "Auth prompt in windows"
- Path to local library for SecureCRT is now set in settings.json
- Hashing of keys and passwords before they are written to the screen, to increase security when entering and logging
- Interfaces that are not in use are now specified in models.json
- Support for multigig ports that may have a completely different naming standard
- Support for new model WS-C3560CX-8XPD-S and C9200L-24PXG-4X with multigig ports
- Log with timestamp is created during provisioning to catch any errors
- Detection of NM on C9300 respawns
- Tidy up the header in the menu and structured the list for better readability
- Removed IBNS2, becomes impossible to maintain that code as it is not used live
- SOLFindIP handles error 500 from webserver
- Clearer dialogue when upgrading when connecting or removing cable
- Prevent provisioning of already provisioned switch
- When making an external access port, certain settings are adapted if it is Lanbit
### Changed
- Version 12.2.55 doesn't like pipe after "dir flash", switches to "show flash" instead
- Added "auto qos global compact" on selected models
- Added "dot1x timeout tx-period 7" to PortAccess
- Moved ISE specific rows within the conditions for this
- ISE Syslog to MNT is removed
- Added "transport output none" to all lines

## 2.4.5
### Fixed
- Problem detecting serial ports on newer computers, removed notification of unsupported serial ports
- Two errors in the tab object when upgrading

## 2.4.4
### Fixed
- For some switches, you could not create an access or trunk port if it would not normally have such a port
### Added
- Module control in C9300 removed, is now default

## 2.4.3
### Added
- Can now add a broadband device to ISE

## 2.4.2
### Fixed
- Fixed error in entering vlan, vlan between 50 and 99 was considered invalid
- Errors in the upgrade meant that a reload was never performed when a return was missing
- Errors in the SerialConnect function caused the wrong tab to be selected, which could be devastating

## 2.4.1
### Added
- Support for SecureCRT 9.2
- Fix in option 20 is removed, the bug is remedied by making a new ISE port instead
- Options 11 and 14 temporarily close the port during setup

## 2.4.0
### Fixed
- When a tab was reused, it did not become active
- Optimized which commands are written to the switch while still being able to cancel provisioning
- Missing a version verification timeout
### Added
- Support to retrieve address of SNMP location from building register via Excel
- New module that can translate Swedish characters
- Verification takes place that just one switch is connected in active session
- Detects if the script was executed in a CMD or WSL session, could otherwise get stuck in a loop
- Built-in management port is now set from models.json
- When ISE is not in use, the access ports are created, but without the access vlan
- When the KBN trunk is created, all VLAN in the database is now also created and named correctly
- Version information in the JSON files
- Ports for API are now set in settings.json
- The exception option now rewrites the entire port's configuration
- New menu item that connects all connected serial ports
- Completely reworked connection with ssh, now uses SecureCRT instead of a module. Much faster!
- StackWise detection capability
### Changed
- AccessPort:
  Port-security städades
  Authentication event städades

## 2.3.7
### Fixed
- A certain type of switch uses a custom/incorrect model number in some places, resulting in active software version not being detected

## 2.3.6
### Fixed
- Swapped tab for space according to PEP-8. Created problems in various editors
- GetVersion sometimes glitched and crashed the script, when the text was not captured from the cli
- Failed to specify domain name and VTP domain in settings.json, instead of hard in the code
- Exceptions are now specific according to PEP-8
### Added
- Better management and reuse of series sessions, which are already in a tab
- Consolidated OS-specific settings into preChecks
- Settings and secret are now not loaded in each module
- The dialog around entering interface names is improved. The example is a correct port for that model and function
### Changed
- "IP domain-lookup" skall numera vara "IP domain lookup"
- Smart token syntax has changed on C9K

## 2.3.5
### Added
- Support for install mode for selected switches
- Cleaned up the CleanFlash feature that integrates with other code instead
- Automatic switch restart after upgrade
- Inserting SecureCRT reboot after upgrading Python modules
- When updating or installing modules, internet access is validated
- Compare the hash of the locally stored key file to determine if it has been modified
### Fixed
- Series session management still fails, trimmed what value it uses for evaluation of ScriptTab
- Removed control of returncode after upgrading via PIP, these may vary even though they are successful
- Different stavfel i dialoger
### Changed
- Autoinstall is now disabled by default
- "IP domain-name" is changed to "IP domain name"

## 2.3.4
### Fixed
- Some minor customizations after contacting support at Vandyke, and documentation

## 2.3.3
### Fixed
- Improved management of series sessions. Can now handle multiple series adapters being connected
- An error occurs when no tabs are open and the script is executed with options that require a serial session, temporary resolution pending case

## 2.3.2
### Fixed
- Improper handling when the USB adapter is not supported/known
- Improper handling when no USB adapter is connected
- Something has happened in Windows that means that some adapters were not recognized correctly. Changed how an adapter is detected

## 2.3.1
### Added
- Nowadays does not close the current tab when starting a series session
- Closes the series session after itself
- Consolidated everything related to ISE in the settings file
- Menu 5 now also sets profile id on selected devices
### Fixed
- In menu 5, the MAC address is now in the message when it has succeeded and when it has not found the device
- The validatemac function was inconsistent with the data type it responded with
- Clearer error messages when json file cannot be read
- Clarified the text in menu 4
- Improved verification of json data when loaded
- Improved series session management
- Misspelling in menu 4 corrected
- Menu 14 did a default of the port before, which is wrong
- ConnectSerial returned with inconsistent data type
### Changed
- Improved security in ssh

## 2.3.0
### Added
- Redo how the version on the OS is checked. Constantly faulting this one somehow, especially with IOS-XE
- With new feature that reads version, "old_code" can be removed in the models file
- MAC validation now supports another format: without delimiter
- Cleaned up functions so that returned value has the same format in all applicable functions
- Moved device-sensor and device-tracker so that they are also included if you do not want ISE
- Support for SecureCRT version 9.1
- Automatic installation and updating of modules
- Support for personal settings stored locally on the computer
- Simplified the code that builds the menu, was a leftover from an attempt to build the menu from a JSON file
- Custom settings.json for new menu item six
- Added menu items 21 and 22, two different show commands
- Reworked the entire GetModel feature to make it more robust
- Started using type hints in the code for functions
### Fixed
- Missed support for MacOS lately, fixed this in the parts that handle paths and devices
- Rättat fel and models.json
- Tidy imported modules
- Verification of certificate verified wrong port in some cases
- Location Regex didn't allow street names with spaces
- Incorrect version information for some switches in models.json
- Closed the session after successful validation of certificates in ValidateCert
- Handling of exceptions in functions that read json files

## 2.2.2
### Fixed
- Error when upgrading when the flash already contains the file, but is not the active one
- Errors in the access port meant that a row was not provisioned in normal cases
- The URL for downloading the secrets file was incorrectly constructed

## 2.2.1
### Added
- Now faster to type commands in cli
- Detects previously provisioned switch
- Validation of mac address in menu 5
- Smart license is now scalable for future models through "smartlicense" in models.json
- Management over L3 is determined by "layer3" in models.json
- Optional support for IBNS 2.0, through "ibns2" in models.json and networks.json (beta)
- Terminal width changed to 150 characters
- Menu 5 can now take a comma-separated list of mac addresses
- Refined how access and trunk ports are selected, removed a model dependency in the code
- Smart license now goes to its own internal server
### Fixed
- Fixed bug that occurs when calculating free space on C9X
- Fixed Fel and Ping
- The C9300-24S has no access ports, but the script thought so. Is now fixed

## 2.2.0
### Added
- I've overworked how the menu is built, but now more programmatically correct
- Upgrade port is now dynamically generated instead of static from modelno.csv
- All loading of settings is now done from JSON files
- Certificate verification is now done by default
- Exec timeout is increased from five minutes to 15
- Moved all model-specific information to JSON file
- Control of prerequisites moved to own function, which is also only executed at start-up
- Selectively control per vlan whether quarantine, telephony or ISE is to be used in networks.json
- Prefixes on interface names are now taken from models.json
- Option 5, Change Endpoint ID Group (MAB)
- Some "lite" switches have a hardware limit for how many ports can use, for example, auto qos. Now taking this into account with "restrictedqos" in models.json
### Fixed
- The flash clearing function used the wrong variable and printed junk characters instead. Around since pre 2.0
- CheckExec could fail sometimes, put a timeout for that dialog, and restart within the loop
- Option 13, external access port, is slightly cleaned up for wider use
- Solarwinds discovery adapted for C9300

## 2.1.1
### Added
- Improved PSN node management
### Fixed
- Regex for verifying VLAN fails on numbers ending with a zero, for example 40

## 2.1.0
### Added
- Menu item four that removes a device from Solarwinds and ISE, with validation that only one IP for the access networks is selected
- Certificate verification is now modular, reducing complexity of new integrations
- Updated interface name matching to handle 100Gb and 200Gb interfaces, as well as support for Nexus
### Fixed
- Call-home can fail when it resolves over ipv6 instead of ipv4

## 2.0.4
### Added
- Login block on repeated login attempts
- Requires new module, python-certifi-win32, which reads local certificates in Windows
- Validation of certificates in the integration with ISE and Solarwinds
- Verification that the API responds correctly before menu items are executed
- Verification of installed modules
- Validation of vlan, interface and ip address takes place in a separate function for easier maintenance
### Fixed
- The integration with ISE and Solarwinds does not use global variable for server names anymore, something that was left over from pre 2.0
- Wrong variable in part of the if statement in a couple of places, meant that the dialog could not be ended with cancel or X
- Misspelling affecting port creation for 3560CG, incorrect string
- Bug crashing script in menu item 10, using wrong variable

## 2.0.3
### Added
- Trunks no longer get unplugged in menu item 3
### Fixed
- Use the Orion SDK for the IPAM integration just like other parts that speak to the Solarwinds API

## 2.0.2
### Fixed
- Cisco USB adapter responds with pid and vid as NoneType, which crashes the script

## 2.0.1
### Added
- Randomize the order of ip to dns, mnt node, ntp and psn node to "load balance"
- Removed a couple of boxes with positive status that required interactivity unnecessarily
- Tagit bort Energywise

## 2.0.0
### Added
- Translated to Python 3.8
- Menysystem ersätter de separata scripten
- Factory default and T2KBN are moved to the new menu
- Better formatting, readability and handling of json code in the dialogue with REST API
- Encryption of the contents of the password file that is now called secret.enc. The version dependency can thus be removed, and replaced with a key that is saved in each user's computer through a dialog if the file is missing
- Catalyst 1000 series support
- Hardened the configuration of IOS based on the advice of Cisco. Among other things, login only with SSHv2
- Tidy boolean handling
- Clean management of model-specific configuration
- Ability to add new devices to Solarwinds and set the right polling and properties with RESP API
- Removed support for cisco phone on access port
- KBN3 support will be removed
- Ping of device to verify that it is properly connected before provisioning proceeds
- Automatically creates a session with connected serial port when needed. The USB adapter's pid and vid must be included in the tuple tplPID and tplVID. This is so that the wrong adapter is not selected.
- Detects newly started switch and handles the auto install dialog to priv exec
- All inputs have regex verification to avoid crashes or loops
- Possibility to end at a dialogue, was not implemented before
- Menu item for fix for authentication bug of MAB
### Caveat
- Menu option three doesn't give any feedback when it works, and it takes a while

## 1.9.2
### Changed
- Optimized code
- C9k lacked a smart-license trap
- Pause function after a range command
- Optimized CleanFlash to use the FindImage feature
### Caveat
- Last version with support for VBScript

## 1.9.1
### Fixed
- Fixed order when loading external code blocks
- Verification that it is a serial session and not ssh
- Issue with C9k that now uses new method for upgrading. Redesigned the entire UpgradeCheck function

## 1.9.0
### Added
- Moves out blocks of code common into external files that are loaded as needed. Simplifies updating code between scripts
- Verifies all input so that it is formatted correctly. Must prevent crashes when incorrect value is entered

## 1.8.2
### Fixed
- Optimerat Do... Course
- Fixed bug in mode detection that sometimes didn't work if text was written to console by the Switch
- Consistent use of network(0)

## 1.8.1
### Fixed
- Fixed a bug with the C9300-NM-8X
- Automated dialogue around C9300-NM-8X

## 1.8.0
### Added
- New models file with new image for C9K
- New switch C9300-24S that only contains trunk ports
- Automated discovery of existing VLANs and management VLANs in single-port scripts
- Detection of 8x10Gb module in C9300
- If the secretfile is out of date, a new window will open where you can download new
- Detection of exec, priv exec and config mode
### Changed
- Changed the handling of the creation of trunk ports. Switched from subroutine to function
- Changed the creation of ise ports. Switched from subroutine to function
- Via ISE Accessport, classic trunk doors can now also become access ports with ISE
### Fixed
- Corrected dialogue text
- Cleaned up remnants of updating C9K models
- Fix for left conf for default gateway or route after upgrade has been performed

## 1.7.3
### Added
- The network variables are now stored in a separate file so that you do not have to edit the code inside the script if this should change. Thus introduces the file networks.csv on a common file surface.
- The single-port scripts now have support for running on any port in the switch.
- Removed page break that came with C9k in some features
### Changed
- Goes back to classic upgrade on C9K
- Changed FreeMem to a function
- Changed order of aes encryption for type 0 passwords is on its way out in c9k

## 1.7.2
### Added
- Added support for the L3 service in KBN
- Support for dhcp snooping
- Support for IBNS 2.0 which is selectable on selected switch models
- Added an ACL for VTY access, which is best-practice
### Changed
- Changed pause in SendLine to 175ms
### Fixed
- Fixed bug in the CleanFlash module for 2960X


## 1.7.1
### Added
- Added flow-control function that eliminates special settings in the session
### Changed
- Additional tidy dialogues
- Better error handling
### Fixed
- Problems with the upgrade module. Rewritten a lot of code to deal with a peculiarity that makes ftp sometimes not work.
- Forgot to enable CleanFlash in version ## 1.7.0
- Two failures in global for 2960 with 15.0

## 1.7.0
### Added
- Verified upgrade of C9K
### Changed
- Cleaned up the code that had become difficult to keep up to date
- Uniform configuration around pop-up boxes as well as cleaned count and default selection
- Cleaned variables
### Fixed
- Fixed a bug that reserved ip when upgrading
- Fixed verification of correct vlan
- Upgrades sometimes fail. Added 15sec delay before ftp transfer

## 1.6.3
### Added
- Integration of Solarwinds to find the next available ip and mark it Reserved

## 1.6.2
### Added
- Verification of switch name and ip against ISE if they already exist

## 1.6.1
### Added
- Added module for ISE REST API that adds the switch as a new network device
- Version control on secrets.dat
### Changed
- Changed the order of factory default. Always got a question about saving config

## 1.6.0
### Added
- Introduces file for switch models and its unique settings
- Introduces file for keys, tokens, and passwords
- Fixed bug in the update module that caused incorrect configuration to be saved on reboot
- Cleaned up variables used
- Added module that checks free space on flash
- Added module that can clean up old .bin files
- More and better documentation in the code
- Consolidated bits of switch configuration
