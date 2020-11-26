# Provisioning

This is a script to provision and make standard changes to Cisco switches at Kungsbacka kommun
It provides integration with SecureCRT, Cisco Identity Service Engine and Solarwinds IPAM

Please choose a branch

## Release Notes ##
* Translated to Python 3.8
* A menu is replacing seperate scripts
* Factory Default and T2KBN moves from main script to the menu
* Better formatting, readability and handling of Json in dialogue with RESP API
* Encryption of the passwordfile. this removes the version dependence of that file, and replacing it with a key file that gets downloaded the first time the script runs
