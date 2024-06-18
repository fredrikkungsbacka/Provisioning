# $language = "Python3"
# $interface = "1.0"

"""
Cisco Provisioning Script

This is a script to provision, make standard changes and reporting to Cisco devices at Kungsbacka kommun.
It provides integration with several tools and systems used by the network team.

Version:    2024.0.0
Author:     Fredrik Karlsson (fredrik.karlsson@kungsbacka.se)
Maintainer: Fredrik Karlsson (fredrik.karlsson@kungsbacka.se)
Legal:      For Kungsbacka kommun internal use only!
License:    This script and its components are subject to confidentiality and may not be distributed to anyone other than authorized personnel for its express purpose
Status:     Development
"""

###
# start script
###

# create parts of the menu
menu_headtext = ( # menu header
  f" Version {__doc__.split('Version:')[1].split(chr(10))[0].strip()} ({__doc__.split('Status:')[1].split(chr(10))[0].strip()})\n"
  f" By: {__doc__.split('Author:')[1].split(chr(10))[0].strip()}\n"
  f" {__doc__.split('Legal:')[1].split(chr(10))[0].strip()}"
)
menu_title = __doc__.splitlines()[1] # the name of the script

# handle if script is executed outside of securecrt
try:
  # fix for code validators
  crt_object = crt # type: ignore[name-defined]
except NameError:
  # name crt is not defined
  menu_headdel = "=" * round(len(max(menu_headtext.split(chr(10)), key = len)) + 1) # create delimiter dynamically after header length
  print(f'{menu_headdel}\n {menu_title}\n{menu_headtext}\n{menu_headdel}\nScript not run from SecureCRT, Exiting!')
else:
  menu_headdel = "=" * round(len(max(menu_headtext.split(chr(10)), key = len)) * 0.67) # create delimiter dynamically after header length
  menu_header = f'{menu_headdel}\n{menu_headtext}\n{menu_headdel}\n' # assemble the header

  crt_object.Dialog.MessageBox(f'{menu_header}\nThis is not the script!', menu_title, 16 | BUTTON_OK ) # type: ignore[name-defined] # pylint: disable=undefined-variable

###
# end script
###
