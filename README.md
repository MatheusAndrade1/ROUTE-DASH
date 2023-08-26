# ROUTE/DASH Analyzer

The Lua file is a Wireshark dissector that dissects the UDP payload to identify ROUTE protocol fields. The dissector saves the payloads to a local folder.

The python script reads the files saved into the local folder to identify the parameters described by the MPD, it also rename the files according to the T-SID sinalization.
