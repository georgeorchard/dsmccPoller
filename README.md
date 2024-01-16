README - dsmccPoller.py

This program takes an input transport stream file name, interval, count, PID and creates a TS file that has count DSMCC packets of pid, split between interval ms of stuffing packets.

HOW TO RUN

Ensure first that TSDuck is installed and up to date.

Run dsmccPoller.py from command line:
python dsmccPoller.py [param1] [param2] [param3] [param4] 
[param1] - (String) file name for the transport stream (with or without extension)
[param2] - (Int) interval in ms between DSMCC count packets
[param3] - (Int) count of DSMCC count packets
[param4] - (Int) PID for DSMCC count packets
