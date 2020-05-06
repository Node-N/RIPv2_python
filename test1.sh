#!/bin/sh
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test1/config1.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test1/config2.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test1/config3.txt; exec bash" 

