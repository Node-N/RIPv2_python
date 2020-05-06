#!/bin/sh
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test3/config1.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test3/config2.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test3/config3.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test3/config4.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test3/config5.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test3/config6.txt; exec bash"
