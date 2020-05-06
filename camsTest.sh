#!/bin/sh
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/camsTest/config.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/camsTest/config2.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/camsTest/config3.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/camsTest/config4.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/camsTest/config5.txt; exec bash"
