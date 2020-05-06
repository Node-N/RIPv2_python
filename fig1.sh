#!/bin/sh
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/fig1/config1.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/fig1/config2.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/fig1/config3.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/fig1/config4.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/fig1/config5.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/fig1/config6.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/fig1/config7.txt; exec bash"
