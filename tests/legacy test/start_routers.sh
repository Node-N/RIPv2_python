#!/bin/sh
gnome-terminal -- /bin/sh -c "python3 rip.py config.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py config2.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py config3.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py config4.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py config5.txt; exec bash"
