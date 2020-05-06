#!/bin/sh
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test4/config1.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test4/config2.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test4/config3.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test4/config4.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test4/config5.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test4/config6.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test4/config7.txt; exec bash" &
gnome-terminal -- /bin/sh -c  "python3 rip.py tests/test4/config8.txt; exec bash"
