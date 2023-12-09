# LRKDetect - Linix Rootkit Detect

This is a small python script which can detect Linux Kernel Mode Rootkits.
It can detect hidden processes by checking if the PID is hidden from showing under /proc/, but the files in the PID's subdirectory are still accessible.
It can detect hidden kernel modules by checking if they hid from /proc/modules but not their subdirectory under /sys/module/.
If it hides from both locations, or does not hide at all, it will not be detected through this mechanism, but may still be detected because of hiding a PID.
There are other malicious things rootkits might do like hiding open ports, which will not be detected.

## Running the script

First, clone the repository. Second:

    python scanner.py

The script will let you know if something malicious was found.