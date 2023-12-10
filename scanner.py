import os

def get_PID_by_files(max_pid):

    existing_pids = []

    for pid in range(1, max_pid+1):
        pid = str(pid)
        try:
            # If this file exists, then the *thread* exists
            with open(f"/proc/{pid}/status") as file:
                for line in file:
                    if line.startswith("Tgid"):
                        tgid = line[line.rindex("\t") + 1:-1] # Remove tab and newline to get the TGID
                        # If the TGID is different from the PID of the current folder then it is only a thread, therefore not shown in the directory listing of /proc
                        if tgid == pid:
                            existing_pids.append(pid)
        except FileNotFoundError:
            continue

    return existing_pids

def get_PID_by_dir():
    displayed_pids = []
    for file in os.listdir("/proc"):
        # Filter out the files and folders under /proc that do not correspond to PIDs
        if os.path.isdir(f"/proc/{file}") and file.isnumeric():
            displayed_pids.append(file)
    
    return displayed_pids

def check_hidden_modules():

    modules_proc = []
    hidden = []

    # First, get all modules according to /proc/modules (Which is used my lsmod)
    with open("/proc/modules", "r") as file:

        for line in file:
            modules_proc.append(line[:line.index(" ")])


    modules_sys = os.listdir("/sys/module")

    # Not all subdirectories in /sys/module correspond to modules. But those that contain a sections-subdirectory do.
    for module in modules_sys.copy():
        if "sections" not in os.listdir(f"/sys/module/{module}"):
            modules_sys.remove(module)

    for module in modules_proc:
        if module not in modules_sys:
            hidden.append(module)

    for module in modules_sys:
        if module not in modules_proc:
            hidden.append(module)
    
    return hidden


def check_hidden_pid():

    max_pid = 0
    hidden = []

    with open("/proc/sys/kernel/pid_max", "r") as file:
        max_pid = int(file.readline())

    # It is possible that some process terminates between get_PID_by_files and get_PID_by_dir
    # It is also possible that a new process is created inbetween, but that is not a problem, 
    # as rootkits will probably not hide /proc/<pid>/status without hiding /proc/<pid>
    existing_pids = set(get_PID_by_files(max_pid))
    displayed_pids = get_PID_by_dir()

    # With this, only PIDs that have existed before calling get_PID_by_dir as well as after calling it will be taken into consideration
    existing_pids = existing_pids & set(get_PID_by_files(max_pid))

    for pid in existing_pids:
        if pid not in displayed_pids:
            hidden.append(pid)

    return hidden

if __name__ == "__main__":
    
    is_detected = False

    for module in check_hidden_modules():
        is_detected = True
        cmdline = ""
        with open("/proc/{module}/cmdline", "r") as file:
            cmdline = file.readline()
        
        print(f"The module {module} is hidden. It might be a rootkit. Cmdline: {cmdline}")

    for pid in check_hidden_pid():
        is_detected = True
        print(f"Process {pid} is hidden. Potential Rootkit-Activity")
    
    if not is_detected:
        print("No signs of rootkits found. This does not mean that there are none.")
