import os

def get_PID_by_files():

    existing_pids = []

    for pid in range(1, max_pid+1):
        try:
            with open(f"/proc/{pid}/status") as file:
                for line in file:
                    if line.startswith("Tgid"):
                        tgid = line[line.rindex("\t") + 1:-1] # Remove tab and newline
                        if tgid == pid:
                            existing_pids.append(pid)
        except FileNotFoundError:
            continue

    return existing_pids

def get_PID_by_dir():
    displayed_pids = []
    for file in os.listdir("/proc"):
        if os.path.isdir(f"/proc/{file}") and file.isnumeric():
            displayed_pids.append(file)
    
    return displayed_pids

def check_hidden_modules():
    modules_proc = []
    hidden = []

    with open("/proc/modules", "r") as file:

        for line in file:
            modules_proc.append(line[:line.index(" ")])


    modules_sys = os.listdir("/sys/module")

    for module in modules_sys:
        if "sections" not in os.listdir(f"/sys/module/{module}"):
            modules_sys.remove(module)

    for module in modules_proc:
        if module not in modules_sys:
            hidden.append(module)
    
    return hidden


def check_hidden_pid():

    max_pid = 0
    hidden = []

    with open("/proc/sys/kernel/pid_max", "r") as file:
        max_pid = int(file.readline())

    existing_pids = set(get_PID_by_files())
    displayed_pids = set(get_PID_by_dir())

    # With this, it is possible that a PID is listed as a dir under /proc but is terminated before this line, 
    # so that displayed_pids contains a PID that existing_pids does not contain.
    # This is fine however, as we can assume that a rootkit would not hide the /proc/<pid>/status file without hiding the directory.
    existing_pids = existing_pids & set(get_PID_by_files())

    for pid in existing_pids:
        if pid not in displayed_pids:
            hidden.append(pid)

if __name__ == "main":
    print("test")
    for module in check_hidden_modules():
        print(f"The module {module} is hidden. It might be a rootkit.")

    for pid in check_hidden_pid():
        print(f"Process {pid} is being hidden. Potential Rootkit-Activity")
    
