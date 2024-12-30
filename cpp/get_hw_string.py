import subprocess

# [COUNT]x [CPU MODEL], [OS RELEASE], [PYTHON VERSION], [RAM GB]
def get_hardware_string():
    # Get CPU info
    cpu_info = subprocess.run("lscpu", capture_output=True, text=True).stdout.splitlines()
    cpu_count = [x for x in cpu_info if 'CPU(s)' in x][0].split(":")[1].strip()
    cpu_model = [x for x in cpu_info if 'Model name' in x][0].split(":")[1].strip()

    # Get OS info
    os_info = subprocess.run("lsb_release -a", capture_output=True, text=True, shell=True).stdout.splitlines()
    os_release = [x for x in os_info if 'Description' in x][0].split(":")[1].strip()

    # Get Python version
    python_version = subprocess.run("python --version", capture_output=True, text=True, shell=True).stdout.strip()

    # Get RAM amount
    ram_info = subprocess.run("free --giga", capture_output=True, text=True, shell=True).stdout.splitlines()
    ram_gb = [x for x in ram_info if 'Mem' in x][0].split()[1]

    return f"{cpu_count}x {cpu_model},{os_release},{python_version},{ram_gb} GB RAM"

print(get_hardware_string(), end='')