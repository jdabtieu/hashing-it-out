import subprocess
import signal

received_sigint = False

def get_total_hugepages():
    with open('/proc/meminfo') as f:
        for line in f:
            if 'HugePages_Total' in line:
                return int(line.split()[1])
    raise Exception('HugePages_Total not found')

def get_free_hugepages():
    with open('/proc/meminfo') as f:
        for line in f:
            if 'HugePages_Free' in line:
                return int(line.split()[1])
    raise Exception('HugePages_Free not found')

def sigint_handler(sig, frame):
    global received_sigint
    received_sigint = True
    return

# Get KB usage of hugepages
def main():
    signal.signal(signal.SIGINT, sigint_handler)
    total_pages = get_total_hugepages()
    min_free_pages = total_pages
    while not received_sigint:
        min_free_pages = min(min_free_pages, get_free_hugepages())
    print((total_pages - min_free_pages) * 2 * 1024)  # 2MB hugepages

if __name__ == '__main__':
    main()