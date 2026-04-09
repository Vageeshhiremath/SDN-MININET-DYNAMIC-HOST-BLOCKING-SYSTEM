import subprocess

def is_blocked(ip):
    result = subprocess.run(
        ["sudo", "ovs-ofctl", "-O", "OpenFlow10", "dump-flows", "s1"],
        capture_output=True, text=True
    )

    output = result.stdout
    return f"nw_src={ip}" in output and "actions=drop" in output
