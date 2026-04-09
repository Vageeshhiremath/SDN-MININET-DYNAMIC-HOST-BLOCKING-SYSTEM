import subprocess

def block_ip(ip):
    cmd = [
        "sudo", "ovs-ofctl", "-O", "OpenFlow10",
        "add-flow", "s1",
        f"priority=100,ip,nw_src={ip},actions=drop"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr

def unblock_ip(ip):
    cmd = [
        "sudo", "ovs-ofctl", "-O", "OpenFlow10",
        "del-flows", "s1",
        f"nw_src={ip}"
    ]
    subprocess.run(cmd, capture_output=True, text=True)
