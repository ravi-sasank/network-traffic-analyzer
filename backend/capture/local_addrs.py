"""Discover this machine's own IP addresses so we can tell local from remote."""
import subprocess
import re


def get_local_addresses(iface):
    """Return the set of IPv4/IPv6 addresses bound to the interface."""
    addrs = set()
    try:
        out = subprocess.run(["ifconfig", iface], capture_output=True,
                             text=True, timeout=5).stdout
        addrs.update(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out))
        for a in re.findall(r"inet6 ([0-9a-fA-F:]+)", out):
            addrs.add(a.split("%")[0].lower())
    except (subprocess.SubprocessError, OSError):
        pass
    return addrs
