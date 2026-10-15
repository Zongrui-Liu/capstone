# Helper function to find the VTEP for a given host IP and MAC in the EVPN table
def get_host_vtep(router, host_ip, host_mac):
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn route type macip json",
        isjson=True
    )

    for rd, routes in output.items():

        # Skip non-dictionary entries
        if not isinstance(routes, dict):
            continue

        for prefix, route_info in routes.items():

            # Skip non-dictionary route entries
            if not isinstance(route_info, dict):
                continue

            # Match the exact Type-2 route
            for path_group in route_info.get("paths", []):

                if not isinstance(path_group, list):
                    continue

                for path in path_group:

                    if not isinstance(path, dict):
                        continue

                    if path.get("ip") != host_ip:
                        continue

                    if path.get("mac") != host_mac:
                        continue

                    if not path.get("valid"):
                        continue

                    if not path.get("bestpath"):
                        continue

                    for nexthop in path.get("nexthops", []):
                        if nexthop.get("used"):
                            return nexthop.get("ip")

    return None


def move_host(
    tgen,
    source,
    target,
    ip,
    mac,
    gateway=None,
    interface="eth0",
):
    """
    Simulate host mobility by transferring an IP/MAC
    identity between two existing Munet hosts.

    The source interface stays down after movement.
    """

    old = tgen.net[source]
    new = tgen.net[target]

    print(f"Moving {ip}: {source} -> {target}")

    # STEP 1: Disable source interface
    old.cmd_raises(
        f"ip link set dev {interface} down"
    )

    # STEP 2: Remove source IPv4 addresses
    old.cmd_raises(
        f"ip -4 addr flush dev {interface}"
    )

    # STEP 3: Disable target interface
    new.cmd_raises(
        f"ip link set dev {interface} down"
    )

    # STEP 4: Remove target IPv4 addresses
    new.cmd_raises(
        f"ip -4 addr flush dev {interface}"
    )

    # STEP 5: Assign moving MAC
    new.cmd_raises(
        f"ip link set dev {interface} address {mac}"
    )

    # STEP 6: Assign moving IP/prefix
    new.cmd_raises(
        f"ip addr add {ip} dev {interface}"
    )

    # STEP 7: Enable target interface
    new.cmd_raises(
        f"ip link set dev {interface} up"
    )

    # STEP 8: Configure gateway
    if gateway:
        new.cmd_raises(
            f"ip route replace default via {gateway} "
            f"dev {interface}"
        )

    print(f"Movement complete: {source} -> {target}")


    # STEP 9: Trigger traffic for the moved host on the new interface
    def trigger_host_learning(host, interface,gateway, method):
        if method == "ping":
            return host.cmd(
                f"ping -c 3 -W 1 {gateway}"
            )

        if method == "arp":
            return host.cmd(
                f"arping -c 3 -I {interface} {gateway}"
            )

        raise ValueError(f"Unknown method: {method}")

    arp = trigger_host_learning(new, interface,gateway, "arp")

    print(arp)

# Diagnostic function to display the mobility state of a host across all leaf routers
def show_mobility_state(tgen, host_ip, host_mac):
    for leaf_name in ["leaf1", "leaf2", "leaf3"]:
        router = tgen.gears[leaf_name]
        node = tgen.net[leaf_name]

        print(f"\n===== {leaf_name} =====")

        print("FDB:")
        print(
            node.cmd(
                f"bridge fdb show | grep -i {host_mac}"
            )
        )

        print("Neighbor table:")
        print(
            node.cmd(
                f"ip neigh show | grep {host_ip}"
            )
        )

        print("EVPN routes:")
        print(
            router.vtysh_cmd(
                "show bgp l2vpn evpn route type macip"
            )
        )