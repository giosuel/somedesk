#!/usr/bin/env bash
# NAT traversal test with real NATs (needs sudo): two peers on separate private networks, each
# behind its own masquerading NAT router that drops unsolicited inbound traffic, and the server on
# a shared "internet" bridge.
#
#   1. Typical home NAT (ports are kept per socket): the peers must connect directly.
#      Each NAT sits behind an ISP router, so internet paths have realistic hop counts.
#   2. Symmetric NAT (a new random port per destination): hole punching cannot work, so the
#      session must fall back to the relay.
#
# Uses SOMEDESK_TEST_DATABASE_URL like scripts/test.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
ADMIN_URL="${SOMEDESK_TEST_DATABASE_URL:-postgres://sysadmin:devpass@localhost/postgres}"
DB_URL="${ADMIN_URL%/*}/somedesk_nat"
ME="$(id -un)"
WORK="$(mktemp -d)"

# --workspace resolves dependency features like `cargo test --workspace` (scripts/test.sh), so
# everything the tests already compiled is reused instead of being built a second time.
cargo build -q --workspace --bins --examples
PEER="$PWD/target/debug/examples/nat_peer"

cleanup() {
    [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
    for side in a b; do
        for ns in lan nat isp; do sudo ip netns del "sd-$ns-$side" 2>/dev/null || true; done
    done
    sudo ip link del sd-inet 2>/dev/null || true
    sudo iptables -D FORWARD -i sd-inet -o sd-inet -j ACCEPT 2>/dev/null || true
    sudo iptables -D INPUT -i sd-inet -j ACCEPT 2>/dev/null || true
    psql "$ADMIN_URL" -qc "DROP DATABASE IF EXISTS somedesk_nat WITH (FORCE)" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
cleanup_quiet() { cleanup; WORK="$(mktemp -d)"; }

setup_network() { # $1: extra MASQUERADE options
    # internet: bridge sd-inet (10.99.0.0/24) with the server (10.99.0.1) and two ISP routers;
    # each ISP router serves one customer NAT (10.98.N.2), behind which sits one PC (192.168.N.2).
    sudo ip link add sd-inet type bridge
    sudo ip addr add 10.99.0.1/24 dev sd-inet
    sudo ip link set sd-inet up
    # Let bridged traffic through even if the host firewall drops forwarding (e.g. Docker)...
    sudo iptables -I FORWARD -i sd-inet -o sd-inet -j ACCEPT
    # ...and let the "internet" reach the server (only on the test bridge).
    sudo iptables -I INPUT -i sd-inet -j ACCEPT
    local n=1
    for side in a b; do
        sudo ip netns add "sd-isp-$side"
        sudo ip netns add "sd-nat-$side"
        sudo ip netns add "sd-lan-$side"
        # ISP router: one leg on the internet bridge, one towards the customer's NAT.
        sudo ip link add "sd-up-$side" type veth peer name "sd-isp-$side-i"
        sudo ip link set "sd-up-$side" master sd-inet up
        sudo ip link set "sd-isp-$side-i" netns "sd-isp-$side"
        sudo ip link add "sd-isp-$side-c" type veth peer name "sd-wan-$side"
        sudo ip link set "sd-isp-$side-c" netns "sd-isp-$side"
        sudo ip link set "sd-wan-$side" netns "sd-nat-$side"
        # Customer NAT and its PC.
        sudo ip link add "sd-gw-$side" type veth peer name "sd-pc-$side"
        sudo ip link set "sd-gw-$side" netns "sd-nat-$side"
        sudo ip link set "sd-pc-$side" netns "sd-lan-$side"
        sudo ip netns exec "sd-isp-$side" sh -e -c "
            ip link set lo up
            ip addr add 10.99.0.$((n + 1))/24 dev sd-isp-$side-i; ip link set sd-isp-$side-i up
            ip addr add 10.98.$n.1/24 dev sd-isp-$side-c; ip link set sd-isp-$side-c up
            sysctl -qw net.ipv4.ip_forward=1"
        sudo ip netns exec "sd-nat-$side" sh -e -c "
            ip link set lo up
            ip addr add 10.98.$n.2/24 dev sd-wan-$side; ip link set sd-wan-$side up
            ip route add default via 10.98.$n.1
            ip addr add 192.168.$n.1/24 dev sd-gw-$side; ip link set sd-gw-$side up
            sysctl -qw net.ipv4.ip_forward=1
            iptables -t nat -A POSTROUTING -o sd-wan-$side -j MASQUERADE $1
            iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            iptables -A FORWARD -i sd-gw-$side -j ACCEPT
            iptables -P FORWARD DROP"
        sudo ip netns exec "sd-lan-$side" sh -e -c "
            ip link set lo up
            ip addr add 192.168.$n.2/24 dev sd-pc-$side; ip link set sd-pc-$side up
            ip route add default via 192.168.$n.1"
        # The server and the other ISP find this customer network through its ISP router.
        sudo ip route add "10.98.$n.0/24" via "10.99.0.$((n + 1))"
        n=$((n + 1))
    done
    sudo ip netns exec sd-isp-a ip route add 10.98.2.0/24 via 10.99.0.3
    sudo ip netns exec sd-isp-b ip route add 10.98.1.0/24 via 10.99.0.2
}

run_case() { # $1: name, $2: MASQUERADE options, $3: expected route
    echo "== $1"
    setup_network "$2"
    psql "$ADMIN_URL" -qc "DROP DATABASE IF EXISTS somedesk_nat WITH (FORCE)" -c "CREATE DATABASE somedesk_nat" >/dev/null
    target/debug/somedesk-server --listen 10.99.0.1:21116 --database-url "$DB_URL" --data-dir "$WORK/server" \
        >"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1
    sudo ip netns exec sd-lan-a runuser -u "$ME" -- "$PEER" 10.99.0.1 bob host "$WORK/id" >"$WORK/host.out" 2>"$WORK/host.log" &
    local host_pid=$!
    sudo ip netns exec sd-lan-b runuser -u "$ME" -- "$PEER" 10.99.0.1 alice viewer "$WORK/id" >"$WORK/viewer.out" 2>"$WORK/viewer.log" || true
    wait "$host_pid" || true
    cat "$WORK/viewer.out" "$WORK/host.out"
    grep -h "candidates" "$WORK/host.log" || true
    local ok=1
    grep -q "viewer route=$3 ack=ack" "$WORK/viewer.out" || ok=0
    grep -q "host route=$3 received=hello through the NAT" "$WORK/host.out" || ok=0
    if [ "$ok" = 0 ]; then
        echo "--- viewer log"; tail -20 "$WORK/viewer.log"
        echo "--- host log"; tail -20 "$WORK/host.log"
        echo "--- server log"; tail -20 "$WORK/server.log"
    fi
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    cleanup_quiet
    if [ "$ok" = 1 ]; then echo "PASS: $1 used the $3 path"; else echo "FAIL: $1 expected the $3 path"; exit 1; fi
}

run_case "home NAT on both sides" "" Direct
run_case "symmetric NAT on both sides" "--random-fully" Relay
