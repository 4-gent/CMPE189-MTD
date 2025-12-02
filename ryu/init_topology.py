#!/usr/bin/python3

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import SingleSwitchTopo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import os

def run():
    setLogLevel('info')

    info("\n*** Starting MTD topology with tap interface\n")

    # -----------------------------
    # Create Mininet topology
    # -----------------------------
    topo = SingleSwitchTopo(k=4)
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
        autoSetMacs=True
    )

    info("*** Starting network\n")
    net.start()

    # -----------------------------
    # CLEAN STALE TAP INTERFACES
    # -----------------------------
    info("*** Cleaning stale tap0 (if exists)\n")
    os.system("ovs-vsctl --if-exists del-port s1 tap0")
    os.system("ip link del tap0 2>/dev/null")

    # -----------------------------
    # CREATE TAP INTERFACE
    # -----------------------------
    info("*** Creating tap0\n")
    os.system("ip tuntap add tap0 mode tap user mininet")
    os.system("ip link set tap0 up")

    # -----------------------------
    # ATTACH TAP0 TO THE SWITCH
    # -----------------------------
    info("*** Attaching tap0 to s1\n")
    os.system("ovs-vsctl add-port s1 tap0 -- set Interface tap0 type=internal")

    # -----------------------------
    # ASSIGN IP TO TAP0
    # -----------------------------
    info("*** Assigning IP 10.0.0.254/24 to tap0\n")
    os.system("ip addr add 10.0.0.254/24 dev tap0")

    # -----------------------------
    # READY - DROP TO MININET CLI
    # -----------------------------
    info("*** Setup complete. Opening Mininet CLI...\n")
    CLI(net)

    # -----------------------------
    # CLEANUP AFTER EXIT
    # -----------------------------
    info("*** Stopping Mininet\n")
    net.stop()

    info("*** Cleaning tap0\n")
    os.system("ovs-vsctl --if-exists del-port s1 tap0")
    os.system("ip link del tap0 2>/dev/null")

    info("*** Done.\n")

if __name__ == "__main__":
    run()