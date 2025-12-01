#!/bin/bash

echo "running single switch and 4 hosts topology..."
sudo mn --topo single,4 --switch ovsk --controller remote --mac
sh ovs-vsctl add-port s1 mytap0 -- set Interface mytap0 type=internal
sudo ifconfig mytap0 10.0.0.254/24 up