#!/bin/bash

echo "running single switch and 4 hosts topology..."

sudo mn --topo single,4 \
    --mac \
    --switch ovsk,protocol=OpenFlow13 \
    --controller=remote,ip=127.0.0.1,port=6633