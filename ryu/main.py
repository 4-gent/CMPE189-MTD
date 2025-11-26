# Initial ryu application

# Ryu controller skeleton for MTD in a SDN.
# Features:
#   - Basic L2 learning switch behavior
#   - Periodic "MTD loop: where you can:
#       -> Shuffle paths (output ports)
#       -> Rotate "virtual service IP" for IP hopping
#   - Simple per-source traffic counters (for future DDoS detection)
#
# Run with:
#   1) chmod +x init_topology.sh
#   2) chmod +x init_mn.sh
#   3) IN SEPARATE TERMINAL (SSH) -> ./init_mn.sh
#   4) ./init_topology.sh

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub
from ryu.lib import mac

class MTDApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # how often to run the mtd mechanism (seconds)
    MTD_PERIOD = 10

    def __init__(self, *args, **kwargs):
        super(MTDApp, self).__init__(*args, **kwargs)

        #dpid -> datapath object (so we can push the flows later)
        self.datapaths = {}

        #l2 learning: {dpid: {mac_addr: port_no}}
        self.mac_to_port = {}

        #simple ip to mac mapping for the hosts (learned from ARP / ipv4)
        self.ip_to_mac = {}

        #per source packet counting (for very simple anomaly / ddos detection)
        #counters[src_ip] = count
        self.ddos_counters = {}

        #config for the protected service
        # example: we pretend our service can be any of these virtual IPs:
        self.service_virtual_ips = [
            "10.0.0.10",
            "10.0.0.20",
            "10.0.0.30",
        ]
        self.active_service_index = 0

        #example tcp port of the protected service
        self.service_tcp_port = 80

        #start the mtd loop (periodic)
        self.mtd_thread = hub.spawn(self._mtd_loop)

    # making helper functions -----------------------------------------------
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        #this jawn is a helper to add a new flow rule
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    match=match,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    match=match,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    instructions=inst)
        datapath.send_msg(mod)

    # event handling (set_ev_cls as a routing decorator) ---------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # called when a switch first connects and installs the table-miss flow entry
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Switch connected: dpid=%s", dpid)
        self.datapaths[dpid] = datapath
        self.mac_to_port.setdefault(dpid, {})

        #table miss flow: send the unmatched packets back to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def state_change_handler(self, ev):
        #track the datapath connections
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapath[datapath.id] = datapath
                self.logger.info("Datapath %s added", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #handle incoming packets (learning switch + hooks for detedction/mtd)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        #parse packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == 0x88cc:
            return #ignore the LLDP
        
        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})

        #learn mac -> port mapping
        self.mac_to_port[dpid][src] = in_port
        
        #learn the ip info if there is any
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4:
            self._update_ip_mapping(ip4, src)
            self._update_ddos_counter(ip4)
        else:
            # also handle arp to learn IP <-> MAC
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                self._update_arp_mapping(arp_pkt, src)

        #basic learning switch forwarding
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        #install the flow to avoid a packet-in on the next one
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        #send packet out
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)

    # need learning helpers ----------------------------------
    def _update_ip_mapping(self, ip4, src_mac):
        # track ip -> mac based on ipv4 header
        if ip4.src not in self.ip_to_mac:
            self.ip_to_mac[ip4.src] = src_mac
            self.logger.info("Learned IPv4 mapping: %s -> %s", ip4.src, src_mac)

    def _update_arp_mapping(self, arp_pkt, src_mac):
        # track ip -> mac based on arp
        if arp_pkt.src_ip not in self.ip_to_mac:
            self.ip_to_mac[arp_pkt.src_ip] = src_mac
            self.logger.info("Learned ARP mapping: %s -> %s", arp_pkt.src_ip, src_mac)

    def _update_ddos_counter(self, ipv4):
        # simple persource counter for future ddos detection
        src_ip = ip4.src
        self.ddos_counters.setdefault(src_ip, 0)
        self.ddos_counters[src_ip] += 1

    # mtd logic (periodic) --------------------------------------
    def _mtd_loop(self):
        #periodic loop to perform mtd actions
        while True:
            hub.sleep(self.MTD_PERIOD)

            self.logger.info("=== MTD Cycle Initiating ===")

            # 1) start anomaly check stub
            self._check_for_ddos_anomaly()

            # 2) ip address hopping (rotate which Virtual IP is 'active')
            self._rotate_service_ip()

            # 3) dynamic path/flow shuffling (change output ports/flows/etc.)
            self._shuffle_paths()

            # 4) reset the counters for the next interval
            self.ddos_counters = {}

            self.logger.info("=== MTD Cycle Done ===")

    def _check_for_ddos_anomaly(self):
        # stub: check counters and log sus sources
        THRESHOLD = 200 #tune if needed

        for src_ip, count in self.ddos_counters.items():
            if count > THRESHOLD:
                self.logger.info(
                    "[ANOMALY] Potential DDoS source %s (count=%d)",
                    src_ip, count
                )
            # TODO:
            #   - Install drop rules for this src_ip
            #   - Use OpenFlow match on ipv4_src=src_ip to block it

    def _rotate_service_ip(self):
        # rotate the active virtaul IPs (ip hopping)

        if not self.service_virtual_ips:
            return
        
        old_ip = self.service_virtual_ips[self.active_service_index]
        self.active_service_index = (self.active_service_index + 1) % len(self.service_virtual_ips)
        new_ip = self.service_virtual_ips[self.active_service_index]

        self.logger.info("IP HOP: %s -> %s", old_ip, new_ip)

        # TODO (core of IP hopping for project):
        #   - Decide how virtual IPs map to physical hosts (e.g., h2, h3, h4).
        #   - Use flow mods with set_field actions to:
        #       * Re-map dst IP from virtual IP to real server IP
        #       * Optionally remap src IP on the way back
        #
        #   For example (for each datapath):
        #       match: ipv4_dst=new_virtual_ip, tcp_dst=service_tcp_port
        #       actions: set_field(real_server_ip as ipv4_dst), output:port_to_server
        #
        #   See: OFPActionSetField in Ryu.

    def _shuffle_paths(self):
        # example stub for dynamic path shuffling

        # For a single switch topo, "path" is basically which port you send to.
        # In multi-switch topologies, you'd install different flow rules
        # in intermediate switches to change the actual route.
        #
        # TODO:
        #   - Decide a mapping (server -> list of candidate ports or paths).
        #   - Randomly choose one each MTD cycle.
        #   - Update the flow rules accordingly.

        self.logger.info("Path shuffle stub called (implement flow changes here)")