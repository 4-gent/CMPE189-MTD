# main.py
# Hardened MTD Ryu controller
# Features:
#   ✔ L2 learning switch
#   ✔ DDoS detection + automatic blocking
#   ✔ IP Address Hopping (virtual → real IP translation)
#   ✔ Dynamic output port path shuffling (only for real server)
#   ✔ Early per-source blocking + packet-in rate limiting
#   ✔ Basic SYN-flood detection

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp
from ryu.lib import hub
import random


class MTDApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    MTD_PERIOD = 10

    def __init__(self, *args, **kwargs):
        super(MTDApp, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.ddos_counters = {}

        # rotating virtual service IPs
        self.service_virtual_ips = ["10.0.0.10", "10.0.0.20", "10.0.0.30"]
        self.active_service_index = 0

        # REAL backend server
        self.real_server_ip = "10.0.0.2"     # h2
        self.real_server_port = 2            # switch port for h2

        # thresholds
        self.DDOS_THRESHOLD = 200            # slower, for background check
        self.EARLY_BLOCK_THRESHOLD = 50      # quick block inside packet_in
        self.SYN_THRESHOLD = 200             # SYN-flood threshold

        # rate limiting for packet-in at the controller (per src_ip)
        self.last_packet_times = {}          # src_ip -> last_seen_time
        self.packet_min_interval = 0.001     # seconds; ~1000 pkt/s per IP

        # SYN counters
        self.syn_counts = {}                 # src_ip -> SYN count

        # start the MTD loop
        self.mtd_thread = hub.spawn(self._mtd_loop)

    # ----------------------------------------------------------------------
    # Add Flow Helper
    # ----------------------------------------------------------------------
    def add_flow(self, dp, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            instructions=inst
        )
        dp.send_msg(mod)

    # ----------------------------------------------------------------------
    # Switch Connect / Table-Miss Rule
    # ----------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        dpid = dp.id
        self.datapaths[dpid] = dp
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("Switch connected: dpid=%s", dpid)

        # table-miss: send small slice to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 128)]
        self.add_flow(dp, 0, match, actions)

    # ----------------------------------------------------------------------
    # Track Datapath State
    # ----------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def state_change_handler(self, ev):
        dp = ev.datapath
        if dp.id not in self.datapaths:
            self.datapaths[dp.id] = dp
            self.logger.info("Datapath %s added", dp.id)

    # ----------------------------------------------------------------------
    # PACKET IN HANDLER
    # ----------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        dpid = dp.id

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt.ethertype == 0x88cc:  # LLDP ignore
            return

        src = eth_pkt.src
        dst = eth_pkt.dst

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip4 = pkt.get_protocol(ipv4.ipv4)
        tcp_seg = pkt.get_protocol(tcp.tcp)
        src_ip = None

        # -------------------------
        # Controller-side rate limit
        # -------------------------
        if ip4:
            src_ip = ip4.src
            now = hub.time()
            last = self.last_packet_times.get(src_ip)

            if last is not None and (now - last) < self.packet_min_interval:
                # drop this packet-in silently (too fast from this src_ip)
                return

            self.last_packet_times[src_ip] = now

            # if we've already seen a lot from this IP in this interval,
            # install an early drop rule and stop processing
            if self.ddos_counters.get(src_ip, 0) > self.EARLY_BLOCK_THRESHOLD:
                self.logger.info("[EARLY BLOCK] High PPS from %s", src_ip)
                match = parser.OFPMatch(ipv4_src=src_ip, eth_type=0x0800)
                self.add_flow(dp, 200, match, [], hard_timeout=60)
                return

        # ------------------------------------
        # Learn IPv4 / ARP and update counters
        # ------------------------------------
        if ip4:
            if src_ip not in self.ip_to_mac:
                self.ip_to_mac[src_ip] = src
                self.logger.info("Learned IP → MAC: %s -> %s", src_ip, src)

            self.ddos_counters.setdefault(src_ip, 0)
            self.ddos_counters[src_ip] += 1

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            if arp_pkt.src_ip not in self.ip_to_mac:
                self.ip_to_mac[arp_pkt.src_ip] = src

        # ------------------------------------
        # SYN-flood detection (hping3-style)
        # ------------------------------------
        if ip4 and tcp_seg:
            # SYN without ACK = likely connection attempt
            if (tcp_seg.bits & 0x02) and not (tcp_seg.bits & 0x10):
                self.syn_counts.setdefault(src_ip, 0)
                self.syn_counts[src_ip] += 1

                if self.syn_counts[src_ip] > self.SYN_THRESHOLD:
                    self.logger.info("[SYN BLOCK] Excessive SYNs from %s",
                                     src_ip)
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=6,
                        ipv4_src=src_ip
                    )
                    self.add_flow(dp, 220, match, [], hard_timeout=120)
                    return

        # ------------------------------------
        # Basic learning-switch forwarding
        # ------------------------------------
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst,
                                    eth_src=src)
            self.add_flow(dp, 1, match, actions, idle_timeout=10)

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        dp.send_msg(out)

    # ----------------------------------------------------------------------
    # MTD LOOP
    # ----------------------------------------------------------------------
    def _mtd_loop(self):
        while True:
            hub.sleep(self.MTD_PERIOD)
            self.logger.info("=== MTD Cycle Starting ===")

            self._check_for_ddos_anomaly()
            self._rotate_service_ip()
            self._shuffle_paths()

            self.ddos_counters = {}
            self.syn_counts = {}

            self.logger.info("=== MTD Cycle Complete ===")

    # ----------------------------------------------------------------------
    # 1. DDoS Detection + Automatic Blocking (slower, periodic)
    # ----------------------------------------------------------------------
    def _check_for_ddos_anomaly(self):
        for src_ip, count in self.ddos_counters.items():
            if count > self.DDOS_THRESHOLD:
                self.logger.info("[BLOCK] DDoS detected from %s", src_ip)

                for dp in self.datapaths.values():
                    parser = dp.ofproto_parser
                    match = parser.OFPMatch(ipv4_src=src_ip, eth_type=0x0800)
                    self.add_flow(dp, 100, match, [], hard_timeout=60)

    # ----------------------------------------------------------------------
    # 2. IP Address Hopping
    # ----------------------------------------------------------------------
    def _rotate_service_ip(self):
        old_ip = self.service_virtual_ips[self.active_service_index]
        self.active_service_index = (
            (self.active_service_index + 1) % len(self.service_virtual_ips)
        )
        new_ip = self.service_virtual_ips[self.active_service_index]

        self.logger.info("IP HOP: %s → %s", old_ip, new_ip)

        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            ofproto = dp.ofproto

            # delete old mapping rule
            match_old = parser.OFPMatch(ipv4_dst=old_ip, eth_type=0x0800)
            mod = parser.OFPFlowMod(
                datapath=dp,
                match=match_old,
                command=ofproto.OFPFC_DELETE
            )
            dp.send_msg(mod)

            # install new mapping rule
            match = parser.OFPMatch(ipv4_dst=new_ip, eth_type=0x0800)
            actions = [
                parser.OFPActionSetField(ipv4_dst=self.real_server_ip),
                parser.OFPActionOutput(self.real_server_port)
            ]
            self.add_flow(dp, 50, match, actions, idle_timeout=30)

    # ----------------------------------------------------------------------
    # 3. Path Shuffling (only for real server traffic)
    # ----------------------------------------------------------------------
    def _shuffle_paths(self):
        ports = [1, 2, 3, 4]
        random.shuffle(ports)
        chosen_port = ports[0]

        self.logger.info("New randomized output port for server: %s",
                         chosen_port)

        for dp in self.datapaths.values():
            parser = dp.ofproto_parser

            # only match traffic headed to the REAL server IP
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_dst=self.real_server_ip
            )
            actions = [parser.OFPActionOutput(chosen_port)]

            # short idle_timeout so stale rules get cleaned up
            self.add_flow(dp, 5, match, actions, idle_timeout=10)