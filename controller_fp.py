from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_0_parser as ofpParser
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types, ipv4, icmp, arp, tcp
from ryu.controller import dpset
from ryu.controller.controller import Datapath
from MonitorFlagEvent import MonitorFlagEvent
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
from ryu.lib import dpid as dpid_lib
import json 

false_reality_switch_name = 'ControllerFP'
url = '/falsereality/{attacker_ip}'

class FalseRealitySwitch(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    
    _CONTEXTS = {'wsgi': WSGIApplication}
    dl_type_arp = 0x0806
    dl_type_ipv4 = 0x0800
    
    def __init__(self, *args, **kwargs):
        super(FalseRealitySwitch, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(FalseRealitySwitchController,{false_reality_switch_name: self})

    def add_flow(self, dp: Datapath, match: ofpParser.OFPMatch, actions: list, priority=0, idle_timeout=300,  hard_timeout=0):
        ofproto = dp.ofproto
        parser: ofpParser = dp.ofproto_parser
        mod = parser.OFPFlowMod(datapath=dp, match=match, actions=actions, priority=priority, 
              idle_timeout=idle_timeout, hard_timeout=hard_timeout, cookie=0, command=ofproto.OFPFC_ADD)
        dp.send_msg(mod)

    def trigger_migration(self, attacker_ip):
        print(f"Triggering migration for attacker ip {attacker_ip}")

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev: dpset.EventDP):
        if ev.enter:
            print("connected")
        else:
            print("disconnected")
        dp: Datapath = ev.dp
        parser : ofpParser = dp.ofproto_parser
        ofproto: ofproto_v1_0 = dp.ofproto
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        #match:ofpParser.OFPMatch = parser.OFPMatch(dl_type=self.dl_type_arp)
        match:ofpParser.OFPMatch = parser.OFPMatch()
        self.add_flow(dp,match,actions,priority=100,idle_timeout=0)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp: Datapath = msg.datapath
        ofproto: ofproto_v1_0 = dp.ofproto
        parser: ofpParser = dp.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)
 
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        ipv4_pkt:ipv4.ipv4 = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt:tcp.tcp = pkt.get_protocol(tcp.tcp)
        return
        if ipv4_pkt is not None and tcp_pkt is not None:
            ip_src = ipv4_pkt.src
            ip_dst = ipv4_pkt.dst
            mac_src = eth.src
            mac_dst = eth.dst
            tcp_src = tcp_pkt.src_port
            tcp_dst = tcp_pkt.dst_port
            dpid = dp.id
            self.logger.info("packet in %s %s %s %s", dpid, ip_src, ip_dst, msg.in_port)
            actions = []
            if ip_src == "72.227.182.113":
                actions.append(parser.OFPActionSetNwSrc("192.122.236.113"))
                actions.append(parser.OFPActionOutput(1))
            elif ip_src == "10.10.1.1":
                actions.append(parser.OFPActionSetNwSrc("192.122.236.113"))
                actions.append(parser.OFPActionOutput(8))

            #actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            #match:ofpParser.OFPMatch = parser.OFPMatch()
            #self.add_flow(dp,match,actions,priority=100,idle_timeout=0)

            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,actions=actions, data=msg.data)
            dp.send_msg(out)
        
     
    @set_ev_cls(MonitorFlagEvent)
    def monitor_flag_handler(self, ev):
        print("received event")


class FalseRealitySwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(FalseRealitySwitchController, self).__init__(req, link, data, **config)
        self.false_reality_switch_app = data[false_reality_switch_name]
#,requirements={'attacker_ip': str}
    @route('falsereality', url, methods=['GET'])
    def f(self, req, **kwargs):

        attacker_ip = req.path.rsplit('/')[2]

        switch_app: FalseRealitySwitch = self.false_reality_switch_app
        switch_app.trigger_migration(attacker_ip)
    
        return Response()

    # @route('simpleswitch', url, methods=['PUT'],requirements={'dpid': dpid_lib.DPID_PATTERN})
    # def put_mac_table(self, req, **kwargs):

    #     simple_switch = self.simple_switch_app
    #     dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
    #     try:
    #         new_entry = req.json if req.body else {}
    #     except ValueError:
    #         raise Response(status=400)

    #     if dpid not in simple_switch.mac_to_port:
    #         return Response(status=404)

    #     try:
    #         mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
    #         body = json.dumps(mac_table)
    #         return Response(content_type='application/json', body=body)
    #     except Exception as e:
    #         return Response(status=500)