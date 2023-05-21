from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3_parser as ofpParser, ofproto_v1_3
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
from datetime import timedelta
from ProactiveMigration import Migrator
from time import sleep
import time
import yaml
from threading import Thread
from machine import Host, Client

false_reality_switch_name = 'ControllerFP'
url = '/falsereality/{attacker_ip}'
ovs_ip = "10.10.1.100"
ovs_mac = "6e:40:e4:a2:0f:41"
class FalseRealitySwitch(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    _CONTEXTS = {'wsgi': WSGIApplication}
    dl_type_arp = 0x0806
    dl_type_ipv4 = 0x0800
    
    def __init__(self, *args, **kwargs):
        super(FalseRealitySwitch, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(FalseRealitySwitchController,{false_reality_switch_name: self})
        with open("./hosts.yaml", 'r') as file:
            yaml_file = yaml.safe_load(file)
            self.yaml_file = yaml_file
        
            self.key_cred = yaml_file["key_cred"]
            self.vm_pool_list = yaml_file["vm_pool"]
            self.vms = yaml_file["vms"]   # VMS
            self.dummy_vm = yaml_file["Dummy_VM"]
            self.vm_ips = [self.vms[key]["local_ip"] for key in self.vms.keys()]

        self.host_vms = {}
        self.clients = {}
        self.read_mapping("mapping.json")
        self.datapath= None
        self.parser = None
        self.migrator=Migrator()
        self.periodic_migrator_daemon = Thread(target=self.periodically_migrate, args=(), daemon=True, name='Background')
        self.periodic_migrator_daemon.start()

    # def add_flow(self, dp: Datapath, match: ofpParser.OFPMatch, actions: list, priority=0, idle_timeout=300,  hard_timeout=0):
    #     ofproto = dp.ofproto
    #     parser: ofpParser = dp.ofproto_parser
    #     mod = parser.OFPFlowMod(datapath=dp, match=match, actions=actions, priority=priority, 
    #           idle_timeout=idle_timeout, hard_timeout=hard_timeout, cookie=0, command=ofproto.OFPFC_ADD)
    #     dp.send_msg(mod)

    def read_mapping(self,filename):
        file = open(filename,"r")
        obj = json.load(file)
        for h in obj['hosts']:
            ip = h['ip']
            interface= h['interface']
            mac = h['mac']
            name = h['name']
            self.host_vms[mac] = (Host(ip, interface ,mac, name))

        for c in obj['clients']:
            ip = c['ip']
            interface = c['interface']
            mac = c['mac']
            name = c['name']
            cookie = c['cookie']
            self.clients[mac] = (Client(ip, interface, mac, name,cookie))

    def add_flow(self, datapath, priority, match, actions,cookie=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser: ofpParser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,cookie=cookie)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,cookie=cookie)
        datapath.send_msg(mod)


    def trigger_migration(self, attacker_ip):
        print(f"Triggering migration for attacker ip {attacker_ip}")
    
    def periodically_migrate(self,):
        while True:
            sleep(30)
            print("MIGRATING AT.....{}".format(time.ctime()))
            for client in self.clients.values():
                self.parser.OFPFlowMod(datapath=self.datapath,cookie=client.cookie,cookie_mask=-1,command=ofproto_v1_3.OFPFC_DELETE)
            self.migrator.migrate()  # 
            self.update_redirection_rules()
            print("\n\n\n")
            #sleep(10)

    #Priority = 5        
    def update_redirection_rules(self,):
        current_vm = self.migrator.getCurrentHost()
        parser = self.parser
       
       
        return
    
    def black_list_ip(self, ip_addr:str):
        current_vm = self.migrator.getCurrentHost()
        parser = self.parser
        match = parser.OFPMatch(eth_type=self.dl_type_ipv4, ipv4_src = str(ip_addr))

        action_modify_headers = [
            parser.OFPActionSetField(eth_dst=self.dummy_vm["mac"]),
            parser.OFPActionSetField(ipv4_dst=self.dummy_vm["local_ip"]),
            parser.OFPActionOutput(self.dummy_vm["ovs_port"])   # send to port directed to dummy_vm
        ]
        self.add_flow(self.datapata, 10, match,action_modify_headers)
        return

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev: dpset.EventDP):
        if ev.enter:
            print("connected")
        else:
            print("disconnected")
       
       
    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in_handler(self, ev):
    #     msg = ev.msg
    #     dp: Datapath = msg.datapath
    #     ofproto: ofproto_v1_0 = dp.ofproto
    #     parser: ofpParser = dp.ofproto_parser
    #     pkt = packet.Packet(msg.data)
    #     eth: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)
 
    #     if eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         return
        
    #     ipv4_pkt:ipv4.ipv4 = pkt.get_protocol(ipv4.ipv4)
    #     tcp_pkt:tcp.tcp = pkt.get_protocol(tcp.tcp)
    #     return
    #     if ipv4_pkt is not None and tcp_pkt is not None:
    #         ip_src = ipv4_pkt.src
    #         ip_dst = ipv4_pkt.dst
    #         mac_src = eth.src
    #         mac_dst = eth.dst
    #         tcp_src = tcp_pkt.src_port
    #         tcp_dst = tcp_pkt.dst_port
    #         dpid = dp.id
    #         self.logger.info("packet in %s %s %s %s", dpid, ip_src, ip_dst, msg.in_port)
    #         actions = []
    #         if ip_src == "72.227.182.113":
    #             actions.append(parser.OFPActionSetNwSrc("192.122.236.113"))
    #             actions.append(parser.OFPActionOutput(1))
    #         elif ip_src == "10.10.1.1":
    #             actions.append(parser.OFPActionSetNwSrc("192.122.236.113"))
    #             actions.append(parser.OFPActionOutput(8))

    #         #actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
    #         #match:ofpParser.OFPMatch = parser.OFPMatch()
    #         #self.add_flow(dp,match,actions,priority=100,idle_timeout=0)

    #         out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,actions=actions, data=msg.data)
    #         dp.send_msg(out)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        dst = eth.dst
        src = eth.src

        ipv4_pkt:ipv4.ipv4 = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt:tcp.tcp = pkt.get_protocol(tcp.tcp)

        if ipv4_pkt is not None and tcp_pkt is not None:
            ip_src = ipv4_pkt.src
            ip_dst = ipv4_pkt.dst
            mac_src = eth.src
            mac_dst = eth.dst
            tcp_src = tcp_pkt.src_port
            tcp_dst = tcp_pkt.dst_port

            if ip_dst == ovs_ip:
                #tcp packets coming from current host
                client = None
                if mac_src in self.clients:
                    client: Client = self.clients[mac_src]
                if client is not None:

                    current_vm = self.migrator.getCurrentHost()
                    action_modify_headers = [
                        parser.OFPActionSetField(eth_dst=self.vms[current_vm]["mac"]),
                        parser.OFPActionSetField(ipv4_dst=self.vms[current_vm]["local_ip"]),
                        parser.OFPActionOutput(self.vms[current_vm]["ovs_port"])   
                    ]
                    
                    match = parser.OFPMatch(eth_type=self.dl_type_ipv4, ipv4_dst=ovs_ip,ip_proto=6,tcp_dst=80,tcp_src=tcp_src)
                    self.add_flow(self.datapata,5, match, action_modify_headers,client.cookie)

                    reverse_match = self.parser.OFPMatch(eth_type=self.dl_type_ipv4,ip_proto=6,ipv4_dst=ip_src,ipv4_src=self.vms[current_vm]["local_ip"],tcp_dst=tcp_src)
                    
                    action_modify_headers_reverse = [
                        parser.OFPActionSetField(eth_src=ovs_mac),
                        parser.OFPActionSetField(ipv4_src=ovs_ip),
                        parser.OFPActionOutput(in_port)   # send to port directed to dummy_vm
                    ]

                    self.add_flow(self.datapata,5, reverse_match, action_modify_headers_reverse,client.cookie)

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                        in_port=self.vms[current_vm]["ovs_port"], actions=action_modify_headers, data=msg.data)
                    datapath.send_msg(out)

       
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.ofproto = ofproto
        self.datapata=datapath
        self.parser: ofpParser = parser
        self.parser.OFPFlowMod(datapath=self.datapath,command=ofproto_v1_3.OFPFC_DELETE)
        match = self.parser.OFPMatch(eth_type=self.dl_type_ipv4,ip_proto=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions)

        match = self.parser.OFPMatch(eth_type=self.dl_type_arp)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions)

        match = self.parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

        #for vm in self.vms:
            

    
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