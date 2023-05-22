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
url = '/falsereality/{attacker_ip}/{attacker_mac}'
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
        self.read_mapping("mapping.json")
        self.host_macs = [h.mac for h in self.host_vms.values()]
        self.datapath= None
        self.migrator=Migrator()
        self.current_vm = self.migrator.getCurrentHost()
        self.periodic_migrator_daemon = Thread(target=self.periodically_migrate, args=(), daemon=True, name='Background')
        self.periodic_migrator_daemon.start()
        self.mac_to_client = {}
        self.curr_cookie = 1
        self.attacker_ip = None
        self.attacker_mac = None
        self.attacker_cookie = None
        self.ofproto = ofproto_v1_3

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


    def trigger_defense(self, attacker_ip,attacker_mac):
        print(f"Triggering defense for attacker ip {attacker_ip}")
        self.attacker_ip = attacker_ip
        self.attacker_mac = attacker_mac
        self.attacker_cookie = self.curr_cookie
        self.curr_cookie = self.curr_cookie + 1
        self.delete_all_rules(self.datapath)
        self.add_preexisting_client_rules(self.migrator.getCurrentHost())
        
    
    def delete_client_rules(self,datapath,cookie):
        
        print(f"deleting all rules for cookie={cookie}")
        mod = ofpParser.OFPFlowMod(datapath=datapath,
                                        cookie=cookie,
                                        cookie_mask=1,
                                        command=ofproto_v1_3.OFPFC_DELETE,
                                        table_id = ofproto_v1_3.OFPTT_ALL,
                                        out_port=ofproto_v1_3.OFPP_ANY,
                                        out_group=ofproto_v1_3.OFPG_ANY)
        datapath.send_msg(mod)
    
    def delete_all_rules(self,datapath: Datapath):
        mod = ofpParser.OFPFlowMod(datapath=datapath,
                                        cookie_mask=0,
                                        command=ofproto_v1_3.OFPFC_DELETE,
                                        table_id = ofproto_v1_3.OFPTT_ALL,
                                        out_port=ofproto_v1_3.OFPP_ANY,
                                        out_group=ofproto_v1_3.OFPG_ANY)
        datapath.send_msg(mod)

        self.add_base_rules(datapath)


    def periodically_migrate(self,):
        while True:
            sleep(30)
            print("MIGRATING AT.....{}".format(time.ctime()))
            next_vm = self.migrator.chooseNextVM()
            self.add_preexisting_client_rules(next_vm)
            self.add_base_rules(self.datapath)
            self.migrator.migrate(next_vm) 
            print("\n\n\n")
            #sleep(10)

    def add_preexisting_client_rules(self,next_vm):
        for mac, client in self.mac_to_client.items():
            if mac != self.attacker_mac:
                self.add_redirection_rule(next_vm, client)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev: dpset.EventDP):
        if ev.enter:
            print("connected")
        else:
            print("disconnected")
       
    
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
        parser : ofpParser = datapath.ofproto_parser
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
            if mac_src not in self.host_macs:
                if mac_src not in self.mac_to_client:
                    self.mac_to_client[mac_src] = Client(ip_src,in_port,mac_src,None,self.curr_cookie)
                    self.curr_cookie = self.curr_cookie + 1
                
                client = self.mac_to_client[mac_src]


                if self.attacker_ip != None and ip_src == self.attacker_ip:
                    self.add_attacker_rule(datapath,parser,self.attacker_cookie)
                    return

                if ip_dst == ovs_ip:
                    #tcp packets coming from current host
                    current_vm = self.migrator.getCurrentHost()
                    action_modify_headers = self.add_redirection_rule(current_vm,client)
                
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=self.vms[current_vm]["ovs_port"], actions=action_modify_headers, data=msg.data)
                    datapath.send_msg(out)
                    self.add_base_rules(datapath)
    
    def add_redirection_rule(self, host, client):

        if self.migrator.getCurrentHost() != host:
                self.delete_client_rules(self.datapath,client.cookie)
                
        reverse_match = None

        action_modify_headers = [
        ofpParser.OFPActionSetField(eth_src=ovs_mac),
        ofpParser.OFPActionSetField(eth_dst=self.vms[host]["mac"]),
        ofpParser.OFPActionSetField(ipv4_dst=self.vms[host]["local_ip"]),
        ofpParser.OFPActionSetField(ipv4_src=ovs_ip),
        ofpParser.OFPActionOutput(self.vms[host]["ovs_port"])   
        ]
        #,tcp_src=tcp_src
        match = ofpParser.OFPMatch(eth_type=self.dl_type_ipv4, ipv4_dst=ovs_ip,ip_proto=6,tcp_dst=80)
        self.add_flow(self.datapath,200, match, action_modify_headers,client.cookie)

        #,tcp_dst=tcp_src
        reverse_match = ofpParser.OFPMatch(eth_type=self.dl_type_ipv4,ip_proto=6,ipv4_dst=ovs_ip,ipv4_src=self.vms[host]["local_ip"])
        action_modify_headers_reverse = [
            ofpParser.OFPActionSetField(eth_src=ovs_mac),
            ofpParser.OFPActionSetField(ipv4_src=ovs_ip),
            ofpParser.OFPActionSetField(ipv4_dst=client.ip),
            ofpParser.OFPActionSetField(eth_dst=client.mac),
            ofpParser.OFPActionOutput(client.interface)  
        ]
        self.add_flow(self.datapath,200, reverse_match, action_modify_headers_reverse, client.cookie)

        return action_modify_headers
    
    def add_attacker_rule(self,datapath,parser,cookie):
        action_modify_headers = [
                    parser.OFPActionOutput(ofproto_v1_3.OFPP_IN_PORT)
                ]
        match = parser.OFPMatch(eth_type=self.dl_type_ipv4, ipv4_src=self.attacker_ip)
        self.add_flow(self.datapath,200, match, action_modify_headers,cookie)
        
    def add_base_rules(self,datapath):
        #print("adding base rules")
        match = ofpParser.OFPMatch(eth_type=self.dl_type_ipv4,ip_proto=1)
        actions = [ofpParser.OFPActionOutput(ofproto_v1_3.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions)

        match = ofpParser.OFPMatch(eth_type=self.dl_type_arp)
        actions = [ofpParser.OFPActionOutput(ofproto_v1_3.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions)

        match = ofpParser.OFPMatch()
        actions = [ofpParser.OFPActionOutput(ofproto_v1_3.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

        if self.attacker_ip is not None and self.attacker_mac is not None and self.attacker_cookie is not None: 
            self.add_attacker_rule(datapath,ofpParser,self.attacker_cookie)
            
       
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath
        

        self.delete_all_rules(datapath)
       
    
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
        sp = req.path.rsplit('/')
        attacker_ip = sp[2]
        attacker_mac = sp[3]
        switch_app: FalseRealitySwitch = self.false_reality_switch_app
        switch_app.trigger_defense(attacker_ip,attacker_mac)
    
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