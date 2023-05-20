from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_0_parser as ofpParser
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types, ipv4, icmp, arp, tcp
from ryu.controller import dpset
from ryu.controller.controller import Datapath
from ryu.lib import hub
from MonitorFlagEvent import MonitorFlagEvent, MonitorFlagEventRequest
import pyshark
from machine import Host, Client
import json

suspicious_hosts = {}
host_vms =  { 1: Host("10.10.1.1","eth1","02:86:76:de:c7:db","vm1",True),
              2: Host("10.10.1.2","eth2","02:09:9e:7d:f1:c4","vm2"),
              3: Host("10.10.1.3","eth3","02:0f:9d:0c:4f:27","vm3"),
              4: Host("10.10.1.4","eth4","02:83:3d:8f:e8:da","dummyVM")
            }

clients = { 1: Client("10.10.1.6","eth6","02:4f:26:ff:5e:16","client"),
            2: Client("10.10.1.7","eth7","02:d6:81:16:6e:96","client2"),
            3: Client("10.10.1.5","eth5","02:e0:67:27:93:60","attacker")
           }



class Monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    dl_type_arp = 0x0806
    dl_type_ipv4 = 0x0800

    def __init__(self, *args, **kwargs):
        super(Monitor, self).__init__(*args, **kwargs)
        self.host_vms = []
        self.clients = []
        self.read_mapping("mapping.json")

        self.threads = []

        for i, host in host_vms.items():
            host.capture = pyshark.RemoteCapture(host.ip,host.interface)
            self.threads.append(hub.spawn(host.monitor))


        for i, client in clients.items():
            client.capture = pyshark.RemoteCapture(host.ip,host.interface)
            self.threads.append(hub.spawn(client.monitor))

        #self.monitor_thread = hub.spawn(self._monitor)

    def _request_stats(self, datapath: Datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto: ofproto_v1_0 = datapath.ofproto
        parser: ofpParser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        return
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            #for dp in self.datapaths.values():
                #self._request_stats(dp)
            hub.sleep(1)
            event = MonitorFlagEvent()
            request = MonitorFlagEvent()
            eth0= pyshark.LiveCapture("eth0")
            eth1= pyshark.LiveCapture("eth1")
            print(eth0)
            print(eth1)
            #self.send_event("ControllerFP",event)
            


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        return
        body = ev.msg.body

        self.logger.info('datapath         '
                        'in-port  eth-dst           '
                        'out-port packets  bytes')
        self.logger.info('---------------- '
                        '-------- ----------------- '
                        '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                        key=lambda flow: (flow.match['in_port'],
                                            flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                            ev.msg.datapath.id,
                            stat.match['in_port'], stat.match['eth_dst'],
                            stat.instructions[0].actions[0].port,
                            stat.packet_count, stat.byte_count)
            
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        return
        body = ev.msg.body

        self.logger.info('datapath         port     '
                        'rx-pkts  rx-bytes rx-error '
                        'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                        '-------- -------- -------- '
                        '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                            ev.msg.datapath.id, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors)
    
    def read_mapping(self,filename):
        file = open(filename,"r")
        obj = json.load(file)
        for h in obj['hosts']:
            ip = h['ip']
            interface = h['interface']
            mac = h['mac']
            name = h['name']
            self.host_vms.append(Host(ip,interface,mac,name))

        for c in obj['clients']:
            ip = c['ip']
            interface = c['interface']
            mac = c['mac']
            name = c['name']
            self.clients.append(Client(ip,interface,mac,name))
