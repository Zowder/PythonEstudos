# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import struct
import json
import random
import ryu.utils
from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import mac_to_port
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.controller import dpset
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.topology import event, switches
import networkx as nx
from pprint import pprint
LOG = logging.getLogger('ryu.app.simple_switch_13')
class TopologyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyController, self).__init__(req, link, data, **config)
        self.flow_api = data['flow_api']

    @route('topology', '/get',
           methods=['GET'])
    def get_switch(self, req, **kwargs):
        return self._return_path(req, **kwargs)
    def _pprint(self, req, **kwargs):
        pprint(dir(req))
    def _return_path(self, req, **kwargs):
        body = json.dumps({"Teste": "Testando"})
        resp = Response(content_type='application/json', body=body)
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(TopologyController, {'flow_api': self})
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i=0
        self.dps = {}
        self.filter_data = {
            'switch_src': 1,
            'switch_dst': 4,
            'host_src': '192.168.100.1',
            'host_dst': '192.168.100.2',
            'in_port_src': '1',
            'in_port_dst': '1',
            'out_port_src': '2',
            'out_port_dst': '2'

        }
        #self.intent= {'sw_src': 's1', 'sw_dst': 's4', }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #dp2 = self.get_datapath(0000000000000001)
        #pprint(dir(dp2))
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

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
            #pprint(in_port)
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
            #pprint(eth_type)
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                # ignore lldp packet
                return
            dst = eth.dst
            src = eth.src
            #pprint(dst)
            #pprint(src)
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if src not in self.net:
                self.net.add_node(src)
                self.net.add_edge(dpid,src,{'port':in_port})
                self.net.add_edge(src,dpid)
            if dst in self.mac_to_port[dpid]:
                path=nx.shortest_path(self.net,src,dst)
                #self.create_intent(body)
                next=path[path.index(dpid)+1]
                out_port=self.net[dpid][next]['port']
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def create_intent(self, filter_data):
        sw_src = filter_data['switch_src']
        sw_dst = filter_data['switch_dst']
        src = filter_data['host_src']
        dst = filter_data['host_dst']
        in_port_src = filter_data['in_port_src']
        in_port_dst = filter_data['in_port_dst']
        out_port_src = filter_data['out_port_src']
        out_port_dst = filter_data['out_port_dst']

        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(sw_src,src,{'port':in_port_src})
            self.net.add_edge(src,sw_src)
            #print self.net.edges()
        if dst not in self.net:
            self.net.add_node(dst)
            self.net.add_edge(sw_dst,dst,{'port':in_port_dst})
            self.net.add_edge(dst,sw_dst)
            path=nx.shortest_path(self.net,src,dst)
        else:
            path=nx.shortest_path(self.net,src,dst)
        for dpid in path[1:-1]:
            #pprint(dpid)
            datapath = self.get_datapath(dpid)
            #pprint(datapath.ports)
            ofproto = datapath.ofproto
            ofproto_parser = datapath.ofproto_parser
            next=path[path.index(dpid)+1]
            previous=path[path.index(dpid)-1]
            out_port= int(self.net[dpid][next]['port'])
            actions = [ofproto_parser.OFPActionOutput(out_port)]
            in_port = int(self.net[dpid][previous]['port'])

            match = ofproto_parser.OFPMatch(in_port=in_port, ipv4_dst=dst, eth_type=2048)

            match1 = ofproto_parser.OFPMatch(in_port=in_port, ipv4_dst=src, eth_type=2048)
            actions1 = [ofproto_parser.OFPActionOutput(izzz)]

            #self.add_flow(datapath, 1, match, actions, 0)

    def get_datapath(self, dpid):
        if dpid not in self.dps:
            datapath = get_switch(self.topology_api_app, dpid)[0]
            dp = datapath.dp
            self.dps[dpid] = dp
            return dp

        return self.dps[dpid]

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        #datapath = self.get_datapath(1)
        #pprint(datapath.id)
        #print "**********List of switches"
        #for switch in switch_list:
        #self.ls(switch)
        #print switch
        #self.nodes[self.no_of_nodes] = switch
        #self.no_of_nodes += 1

        links_list = get_link(self.topology_api_app, None)
        #print links_list
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        print links
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        print link
        self.net.add_edges_from(links)
        self.create_intent(self.filter_data)
        #port = self.net[1][2]['port']
        #print port
        ##print "**********List of links"
        #port = self.net.get_edge_data()
        #pprint(port)
        #self.create_intent('9a:24:bb:e1:e0:7d','5a:e5:e6:a0:04:3d')
