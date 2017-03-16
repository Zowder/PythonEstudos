sudo ovs-ofctl add-flow s1 "dl_type=0x0800,idle_timeout=1800,icmp,priority=65535,nw_src=10.0.0.1,nw_dst=10.0.0.2,in_port=1,actions=output:2"
sudo ovs-ofctl add-flow s1 "dl_type=0x0800,idle_timeout=1800,icmp,priority=65535,nw_src=10.0.0.2,nw_dst=10.0.0.1,in_port=2,actions=output:1"

#sudo ovs-ofctl add-flow s4 "dl_type=0x0800,idle_timeout=1800,icmp,priority=65535,nw_src=192.168.100.1,nw_dst=192.168.100.2,in_port=2,actions=output:1"
#sudo ovs-ofctl add-flow s4 "dl_type=0x0800,idle_timeout=1800,icmp,priority=65535,nw_src=192.168.100.2,nw_dst=192.168.100.1,in_port=1,actions=output:2"
