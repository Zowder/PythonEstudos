"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        h1 = self.addHost( 'h1', ip='192.168.100.1/24', mac='00:00:00:00:00:01' )
        h2 = self.addHost( 'h2', ip='192.168.100.2/24', mac='00:00:00:00:00:02')
        s1 = self.addSwitch( 's1' )
        #s2 = self.addSwitch( 's2' )
        #s3 = self.addSwitch( 's3' )
        s4 = self.addSwitch( 's4' )

        # Add links
        self.addLink( h1, s1 )
        self.addLink( h2, s4 )
        #self.addLink( s1, s2 )
        #self.addLink( s2, s4 )
        #self.addLink( s2, s3 )
        self.addLink( s1, s4 )


topos = { 'mytopo': ( lambda: MyTopo() ) }
