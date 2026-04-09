from mininet.topo import Topo

class SecurityTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')

        h1 = self.addHost('h1', ip='10.0.0.1/24')  # normal host
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # victim/server
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # attacker
        h4 = self.addHost('h4', ip='10.0.0.4/24)

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

topos = {'securitytopo': (lambda: SecurityTopo())}
