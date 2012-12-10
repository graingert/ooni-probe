from twisted.python import usage
from twisted.internet import defer

from ooni.templates import scapyt

from scapy.all import TCP, IP

from ooni.utils import log

class UsageOptions(usage.Options):
    optParameters = [
                    ['timeout', 't', 5,
                        'The timeout after which to give up checking the site']
                    ]

class NetworkLatencyTest(scapyt.BaseScapyTest):
    name = "Network Latency test"
    version = "0.0.1"

    inputFile = ['f', 'file', None,
            'A file containing IP port pairs to compute latency towards (separated by :)']

    def setUp(self):
        self.dstIP, self.dstPort = self.input.split(':')

    def test_tcp_syn(self):
        packet = IP(dst=self.dstIP)/TCP(dport=self.dstPort, flags='S')
        recv = self.sr1(packet)
        self.report['latency'] = recv.time - packet.time

