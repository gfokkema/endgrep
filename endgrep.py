from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP, TCP
from threading import Thread
from time import sleep

import argparse
import pcapy


class Stream:
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst or \
            self.src == other.dst and self.dst == other.src

    def __hash__(self):
        return hash(self.src) + hash(self.dst)

    def __lt__(self, other):
        return (self.src, self.dst) < (other.src, other.dst)

    def __str__(self):
        return 'from-{}.{}-to-{}.{}'.format(*self.src, *self.dst)

class Dumper:
    def __init__(self, stream, handler):
        self.dumper = handler.dump_open('{}.pcap'.format(str(stream)))
        self.size = 0

    def append(self, hdr, pkt):
        self.dumper.dump(hdr, bytes(pkt))
        self.size = self.size + len(pkt)

    def close(self):
        self.dumper.close()

class Parser:
    streams = {}

    def __init__(self, descriptor, filter=None, limit=None, live=True):
        self.descriptor = descriptor
        self.filter = filter
        self.limit = limit
        self.live = live
        self.quit = False

    def process(self, hdr, pkt):
        if IP not in pkt or TCP not in pkt:
            return
        src = (pkt[IP].src, pkt[TCP].sport)
        dst = (pkt[IP].dst, pkt[TCP].dport)
        stream = Stream(src, dst)
        if stream not in self.streams:
            self.streams[stream] = Dumper(stream, self.handler)
        self.streams[stream].append(hdr, pkt)

    def run(self):
        if self.live:
            self.handler = pcapy.open_live(self.descriptor, -1, True, 100)
        else:
            self.handler = pcapy.open_offline(self.descriptor)
        self.handler.setfilter(self.filter)
        params = (self.descriptor, self.handler.getnet(), self.handler.getmask(), self.handler.datalink())
        print('Listening on {}: net={}, mask={}, linktype={}'.format(*params))
        print('filter: {}'.format(self.filter))
        while not self.quit:
            hdr, raw = self.handler.next()
            if hdr:
                self.process(hdr, Ether(raw))
        for dumper in self.streams.values():
            dumper.close()

    def stop(self):
        self.quit = True

    def summary(self, limit):
        print('-- start --')
        for k, v in sorted(self.streams.items(), key=lambda x: x[1].size, reverse=True)[:limit]:
            print('size: {1}, {0}'.format(k, v.size))
        print('-- end --')


def parse_args():
    parser = argparse.ArgumentParser(description='Capture TCP traffic by endpoint')
    descriptor = parser.add_mutually_exclusive_group(required=True)
    descriptor.add_argument('--interface', choices=pcapy.findalldevs(), metavar='INTERFACE', help='')
    descriptor.add_argument('--file', metavar='FILE', help='')
    parser.add_argument('--filter', default='')
    parser.add_argument('--limit', default=10000, type=int)
    return parser.parse_args()

def main():
    args = parse_args()
    if args.interface:
        parser = Parser(args.interface, args.filter, args.limit, True)
    else:
        parser = Parser(args.file, args.filter, args.limit, False)
    thread = Thread(target=parser.run)
    try:
        thread.start()
        while thread.is_alive():
            sleep(1)
            parser.summary(50)
    except KeyboardInterrupt:
        parser.stop()
        thread.join()

if __name__ == '__main__':
    main()
