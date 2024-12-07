import os
import sys
import re
import json
import psycopg2
from dotenv import load_dotenv

class filterlog():

    conn = None

    cursor = None

    def __init__(self):
        load_dotenv('.heimdallr')

        # logging.basicConfig(level=logging.DEBUG)
        # logger = logging.getLogger('digest-filterlog')

        db_settings = {
            'dbname': os.getenv('DATABASE_NAME'),
            'user':  os.getenv('DATABASE_USER'),
            'password': os.getenv('DATABASE_PASSWORD'),
            'host': os.getenv('DATABASE_HOST'),
            'port': os.getenv('DATABASE_PORT'),
        }

        self.conn = psycopg2.connect(**db_settings)

        #self.cursor = self.conn.cursor()

    def digest_empty(self, rec, rest):

        if len(rest) != 1 and rest[0] != '':
            raise Exception("Unexpected rest of record: {0}".format(json.dumps(rest)))

        rest.pop(0)

    def digest_datalength(self, rec, rest):
        '''
        Verify that we have only one item remaining, and that it is a "datalength=X"
        value, and if so, stash the value.
        '''
        rest_dict = {}
        if len(rest) != 1 and rest[0][:11] != 'datalength=':
            raise Exception("Unexpected rest of record: {0}".format(json.dumps(rest)))

        x = rest.pop(0)
        rest_dict['datalength'] = x[11:]
        return rest_dict

    def digest_tcpudp(self, rec, rest):

        rest_dict = {}
        rec['sport'] = rest.pop(0)
        rec['dport'] = rest.pop(0)
        rec['datalen'] = rest.pop(0)
        return rest_dict

    def digest_tcp(self, rec, rest):

        rest_dict = self.digest_tcpudp(rec, rest)
        rest_dict['tcp_flags'] = rest.pop(0)
        rest_dict['seq'] = rest.pop(0)
        rest_dict['ack'] = rest.pop(0)
        rest_dict['window'] = rest.pop(0)
        rest_dict['urg'] = rest.pop(0)
        rest_dict['options'] = rest.pop(0)
        return rest_dict

    def digest_udp(self, rec, rest):

        rest_dict = self.digest_tcpudp(rec, rest)
        return rest_dict

    def digest_igmp(self, rec, rest):

        if len(rest) != 1:
            raise Exception("Unexpected IGMP record data: {0}".format(json.dumps(rest)))

    def digest_icmp(self, rec, rest):

        rec['icmp_type'] = rest.pop(0)

    def digest_icmp_echo_reply(self, rec, rest):

        rec['icmp_id'] = rest.pop(0)
        rec['icmp_seq'] = rest.pop(0)

    def digest_icmp_proto_unreachable(self, rec, rest):

        rec['icmp_dest_ip'] = rest.pop(0)
        rec['icmp_proto_id'] = rest.pop(0)

    def digest_icmp_port_unreachable(self, rec, rest):

        rec['icmp_dest_ip'] = rest.pop(0)
        rec['icmp_proto_id'] = rest.pop(0)
        rec['icmp_port'] = rest.pop(0)

    def digest_icmp_unreachable(self, rec, rest):

        rec['icmp_description'] = rest.pop(0)

    def digest_icmp_need_frag(self, rec, rest):

        rec['icmp_dest_id'] = rest.pop(0)
        rec['icmp_mtu'] = rest.pop(0)

    def digest_icmp_tstamp(self, rec, rest):

        rec['icmp_id'] = rest.pop(0)
        rec['icmp_seq'] = rest.pop(0)

    def digest_icmp_tstamp_reply(self, rec, rest):

        rec['icmp_id'] = rest.pop(0)
        rec['icmp_seq'] = rest.pop(0)
        rec['icmp_otime'] = rest.pop(0)
        rec['icmp_rtime'] = rest.pop(0)
        rec['icmp_ttime'] = rest.pop(0)

    def icmp_default(self, rec, rest):

        rec['icmp_description'] = rest.pop(0)

    def digest_ipv4(self, rec, rest):

        rec['tos'] = rest.pop(0)
        rec['ecn'] = rest.pop(0)
        rec['ttl'] = rest.pop(0)
        rec['id'] = rest.pop(0)
        rec['offset'] = rest.pop(0)
        rec['flags'] = rest.pop(0)
        rec['proto_id'] = rest.pop(0)
        rec['protocol'] = rest.pop(0)
        rec['length'] = rest.pop(0)
        rec['source_ip'] = rest.pop(0)
        rec['dest_ip'] = rest.pop(0)

        if rec['protocol'] == 'tcp':
            rest_dict = self.digest_tcp(rec, rest)
        elif rec['protocol'] == 'udp':
            rest_dict = self.digest_udp(rec, rest)
        elif rec['protocol'] == 'gre':
            rest_dict = self.digest_datalength(rec,rest)
        elif rec['protocol'] == 'ipv6':
            rest_dict = self.digest_datalength(rec,rest)
        elif rec['protocol'] == 'igmp':
            rest_dict = self.digest_datalength(rec, rest)
        elif rec['protocol'] == 'icmp':
            rest_dict = self.digest_datalength(rec, rest)
        else:
            raise Exception('Unknown IPv4 protocol: {0}'.format(rec['protocol']))

        try:
            rest_json = json.dumps(rest_dict)
            if self.conn is not None:
                with self.conn.cursor() as curs:
                    curs.execute('''
                INSERT INTO filterlog (
                    timestamp, 
                    hostname, 
                    rule_num, 
                    sub_rule,
                    anchor,
                    tracker,
                    interface,
                    reason,
                    action,
                    direction,
                    ip_version,
                    tos,
                    ecn,
                    ttl,
                    pkt_id,
                    pkt_offset,
                    flags,
                    proto_id,
                    protocol,
                    pkt_length,
                    source_ip,
                    dest_ip,
                    rest                    
                ) VALUES (
                    %(timestamp)s, 
                    %(hostname)s, 
                    %(rule_num)s, 
                    %(sub_rule)s,
                    %(anchor)s,
                    %(tracker)s,
                    %(interface)s,
                    %(reason)s,
                    %(action)s,
                    %(direction)s,
                    %(ip_version)s,
                    %(tos)s,
                    %(ecn)s,
                    %(ttl)s,
                    %(pkt_id)s,
                    %(offset)s,
                    %(flags)s,
                    %(proto_id)s,
                    %(protocol)s,
                    %(pkt_length)s,
                    %(source_ip)s,
                    %(dest_ip)s,
                    %(rest_json)s
                );                   
            ''',
                                {
                                    'timestamp': rec['date'],
                                    'hostname': rec['host'],
                                    'rule_num': rec['rule_num'],
                                    'sub_rule': rec['sub_rule'],
                                    'anchor': rec['anchor'],
                                    'tracker': rec['tracker'],
                                    'interface': rec['interface'],
                                    'reason': rec['reason'],
                                    'action': rec['action'],
                                    'direction': rec['direction'],
                                    'ip_version': rec['ip_version'],
                                    'tos': rec['tos'],
                                    'ecn': rec['ecn'],
                                    'ttl': rec['ttl'],
                                    'pkt_id': rec['id'],
                                    'offset': rec['offset'],
                                    'flags': rec['flags'],
                                    'proto_id': rec['proto_id'],
                                    'protocol': rec['protocol'],
                                    'pkt_length': rec['length'],
                                    'source_ip': rec['source_ip'],
                                    'dest_ip': rec['dest_ip'],
                                    'rest_json': rest_json
                                }
                                )
                    self.conn.commit()
        except Exception as e:
            print("Error saving record {0}: {1}".format(lineno, e), file=sys.stderr)
            print("Line: {0}".format(line), file=sys.stderr)
            print("")


    def digest_ipv6(self, rec, rest):

        rec['class'] = rest.pop(0)
        rec['flow_label'] = rest.pop(0)
        rec['hop_limit'] = rest.pop(0)
        rec['protocol'] = rest.pop(0)
        rec['proto_id'] = rest.pop(0)
        rec['length'] = rest.pop(0)
        rec['source_ip'] = rest.pop(0)
        rec['dest_ip'] = rest.pop(0)

        if rec['protocol'] == 'tcp':
            self.digest_tcp(rec, rest)
        elif rec['protocol'] == 'udp':
            self.digest_udp(rec, rest)
        elif rec['protocol'] == 'ipv6-icmp':
            self.digest_empty(rec, rest)
        else:
            raise Exception('Unknown IPv6 protocol: {0}'.format(rec['protocol']))

    def digest_filterlog(self, date, host, rest):
        '''
        Digest a filterlog entry
        '''
        rec = { 'date': date, 'host': host }

        x = rest.split(',')

        rec['rule_num'] = x.pop(0)
        rec['sub_rule'] = x.pop(0)
        rec['anchor'] = x.pop(0)
        rec['tracker'] = x.pop(0)
        rec['interface'] = x.pop(0)
        rec['reason'] = x.pop(0)
        rec['action'] = x.pop(0)
        rec['direction'] = x.pop(0)
        rec['ip_version'] = x.pop(0)

        if rec['ip_version'] == '4':
            self.digest_ipv4(rec, x)
        elif rec['ip_version'] == '6' or rec['ip_version'] == 'ipv6':
            self.digest_ipv6(rec, x)
        else:
            raise Exception('Unknown IP version')

        if len(x) != 0:
            print("Remainder: {0}".format(json.dumps(x)), file=sys.stderr)
            raise Exception("Incomplete parsing")

        return rec

def digest(flog, line):
    '''
    Digest a line which is in syslog RFC5424 format, initially pulling off the date/host.
    '''
    m = re.search(r'^(\S+) (\S+) filterlog\[\d+] (.*)', line)
    if m is None:
        raise Exception("Unknown record type for record")

    date = m.group(1)
    host = m.group(2)

    rec = flog.digest_filterlog(date, host, m.group(3))

    return rec

flog = filterlog()
with open("/var/logsafe/alpha-filterlog", "r") as fp:
    for lineno, line in enumerate(fp):
        try:
            rec = digest(flog, line)
            # if rec['action'] == 'block':
            #     print("{0}".format(json.dumps(rec)))
        except Exception as e:
            print("Error parsing record {0}: {1}".format(lineno, e), file=sys.stderr)
            print("Line: {0}".format(line), file=sys.stderr)
            print("")

    print("Total of {0} lines digested".format(lineno-1), file=sys.stderr)
