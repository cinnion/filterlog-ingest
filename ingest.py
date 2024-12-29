#!/usr/bin/env python3
"""
ingest -- A utility to ingest a SYSLOG stream from OPNSense's filterlog

This utility ingests RFC 5424 formatted records from SYSLOG, and where those
records are from filterlog, they are digested and stored in a database.

@author:     Doug Needham

@copyright:  2024 Doug Needham. All rights reserved.

@license:    BSD-3-Clause

@contact:    cinnion@gmail.com
@deffield    updated: Updated
"""
import os
import sys
import re
import json
import psycopg2
# from dotenv import load_dotenv
import dotenv

from argparse import ArgumentParser  # as originalArgumentParser
from argparse import ArgumentError
from argparse import RawDescriptionHelpFormatter
from argparse import SUPPRESS

__version__ = 1.0
__date__ = '2024-12-28'
__updated__ = '2024-12-28'

DEBUG = 1
TESTRUN = 0
PROFILE = 0


class FilterLog:
    conn = None

    def __init__(self, envfile=None):

        dotenv.load_dotenv(envfile)

        db_settings = {
            'dbname': os.getenv('DATABASE_NAME'),
            'user': os.getenv('DATABASE_USER'),
            'password': os.getenv('DATABASE_PASSWORD'),
            'host': os.getenv('DATABASE_HOST'),
            'port': os.getenv('DATABASE_PORT'),
        }

        self.conn = psycopg2.connect(**db_settings)

    def digest_empty(self, _rec, rest):

        if len(rest) != 1 and rest[0] != '':
            raise Exception("Unexpected rest of record: {0}".format(json.dumps(rest)))

        rest.pop(0)

    def digest_datalength(self, _rec, rest):
        """
        Verify that we have only one item remaining, and that it is a "datalength=X"
        value, and if so, stash the value.
        """
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

    def digest_igmp(self, _rec, rest):

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
        elif rec['protocol'] == 'esp':
            rest_dict = self.digest_datalength(rec, rest)
        elif rec['protocol'] == 'gre':
            rest_dict = self.digest_datalength(rec, rest)
        elif rec['protocol'] == 'ipv6':
            rest_dict = self.digest_datalength(rec, rest)
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
            self.conn.rollback()
            raise Exception("Error saving IPv4 record") from e

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
            rest_dict = self.digest_tcp(rec, rest)
        elif rec['protocol'] == 'udp':
            rest_dict = self.digest_udp(rec, rest)
        elif rec['protocol'] == 'ipv6-icmp':
            rest_dict = self.digest_empty(rec, rest)
        else:
            raise Exception('Unknown IPv6 protocol: {0}'.format(rec['protocol']))

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
                    pkt_class,
                    flow_label,
                    hop_limit,
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
                    %(class)s,
                    %(flow_label)s,
                    %(hop_limit)s,
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
                                     'class': rec['class'],
                                     'flow_label': rec['flow_label'],
                                     'hop_limit': rec['hop_limit'],
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
            self.conn.rollback()
            raise Exception("Error saving IPv6 record") from e

    def digest_filterlog(self, date, host, rest):
        """
        Digest a filterlog entry
        """
        rec = {'date': date, 'host': host}

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

    def digest(self, line):
        """
        Digest a line which is in syslog RFC5424 format, initially pulling off the date/host.
        """
        m = re.search(r'^(\S+) (\S+) filterlog\[\d+] (.*)', line)
        if m is None:
            raise Exception("Unknown record type for record")

        date = m.group(1)
        host = m.group(2)

        rec = self.digest_filterlog(date, host, m.group(3))

        return rec


def main():
    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

  Created by Doug Needham on %s.
  Copyright (c) 2024 Doug Needham

  This program and the accompanying materials are made
  available under the terms of the BSD 3-Clause License
  which is available at https://opensource.org/licenses/BSD-3-Clause

  SPDX-License-Identifier: BSD-3-Clause

USAGE
''' % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter,
                                add_help=False)
        parser.add_argument('-h', '--help', action='help', default=SUPPRESS, help='show this help message and exit')
        parser.add_argument('-V', '--version', action='version', version=program_version_message)

        parser.add_argument(dest='envfile',
                            help='path to the environment file with the database configuration [default: %(default)s]',
                            nargs='?',
                            metavar='envfile')

        # Process arguments
        args = parser.parse_args()

        flog = FilterLog(args.envfile)

        lineno = 0
        for line in sys.stdin:
            try:
                line.rstrip('\n')
                lineno = lineno + 1
                flog.digest(line)
            except KeyboardInterrupt:
                ### handle keyboard interrupt ###
                break

            except Exception as e:
                print("Error parsing record: {0}".format(e), file=sys.stderr)
                if e.__cause__:
                    print("Error caused by: {0}".format(e.__cause__), file=sys.stderr)
                print("Line: {0}".format(line), file=sys.stderr)
                print("")

        print("Total of {0} lines digested".format(lineno), file=sys.stderr)

    except ArgumentError as e:
        ### Return 3 after printing the Unknown service status ###
        print(str(e))
        return 3

    except Exception as e:
        if DEBUG or TESTRUN:
            raise e
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        return 3


if __name__ == '__main__':
    if TESTRUN:
        import doctest

        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats

        profile_filename = '_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())
