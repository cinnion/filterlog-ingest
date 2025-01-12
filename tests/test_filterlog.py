import os
from unittest.mock import Mock

import psycopg2
import pytest
import pytest_mock

from ingest import FilterLog


class TestFilterLogInit:

    def test_initDefaultPath_loadDotenvDefaultDoesSearch(self, mocker):
        # Arrange
        mocked_load_dotenv = mocker.patch('dotenv.load_dotenv')
        mocked_connect = mocker.patch('psycopg2.connect')

        # Act
        flog = FilterLog()

        # Assert
        mocked_load_dotenv.assert_called_once_with(None)

    def test_initEnvSpecified_loadDotenvCalledWithSpecifiedEnv(self, mocker):
        # Arrange
        mocked_load_dotenv = mocker.patch('dotenv.load_dotenv')
        mocked_connect = mocker.patch('psycopg2.connect')

        # Act
        flog = FilterLog(".env")

        # Assert
        mocked_load_dotenv.assert_called_once_with('.env')

    # Must be before any valid env is loaded.
    def test_initBadSettings_connectThrowsException(self, mocker):
        # Arrange
        db_settings = {
            'dbname': os.getenv('DATABASE_NAME'),
            'user': os.getenv('DATABASE_USER'),
            'password': os.getenv('DATABASE_PASSWORD'),
            'host': os.getenv('DATABASE_HOST'),
            'port': os.getenv('DATABASE_PORT'),
        }

        # Act
        with pytest.raises(psycopg2.OperationalError):
            FilterLog('/tmp/junkenv')

        # Assert

    def test_init_connectionSettingsPassed(self, mocker):
        # Arrange
        mocked_connect = mocker.patch('psycopg2.connect')

        # Act
        flog = FilterLog("../.env")

        # Assert
        db_settings = {
            'dbname': os.getenv('DATABASE_NAME'),
            'user': os.getenv('DATABASE_USER'),
            'password': os.getenv('DATABASE_PASSWORD'),
            'host': os.getenv('DATABASE_HOST'),
            'port': os.getenv('DATABASE_PORT'),
        }
        mocked_connect.assert_called_once_with(**db_settings)


class TestFilterLog:
    @pytest.fixture(autouse=True, scope="function")
    def setup_function(self, mocker):
        self.obj = FilterLog()

    def test_digestEmpty_isEmpty_zeroLenReturned(self):
        # Arrange
        rec = {}
        rest = ['']

        # Act
        self.obj.digest_empty(rec, rest)

        # Assert
        assert len(rest) == 0
        assert len(rec) == 0

    def test_digestEmpty_twoItems_raisesException(self):
        # Arrange
        rec = {}
        rest = ['1', '2']

        # Act
        with pytest.raises(Exception):
            self.obj.digest_empty(rec, rest)

        # Assert
        assert len(rec) == 0
        assert rest == ['1', '2']

    def test_digestDatalength_isEmpty_raisesException(self):
        # Arrange
        rec = {}
        rest = []

        # Act
        with pytest.raises(Exception):
            self.obj.digest_datalength(rec, rest)

        # Assert
        assert len(rest) == 0
        assert len(rec) == 0

    def test_digestDatalength_notDataLength_raisesException(self):
        # Arrange
        rec = {}
        rest = ['foo']

        # Act
        with pytest.raises(Exception):
            self.obj.digest_datalength(rec, rest)

        # Assert
        assert rest == ['foo']
        assert len(rec) == 0

    def test_digestDatalength_tooLong_raisesException(self):
        # Arrange
        rec = {}
        rest = ['datalength=23', 'bar']

        # Act
        with pytest.raises(Exception):
            self.obj.digest_datalength(rec, rest)

        # Assert
        assert rest == ['datalength=23', 'bar']
        assert len(rec) == 0

    def test_digestDatalength_tooLong_correctLength(self):
        # Arrange
        rec = {}
        rest = ['datalength=23']

        # Act
        retdict = self.obj.digest_datalength(rec, rest)

        # Assert
        assert len(rest) == 0
        assert len(rec) == 0
        assert retdict == {'datalength': '23'}

    def test_digesttcp_goodRecord_movesData(self):
        # Arrange
        rec = {}
        rest = ['mysport', 'mydport', 'mydatalen', 'mytcpflags', 'myseq', 'myack', 'mywindow', 'myurg', 'myopts']

        expected_rec = {
            'sport': 'mysport',
            'dport': 'mydport',
            'datalen': 'mydatalen',
        }

        expected_ret = {
            'tcp_flags': 'mytcpflags',
            'seq': 'myseq',
            'ack': 'myack',
            'window': 'mywindow',
            'urg': 'myurg',
            'options': 'myopts'
        }

        # Act
        ret = self.obj.digest_tcp(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        assert ret == expected_ret

    def test_digestudp_goodRecord_movesData(self):
        # Arrange
        rec = {}
        rest = ['mysport', 'mydport', 'mydatalen']

        expected_rec = {
            'sport': 'mysport',
            'dport': 'mydport',
            'datalen': 'mydatalen',
        }

        expected_ret = {
        }

        # Act
        ret = self.obj.digest_udp(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        assert ret == expected_ret

    @pytest.fixture(scope="function")
    def setup_ip_rec_and_db_mock(self, mocker):
        rec = {'date': 'mydate',
               'host': 'myhost',
               'rule_num': 'myrulenum',
               'sub_rule': 'mysubrule',
               'anchor': 'myanchor',
               'tracker': 'mytracker',
               'interface': 'myint',
               'reason': 'myreason',
               'action': 'myaction',
               'direction': 'mydirection',
               'ip_version': 'myipversion'
               }

        expected_rec_base = {
            'date': 'mydate',
            'host': 'myhost',
            'rule_num': 'myrulenum',
            'sub_rule': 'mysubrule',
            'anchor': 'myanchor',
            'tracker': 'mytracker',
            'interface': 'myint',
            'reason': 'myreason',
            'action': 'myaction',
            'direction': 'mydirection',
            'ip_version': 'myipversion'
        }

        conn = Mock()
        mocker.patch.object(self.obj, 'conn')

        return rec, expected_rec_base

    def test_digestIPv4_tcp_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['mytos', 'myecn', 'myttl', 'myid', 'myoffset', 'myflags', 'myprotoid', 'tcp', 'mylen', 'mysourceip',
                'mydestip', 'mysport', 'mydport', 'mydatalen', 'mytcpflags', 'myseq', 'myack', 'mywindow', 'myurg',
                'options']

        expected_rec = {
            **expected_rec_base,
            'tos': 'mytos',
            'ecn': 'myecn',
            'ttl': 'myttl',
            'id': 'myid',
            'offset': 'myoffset',
            'flags': 'myflags',
            'proto_id': 'myprotoid',
            'protocol': 'tcp',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
            'sport': 'mysport',
            'dport': 'mydport',
            'datalen': 'mydatalen'
        }

        expected_restdict = {
            'tcp_flags': 'mytcpflags',
            'seq': 'myseq',
            'ack': 'myack',
            'window': 'mywindow',
            'urg': 'myurg',
            'options': 'myopts'
        }

        # Act
        self.obj.digest_ipv4(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv4_udp_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['mytos', 'myecn', 'myttl', 'myid', 'myoffset', 'myflags', 'myprotoid', 'udp', 'mylen', 'mysourceip',
                'mydestip', 'mysport', 'mydport', 'mydatalen']

        expected_rec = {
            **expected_rec_base,
            'tos': 'mytos',
            'ecn': 'myecn',
            'ttl': 'myttl',
            'id': 'myid',
            'offset': 'myoffset',
            'flags': 'myflags',
            'proto_id': 'myprotoid',
            'protocol': 'udp',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
            'sport': 'mysport',
            'dport': 'mydport',
            'datalen': 'mydatalen'
        }
        expected_restdict = {
        }

        # Act
        self.obj.digest_ipv4(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv4_esp_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['mytos', 'myecn', 'myttl', 'myid', 'myoffset', 'myflags', 'myprotoid', 'esp', 'mylen', 'mysourceip',
                'mydestip', 'datalength=23']

        expected_rec = {
            **expected_rec_base,
            'tos': 'mytos',
            'ecn': 'myecn',
            'ttl': 'myttl',
            'id': 'myid',
            'offset': 'myoffset',
            'flags': 'myflags',
            'proto_id': 'myprotoid',
            'protocol': 'esp',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
        }
        expected_restdict = {
            'datalength': '23'
        }

        # Act
        self.obj.digest_ipv4(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv4_gre_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['mytos', 'myecn', 'myttl', 'myid', 'myoffset', 'myflags', 'myprotoid', 'gre', 'mylen', 'mysourceip',
                'mydestip', 'datalength=23']

        expected_rec = {
            **expected_rec_base,
            'tos': 'mytos',
            'ecn': 'myecn',
            'ttl': 'myttl',
            'id': 'myid',
            'offset': 'myoffset',
            'flags': 'myflags',
            'proto_id': 'myprotoid',
            'protocol': 'gre',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
        }
        expected_restdict = {
            'datalength': '23'
        }

        # Act
        self.obj.digest_ipv4(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv4_ipv6_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['mytos', 'myecn', 'myttl', 'myid', 'myoffset', 'myflags', 'myprotoid', 'ipv6', 'mylen', 'mysourceip',
                'mydestip', 'datalength=23']

        expected_rec = {
            **expected_rec_base,
            'tos': 'mytos',
            'ecn': 'myecn',
            'ttl': 'myttl',
            'id': 'myid',
            'offset': 'myoffset',
            'flags': 'myflags',
            'proto_id': 'myprotoid',
            'protocol': 'ipv6',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
        }
        expected_restdict = {
            'datalength': '23'
        }

        # Act
        self.obj.digest_ipv4(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv4_igmp_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['mytos', 'myecn', 'myttl', 'myid', 'myoffset', 'myflags', 'myprotoid', 'igmp', 'mylen', 'mysourceip',
                'mydestip', 'datalength=23']

        expected_rec = {
            **expected_rec_base,
            'tos': 'mytos',
            'ecn': 'myecn',
            'ttl': 'myttl',
            'id': 'myid',
            'offset': 'myoffset',
            'flags': 'myflags',
            'proto_id': 'myprotoid',
            'protocol': 'igmp',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
        }
        expected_restdict = {
            'datalength': '23'
        }

        # Act
        self.obj.digest_ipv4(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv4_icmp_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['mytos', 'myecn', 'myttl', 'myid', 'myoffset', 'myflags', 'myprotoid', 'icmp', 'mylen', 'mysourceip',
                'mydestip', 'datalength=23']

        expected_rec = {
            **expected_rec_base,
            'tos': 'mytos',
            'ecn': 'myecn',
            'ttl': 'myttl',
            'id': 'myid',
            'offset': 'myoffset',
            'flags': 'myflags',
            'proto_id': 'myprotoid',
            'protocol': 'icmp',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
        }
        expected_restdict = {
            'datalength': '23'
        }

        # Act
        self.obj.digest_ipv4(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv4_badProto_raisesException(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['mytos', 'myecn', 'myttl', 'myid', 'myoffset', 'myflags', 'myprotoid', 'badproto', 'mylen', 'mysourceip',
                'mydestip', 'datalength=23']

        expected_rec = {
            **expected_rec_base,
            'tos': 'mytos',
            'ecn': 'myecn',
            'ttl': 'myttl',
            'id': 'myid',
            'offset': 'myoffset',
            'flags': 'myflags',
            'proto_id': 'myprotoid',
            'protocol': 'badproto',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
        }
        expected_restdict = {
        }

        # Act
        with pytest.raises(Exception):
            self.obj.digest_ipv4(rec, rest)

        # Assert
        assert len(rest) == 1
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()


    def test_digestIPv6_tcp_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['myclass', 'myflow', 'myhoplimit', 'tcp', 'myprotoid', 'mylen', 'mysourceip',
                'mydestip', 'mysport', 'mydport', 'mydatalen', 'mytcpflags', 'myseq', 'myack', 'mywindow', 'myurg',
                'myopts']

        expected_rec = {
            **expected_rec_base,
            'class': 'myclass',
            'flow_label': 'myflow',
            'hop_limit': 'myhoplimit',
            'proto_id': 'myprotoid',
            'protocol': 'tcp',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
            'sport': 'mysport',
            'dport': 'mydport',
            'datalen': 'mydatalen'
        }
        expected_restdict = {
            'tcp_flags': 'mytcpflags',
            'seq': 'myseq',
            'ack': 'myack',
            'window': 'mywindow',
            'urg': 'myurg',
            'options': 'myopts'
        }

        # Act
        self.obj.digest_ipv6(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv6_udp_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['myclass', 'myflow', 'myhoplimit', 'udp', 'myprotoid', 'mylen', 'mysourceip',
                'mydestip', 'mysport', 'mydport', 'mydatalen']

        expected_rec = {
            **expected_rec_base,
            'class': 'myclass',
            'flow_label': 'myflow',
            'hop_limit': 'myhoplimit',
            'proto_id': 'myprotoid',
            'protocol': 'udp',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
            'sport': 'mysport',
            'dport': 'mydport',
            'datalen': 'mydatalen'
        }
        expected_restdict = {
        }

        # Act
        self.obj.digest_ipv6(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv6_icmp_movesData(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['myclass', 'myflow', 'myhoplimit', 'ipv6-icmp', 'myprotoid', 'mylen', 'mysourceip',
                'mydestip', '']

        expected_rec = {
            **expected_rec_base,
            'class': 'myclass',
            'flow_label': 'myflow',
            'hop_limit': 'myhoplimit',
            'proto_id': 'myprotoid',
            'protocol': 'ipv6-icmp',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
        }
        expected_restdict = {
        }

        # Act
        self.obj.digest_ipv6(rec, rest)

        # Assert
        assert len(rest) == 0
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    def test_digestIPv6_badProtocol_raisesException(self, mocker, setup_ip_rec_and_db_mock):
        # Arrange
        rec, expected_rec_base = setup_ip_rec_and_db_mock

        rest = ['myclass', 'myflow', 'myhoplimit', 'badproto', 'myprotoid', 'mylen', 'mysourceip',
                'mydestip', '']

        expected_rec = {
            **expected_rec_base,
            'class': 'myclass',
            'flow_label': 'myflow',
            'hop_limit': 'myhoplimit',
            'proto_id': 'myprotoid',
            'protocol': 'badproto',
            'length': 'mylen',
            'source_ip': 'mysourceip',
            'dest_ip': 'mydestip',
        }
        expected_restdict = {
        }

        # Act
        with pytest.raises(Exception):
            self.obj.digest_ipv6(rec, rest)

        # Assert
        assert len(rest) == 1
        assert rec == expected_rec
        # self.obj.conn.cursor.execute.assert_called_once()

    @pytest.mark.skip
    def test_digestFilterlog_IPv6_movesData(self, mocker):
        # Arrange
        rest = 'rule,sub,myanchor,mytracker,myinterface,myreason,myaction,mydirection,ipv6,a,b,c'

        def empty_rest(rec, rest):
            rest = []

        mocker.patch.object(self.obj, 'digest_ipv4')
        mocker.patch.object(self.obj, 'digest_ipv6', side_effect=empty_rest)

        called_rec = {
            'date': 'mydate',
            'host': 'myhost',
            'rule_num': 'rule',
            'sub_rule': 'sub',
            'anchor': 'myanchor',
            'tracker': 'mytracker',
            'interface': 'myinterface',
            'reason': 'myreason',
            'action': 'myaction',
            'direction': 'mydirection',
            'ip_version': 'ipv6'
        }

        # Act
        self.obj.digest_filterlog('mydate', 'myhost', rest)

        self.obj.digest_ipv4.assert_not_called()
        self.obj.digest_ipv6.assert_called_once_with(called_rec, ['a', 'b', 'c'])

    @pytest.mark.skip
    def test_digestFilterlog_IP6_movesData(self, mocker):
        # Arrange
        rest = 'rule,sub,myanchor,mytracker,myinterface,myreason,myaction,mydirection,6,a,b,c'

        def empty_rest(rec, rest):
            rest = []
            print(rest)

        mocker.patch.object(self.obj, 'digest_ipv4')
        mocker.patch.object(self.obj, 'digest_ipv6', side_effect=empty_rest)

        called_rec = {
            'date': 'mydate',
            'host': 'myhost',
            'rule_num': 'rule',
            'sub_rule': 'sub',
            'anchor': 'myanchor',
            'tracker': 'mytracker',
            'interface': 'myinterface',
            'reason': 'myreason',
            'action': 'myaction',
            'direction': 'mydirection',
            'ip_version': '6'
        }

        # Act
        self.obj.digest_filterlog('mydate', 'myhost', rest)

        self.obj.digest_ipv4.assert_not_called()
        self.obj.digest_ipv6.assert_called_once_with(called_rec, ['a', 'b', 'c'])

    @pytest.mark.skip
    def test_digestFilterlog_IPV4_movesData(self, mocker):
        # Arrange
        rest = 'rule,sub,myanchor,mytracker,myinterface,myreason,myaction,mydirection,4,a,b,c'

        def empty_rest(rec, rest):
            rest = []

        mocker.patch.object(self.obj, 'digest_ipv4', side_effect=empty_rest)
        mocker.patch.object(self.obj, 'digest_ipv6')

        called_rec = {
            'date': 'mydate',
            'host': 'myhost',
            'rule_num': 'rule',
            'sub_rule': 'sub',
            'anchor': 'myanchor',
            'tracker': 'mytracker',
            'interface': 'myinterface',
            'reason': 'myreason',
            'action': 'myaction',
            'direction': 'mydirection',
            'ip_version': '4'
        }

        # Act
        self.obj.digest_filterlog('mydate', 'myhost', rest)

        self.obj.digest_ipv4.assert_called_once_with(called_rec, ['a', 'b', 'c'])
        self.obj.digest_ipv6.assert_not_called()

    def test_digestFilterlog_unknownIp_raisesException(self, mocker):
        # Arrange
        rest = 'rule,sub,myanchor,mytracker,myinterface,myreason,myaction,mydirection,v8'
        mocker.patch.object(self.obj, 'digest_ipv4')
        mocker.patch.object(self.obj, 'digest_ipv6')

        # Act
        with pytest.raises(Exception):
            self.obj.digest_filterlog('date', 'host', rest)

        self.obj.digest_ipv4.assert_not_called()
        self.obj.digest_ipv6.assert_not_called()

    def test_digest_filterlogRecord_callsDigestFilterlog(self, mocker):
        # Arrange
        line = 'date host filterlog[1234] bar bleh'
        mocker.patch.object(self.obj, 'digest_filterlog')

        # Act
        rec = self.obj.digest(line)

        # Assert
        self.obj.digest_filterlog.assert_called_once_with('date', 'host', 'bar bleh')

    def test_digest_nonFilterLogRecord_raisesException(self, mocker):
        # Arrange
        line = 'date host foo bar bleh'
        mocker.patch.object(self.obj, 'digest_filterlog')

        # Act
        with pytest.raises(Exception):
            rec = self.obj.digest(line)

        # Assert
        self.obj.digest_filterlog.assert_not_called()
