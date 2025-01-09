import os
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
    # @pytest.fixture(autouse=True, scope="function")
    # def setup_function(self, mocker):
    #     print("Setup...")
    #     self.obj = FilterLog()

    def test_digestEmpty_isEmpty_zeroLenReturned(self):
        # Arrange
        rec = {}
        rest = ['']
        obj = FilterLog()

        # Act
        obj.digest_empty(rec, rest)

        # Assert
        assert len(rest) == 0
        assert len(rec) == 0

    def test_digestEmpty_twoItems_raisesException(self):
        # Arrange
        rec = {}
        rest = ['1', '2']
        obj = FilterLog()

        # Act
        with pytest.raises(Exception):
            obj.digest_empty(rec, rest)

        # Assert
        assert len(rec) == 0
        assert rest == ['1', '2']

    @pytest.mark.xfail
    def test_digestFilterlog_IPv6_movesData(self, mocker):
        # Arrange
        rest = 'rule,sub,myanchor,mytracker,myinterface,myreason,myaction,mydirection,ipv6,a,b,c'
        obj = FilterLog()

        def empty_rest(rec, rest):
            rest = []

        mocker.patch.object(obj, 'digest_ipv4')
        mocker.patch.object(obj, 'digest_ipv6', side_effect=empty_rest)

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
        obj.digest_filterlog('mydate', 'myhost', rest)

        obj.digest_ipv4.assert_not_called()
        obj.digest_ipv6.assert_called_once_with(called_rec, ['a', 'b', 'c'])

    @pytest.mark.xfail
    def test_digestFilterlog_IP6_movesData(self, mocker):
        # Arrange
        rest = 'rule,sub,myanchor,mytracker,myinterface,myreason,myaction,mydirection,6,a,b,c'
        obj = FilterLog()

        def empty_rest(rec, rest):
            rest = []
            print(rest)

        mocker.patch.object(obj, 'digest_ipv4')
        mocker.patch.object(obj, 'digest_ipv6', side_effect=empty_rest)

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
        obj.digest_filterlog('mydate', 'myhost', rest)

        obj.digest_ipv4.assert_not_called()
        obj.digest_ipv6.assert_called_once_with(called_rec, ['a', 'b', 'c'])

    @pytest.mark.xfail
    def test_digestFilterlog_IPV4_movesData(self, mocker):
        # Arrange
        rest = 'rule,sub,myanchor,mytracker,myinterface,myreason,myaction,mydirection,4,a,b,c'
        obj = FilterLog()

        def empty_rest(rec, rest):
            rest = []

        mocker.patch.object(obj, 'digest_ipv4', side_effect=empty_rest)
        mocker.patch.object(obj, 'digest_ipv6')

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
        obj.digest_filterlog('mydate', 'myhost', rest)

        obj.digest_ipv4.assert_called_once_with(called_rec, ['a', 'b', 'c'])
        obj.digest_ipv6.assert_not_called()

    def test_digestFilterlog_unknownIp_raisesException(self, mocker):
        # Arrange
        rest = 'rule,sub,myanchor,mytracker,myinterface,myreason,myaction,mydirection,v8'
        obj = FilterLog()
        mocker.patch.object(obj, 'digest_ipv4')
        mocker.patch.object(obj, 'digest_ipv6')

        # Act
        with pytest.raises(Exception):
            obj.digest_filterlog('date', 'host', rest)

        obj.digest_ipv4.assert_not_called()
        obj.digest_ipv6.assert_not_called()
    def test_digest_filterlogRecord_callsDigestFilterlog(self, mocker):
        # Arrange
        line = 'date host filterlog[1234] bar bleh'
        # obj = mocker.patch.object(FilterLog, 'digest_filterlog')
        obj = FilterLog()
        mocker.patch.object(obj, 'digest_filterlog')

        # Act
        rec = obj.digest(line)

        # Assert
        obj.digest_filterlog.assert_called_once_with('date', 'host', 'bar bleh')

    def test_digest_nonFilterLogRecord_raisesException(self, mocker):
        # Arrange
        line = 'date host foo bar bleh'
        # obj = mocker.patch.object(FilterLog, 'digest_filterlog')
        obj = FilterLog()
        mocker.patch.object(obj, 'digest_filterlog')

        # Act
        with pytest.raises(Exception):
            rec = obj.digest(line)

        # Assert
        obj.digest_filterlog.assert_not_called()
