import os
import psycopg2
import pytest

from ingest import FilterLog


class TestFilterLog:

    def test_initDefaultPath_loadDotenvDefaultDoesSearch(self, mocker):
        # Setup
        mocked_load_dotenv = mocker.patch('dotenv.load_dotenv')
        mocked_connect = mocker.patch('psycopg2.connect')

        # Act
        flog = FilterLog()

        # Assert
        mocked_load_dotenv.assert_called_once_with(None)

    def test_initEnvSpecified_loadDotenvCalledWithSpecifiedEnv(self, mocker):
        # Setup
        mocked_load_dotenv = mocker.patch('dotenv.load_dotenv')
        mocked_connect = mocker.patch('psycopg2.connect')

        # Act
        flog = FilterLog(".env")

        # Assert
        mocked_load_dotenv.assert_called_once_with('.env')

    # Must be before any valid env is loaded.
    def test_initBadSettings_connectThrowsException(self, mocker):
        # Setup
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
        # Setup
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
