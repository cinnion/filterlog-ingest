# filterlog-ingest
A utility which ingests and digests the log records from OPNSense's filterlog to
place the records in a PostgreSQL database to be available for analysis.

## Goal

This utility is intended to be used with [Heimdallr](https://github.com/cinnion/heimdallr),
which provides the migrations to create the schema of the table into which this utility loads
the log records. Not all log record fields are loaded into separate database fields at this
time, but are instead loaded into a JSON object stored along with each row. This means that
they are available for more complex queries, but only through the JSON methods provided by
PostgreSQL.

## Installation

This utility is intended to be installed into `/usr/libexec/rsyslog` and then executed via
rsyslog's [omprog](https://www.rsyslog.com/doc/configuration/modules/omprog.html) output 
module. The database configuration file is discussed in the next section.

It requires the following python3 modules to be installed

- dotenv
- psycopg2 (or psycopg2-binary)

## Configuration

Rather than hardcode the database information into the script itself, which would be both 
short-sighted and a security issue given that the code is committed and pushed to gitHub, 
the utility uses dotenv() to load a ENV file.  This file looks something like the following:

```shell
DATABASE_NAME='heimdallr'
DATABASE_USER='heimdallr'
DATABASE_PASSWORD='d958;l*%SDzy)(|21>pq'
DATABASE_HOST='server.example.com'
DATABASE_PORT='5432'
```

In fact, this is a subset of the configuration file used by Heimdallr itself.
