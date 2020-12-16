--
-- Database definition file for the NGX Session Manager in PostgreSQL
--
-- Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
-- See the LICENSE file accompanying the distribution your rights to use
-- this software.
--
-- To load, recommended command is:
--
-- psql -U <userid> -W <database> < ngxsessionmgr.pgsql
--
-- NOTE: ordering on these drop statements must take into consideration the
--       foreign key constraints (or relax foreign key constraints).
--

DROP TABLE IF EXISTS ngxsessionmgr.access;
DROP TABLE IF EXISTS ngxsessionmgr.sessions;
DROP TABLE IF EXISTS ngxsessionmgr.users;

-- Note, no cascade, just in case someone added an extension...
DROP SCHEMA IF EXISTS ngxsessionmgr;

------------------------------------------------------------------

CREATE SCHEMA ngxsessionmgr;

-- Basic user table, this can be extended as needed for custom attributes
CREATE TABLE ngxsessionmgr.users (
     user_id SERIAL NOT NULL,
     user_name VARCHAR(255) NOT NULL,
     external_auth_id VARCHAR(255),
     active BOOLEAN NOT NULL DEFAULT 'y',

     PRIMARY KEY(user_id)
);

-- Active user sessions, for reconstruction and/or external reference
CREATE TABLE ngxsessionmgr.sessions (
     user_id INTEGER NOT NULL,
     session_id VARCHAR(255) NOT NULL,
     source_ipaddr VARCHAR(255) NOT NULL,
     established TIMESTAMPTZ NOT NULL,
     expires TIMESTAMPTZ NOT NULL,
     attributes BYTEA NOT NULL,

     FOREIGN KEY(user_id) REFERENCES ngxsessionmgr.users(user_id)
     -- session_id is only guaranteed unique within running instance...
);

-- Session access/audit history, time series on session create or IP change
CREATE TABLE ngxsessionmgr.access (
     user_id INTEGER NOT NULL,
     session_id VARCHAR(255) NOT NULL,
     source_ipaddr VARCHAR(255) NOT NULL,
     accessed TIMESTAMPTZ NOT NULL,

     FOREIGN KEY(user_id) REFERENCES ngxsessionmgr.users(user_id)
);
