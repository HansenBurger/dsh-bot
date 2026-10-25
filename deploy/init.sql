-- deploy/init.sql — containerized-PostgreSQL bootstrap.
--
-- The shipped deployment targets the *host* PostgreSQL instance (t4 §9.3), whose schema
-- is applied by docs/memory/sql/pg/001..004 through apps/memory-service/src/migrate.mjs
-- (or deploy/scripts/host-pg-prepare.sh, host-side). This file exists for the alternative
-- operator path — `postgres:16` as a compose service — where the image runs every
-- *.sql under /docker-entrypoint-initdb.d exactly once at initdb time.
--
-- It is intentionally idempotent and holds only what initdb cannot give us:
--   * the extension *installation* lives in 001_schema.sql, which runs in the same
--     phase; this file only guarantees the database-level preconditions.
-- Do NOT duplicate 001..004 here: two copies of a migration is how schema drift starts.

SET client_encoding = 'UTF8';

-- C.UTF-8 is required: the byte-trigram path (companion.byte_trgm) indexes UTF-8 byte
-- trigrams and depends on a byte-oriented collation for stable GIN opclass behaviour.
-- A template1-derived database with a non-C locale must be recreated, not patched.
DO $body$
BEGIN
  IF current_setting('server_encoding') <> 'UTF8' THEN
    RAISE EXCEPTION 'dsh_companion requires a UTF8-encoded cluster (got %)', current_setting('server_encoding');
  END IF;
END
$body$;

-- Availability check only: 001 installs the extensions inside schema `public`
-- (t1 lesson: a non-public extension schema breaks maintenance search_path).
DO $body$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pgcrypto') THEN
    RAISE EXCEPTION 'pgcrypto is not available; install postgresql-contrib-16 before starting the memory service';
  END IF;
END
$body$;
