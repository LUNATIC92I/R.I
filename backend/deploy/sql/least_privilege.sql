-- Least-privilege PostgreSQL roles for AFRICAN INTELLIGENCE CORE.
-- Run as the database owner AFTER `alembic upgrade head` (performed by aic_migrator).
-- Passwords are set out of band (\password) or via the institution's secret manager.

CREATE ROLE aic_migrator LOGIN;      -- owns the schema, used only by migrations
CREATE ROLE aic_app LOGIN;           -- used by the API at runtime
CREATE ROLE aic_auditor_ro LOGIN;    -- read-only access to the audit trail for external control bodies

GRANT CONNECT ON DATABASE aic TO aic_app, aic_auditor_ro;
GRANT USAGE ON SCHEMA public TO aic_app, aic_auditor_ro;

-- Runtime: DML on business tables, no DDL.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aic_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aic_app;

-- The audit trail is append-only for the application.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM aic_app;
GRANT SELECT, INSERT ON audit_logs TO aic_app;
-- The chain head row must be updatable (it serialises inserts) but not deletable.
REVOKE DELETE, TRUNCATE ON audit_chain_head FROM aic_app;

-- Defence in depth: forbid UPDATE/DELETE on audit_logs even for roles that might be granted later.
CREATE OR REPLACE FUNCTION aic_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only';
END $$;
DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs;
CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION aic_audit_immutable();

GRANT SELECT ON audit_logs TO aic_auditor_ro;

-- Encrypted document content is only reachable through the API.
REVOKE ALL ON document_blobs FROM aic_auditor_ro;
