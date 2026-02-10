-- Rollback Phase 6: Remove user_escrow_roles table

DROP INDEX IF EXISTS idx_user_escrow_roles_role;
DROP INDEX IF EXISTS idx_user_escrow_roles_escrow;
DROP INDEX IF EXISTS idx_user_escrow_roles_user;
DROP TABLE IF EXISTS user_escrow_roles;
