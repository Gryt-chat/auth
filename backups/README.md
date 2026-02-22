This folder is for **local Postgres backups** of the Keycloak database.

- Backup files (`*.sql`, `*.sql.gz`, `*.dump*`) are **gitignored**.
- Use the scripts in `auth/ops/`:
  - `auth/ops/pg_backup.sh` to create a backup
  - `auth/ops/pg_restore_smoketest.sh` to validate a backup can be restored

