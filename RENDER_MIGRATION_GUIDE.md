# Render Migration Guide - From Local/Railway to Render

This guide helps you migrate your Matrix data from local or Railway databases to Render.

## Pre-Migration Checklist

- [ ] Backup current database (local or Railway)
- [ ] Note down all current environment configurations
- [ ] Render databases created and online (green status)
- [ ] Backend service created but NOT yet migrated
- [ ] Test environment variables configured

---

## Option 1: Migrate Data from Local PostgreSQL

### Prerequisites
- Current local database: `matrix` on `localhost:5432`
- New Render database URL saved
- `pg_dump` and `psql` installed

### Step 1: Backup Local Database

```bash
# On your local machine
pg_dump -U matrix -d matrix -h localhost > matrix_backup.sql
```

This creates a backup file `matrix_backup.sql` (~1-10MB depending on data size).

### Step 2: Create Tables on Render (Run Migrations)

Using Render Shell:

```bash
cd backend
alembic upgrade head
```

This creates the schema on Render database.

### Step 3: Restore Data to Render

```bash
# Replace with your Render DATABASE_URL credentials
psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix < matrix_backup.sql
```

Or using pgAdmin (UI method):
1. Connect to your Render PostgreSQL
2. Restore the `matrix_backup.sql` file
3. Verify data is present

### Step 4: Verify Data

In Render Shell:
```bash
psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix -c "SELECT COUNT(*) FROM users; SELECT COUNT(*) FROM scans;"
```

---

## Option 2: Migrate Data from Railway

### Prerequisites
- Current Railway database external URL
- New Render database URL saved
- `pg_dump` installed locally

### Step 1: Export Data from Railway

```bash
# Use Railway's external database URL
pg_dump [RAILWAY_EXTERNAL_DATABASE_URL] > matrix_from_railway.sql
```

Example:
```bash
pg_dump postgresql://postgres:PASSWORD@hostname.railway.app:5432/postgres > matrix_from_railway.sql
```

### Step 2: Create Tables on Render (Run Migrations)

Using Render Shell:
```bash
cd backend
alembic upgrade head
```

### Step 3: Import Data to Render

```bash
psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix < matrix_from_railway.sql
```

### Step 4: Verify Data Migration

```bash
# Connect to Render database
psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix

# Inside psql prompt:
\dt  # List all tables
SELECT COUNT(*) FROM users;  # Check user count
SELECT COUNT(*) FROM scans;  # Check scan count
\q   # Exit
```

---

## Option 3: Start Fresh (Clean Migration)

If you want to start with a clean database:

### Step 1: Create Empty Schema

In Render Shell:
```bash
cd backend
alembic upgrade head
```

### Step 2: Seed Initial Data (Optional)

Create initial admin user or test data:
```bash
python -c "from app.database import engine, Base; Base.metadata.create_all(engine); print('Schema created')"
```

---

## Redis Migration

### Option A: No Data Migration Needed
Redis is typically used for **caches and sessions**, not persistent data. You can safely:

1. Create a new Redis instance on Render ✓ (done in setup)
2. Use the new `REDIS_URL` in environment variables ✓ (done in setup)
3. Old cache data is not needed (automatically invalidates)

### Option B: Backup Redis (If Needed)

From local/Railway Redis:
```bash
# Local Redis
redis-cli -h localhost -p 6379 BGSAVE

# Railway Redis  
redis-cli -h [RAILWAY_HOST] -p 6379 -a [PASSWORD] BGSAVE
```

Then restore to Render:
```bash
# Advanced - requires custom migration script
# Usually not necessary for caches
```

---

## Verification Checklist

After migration, verify everything:

- [ ] PostgreSQL data migrated:
  ```bash
  # In Render Shell
  psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix -c "SELECT COUNT(*) FROM users;"
  ```

- [ ] Redis connections working:
  ```bash
  # In Render Shell  
  python
  import redis
  r = redis.from_url("redis://default:PASSWORD@hostname.onrender.com:6379")
  print(r.ping())  # Should print True
  exit()
  ```

- [ ] Backend connects to databases:
  ```bash
  # Check backend logs in Render dashboard
  # Should NOT show connection errors
  ```

- [ ] Frontend connects to backend:
  ```bash
  # Test in browser: https://your-app.vercel.app
  # Try logging in or creating a scan
  # Check Network tab for API calls
  ```

- [ ] No data loss:
  ```bash
  # Verify critical data
  # Count records and compare with old system
  ```

---

## Rollback Plan

If migration fails:

### Fast Rollback (Return to Old System)

1. Update backend environment variables back to old database URL
2. In Render dashboard: **update DATABASE_URL** → commit change
3. Render automatically redeploys with old database
4. Check backend health endpoint

### Keep Backup
```bash
# Always keep backups before migration
ls -lah matrix_backup.sql
# Archive for 30 days before deleting
```

---

## Data Validation Queries

Run these to verify data integrity:

```sql
-- Count all tables
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) 
FROM pg_tables 
WHERE schemaname NOT IN ('pg_catalog', 'information_schema');

-- Check users
SELECT COUNT(*) as user_count FROM users;

-- Check scans  
SELECT COUNT(*) as scan_count FROM scans;
SELECT COUNT(*) as with_results FROM scans WHERE scan_results IS NOT NULL;

-- Check jobs queue
SELECT COUNT(*) FROM rq_tasks;

-- Database size
SELECT pg_size_pretty(pg_database_size(current_database()));
```

---

## Common Issues

### Issue: "Invalid UTF-8 sequence" during restore
**Solution**: Use UTF-8 encoding:
```bash
pg_dump -E UTF8 [SOURCE_DB_URL] > backup.sql
psql postgresql://... < backup.sql
```

### Issue: "Role 'postgres' does not exist"
**Solution**: Change role in SQL dump before restoring:
```bash
sed 's/OWNER TO postgres/OWNER TO matrix/g' backup.sql > fixed_backup.sql
psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix < fixed_backup.sql
```

### Issue: Sequence values out of sync
**Solution**: Reset sequences after restore:
```bash
psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix

-- In psql:
SELECT setval(pg_get_serial_sequence('users', 'id'), MAX(id)) FROM users;
SELECT setval(pg_get_serial_sequence('scans', 'id'), MAX(id)) FROM scans;
-- Repeat for each table with auto-incrementing ID
```

### Issue: Foreign key constraint violations
**Solution**: Disable constraints during restore:
```bash
psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix -c "ALTER TABLE ... DISABLE TRIGGER ALL;"
# Restore data
psql ... < backup.sql
# Re-enable
psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix -c "ALTER TABLE ... ENABLE TRIGGER ALL;"
```

---

## Post-Migration Steps

1. **Monitor**: Watch Render logs for errors (first 24 hours)
2. **Test**: Perform full end-to-end testing
3. **Backup**: Enable automatic backups in Render
4. **Archive**: Keep backup file for 30 days
5. **Document**: Note timestamps and versions used

---

## Performance Optimization Post-Migration

After successful migration:

```sql
-- Analyze tables
ANALYZE;

-- Check index usage
SELECT schemaname, tablename, indexname 
FROM pg_indexes 
WHERE schemaname NOT IN ('pg_catalog', 'information_schema');

-- Monitor connection pool
-- Check Render dashboard → Database → Connections
```

---

## Need Help?

- Check Render logs: Service Dashboard → Logs
- PostgreSQL issues: See [RENDER_DEPLOYMENT_GUIDE.md](RENDER_DEPLOYMENT_GUIDE.md)
- Redis issues: Test with `redis-cli`
- Data loss: Use `matrix_backup.sql` to restore
