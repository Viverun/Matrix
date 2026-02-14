# Render Deployment Checklist

Complete this checklist to deploy your Matrix application to Render with PostgreSQL and Redis.

## Phase 1: Prepare Render Account

- [ ] Create account on [render.com](https://render.com)
- [ ] Verify email address
- [ ] Connect GitHub repository
- [ ] Select your repository (Matrix)

## Phase 2: Create PostgreSQL Database

- [ ] Go to Render Dashboard → **Create** → **PostgreSQL**
- [ ] **Configuration**:
  - [ ] Name: `matrix-postgres`
  - [ ] Database: `matrix`
  - [ ] Username: `matrix`
  - [ ] Password: Generate a secure password [OpenSSL tool]
  - [ ] Region: Choose based on your location (e.g., us-east-1, eu-west-1)
  - [ ] PostgreSQL Version: 16 (latest)
  - [ ] Backup frequency: Daily
- [ ] Wait for database to initialize (5-10 minutes)
- [ ] Go to **Info** tab and copy:
  - [ ] **External Database URL**: Save as `DATABASE_URL`
  - Format should be: `postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix`
  - Convert to async format: `postgresql+asyncpg://matrix:PASSWORD@hostname.onrender.com:5432/matrix`

## Phase 3: Create Redis Cache

- [ ] Go to Render Dashboard → **Create** → **Redis**
- [ ] **Configuration**:
  - [ ] Name: `matrix-redis`
  - [ ] Region: **Same as PostgreSQL** (very important!)
  - [ ] Max Memory Policy: `allkeys-lru`
  - [ ] Pricing Plan: Free (or Starter if needed)
- [ ] Wait for Redis to initialize (3-5 minutes)
- [ ] Go to **Info** tab and copy:
  - [ ] **Redis URL**: Save as `REDIS_URL`
  - Format should be: `redis://default:PASSWORD@hostname.onrender.com:6379`

## Phase 4: Deploy Backend Service

- [ ] Go to Render Dashboard → **Create** → **Web Service**
- [ ] **Repository**:
  - [ ] Select your GitHub repository (Matrix)
- [ ] **Service Configuration**:
  - [ ] Name: `matrix-backend`
  - [ ] Region: **Same as PostgreSQL and Redis**
  - [ ] Root Directory: `backend`
  - [ ] Runtime: Docker
  - [ ] Branch: main (or your default branch)
- [ ] **Build & Deploy**:
  - [ ] Build command: (leave empty - Docker will handle)
  - [ ] Start command: (leave empty - Dockerfile will handle)

## Phase 5: Configure Environment Variables

Add these to your Render backend service (Dashboard → Service → Environment):

- [ ] **Database & Cache**:
  - [ ] `DATABASE_URL`: Your converted PostgreSQL URL (with asyncpg)
  - [ ] `REDIS_URL`: Your Redis URL from Phase 3

- [ ] **Security**:
  - [ ] `SECRET_KEY`: Generate random 32+ character string
  - [ ] `ALGORITHM`: HS256
  - [ ] `ACCESS_TOKEN_EXPIRE_MINUTES`: 10080

- [ ] **API Keys** (from your accounts):
  - [ ] `GROQ_API_KEY_SCANNER`: From [Groq Console](https://console.groq.com/keys)
  - [ ] `GROQ_API_KEY_REPO`: From [Groq Console](https://console.groq.com/keys)
  - [ ] `GROQ_API_KEY_CHATBOT`: From [Groq Console](https://console.groq.com/keys)
  - [ ] `GROQ_API_KEY_FALLBACK`: From [Groq Console](https://console.groq.com/keys)

- [ ] **GitHub Integration**:
  - [ ] `GITHUB_TOKEN`: From [GitHub Settings](https://github.com/settings/tokens)

- [ ] **Application Settings**:
  - [ ] `ENVIRONMENT`: production
  - [ ] `DEBUG`: false
  - [ ] `APP_NAME`: Matrix
  - [ ] `PORT`: 8080

- [ ] **CORS & URLs**:
  - [ ] `ALLOWED_ORIGINS`: Your Vercel frontend URL (e.g., https://matrix-xxxxx.vercel.app)

## Phase 6: Verify Deployment

- [ ] Watch build logs in Render dashboard (should complete in 5-15 minutes)
- [ ] Check service status turns **green**
- [ ] Visit your backend URL: `https://<your-service-name>.onrender.com`
- [ ] Test health endpoint: `https://<your-service-name>.onrender.com/health`
  - [ ] Should return: `{"status": "ok", "message": "Matrix API is operational"}`

## Phase 7: Run Database Migrations

### Option A: Using Render Shell (Recommended)

- [ ] Click **Shell** button in your backend service
- [ ] Run:
  ```bash
  cd /opt/render/project/backend  # or your backend path
  alembic upgrade head
  ```
- [ ] Verify no errors in output
- [ ] Exit shell

### Option B: Using One-Off Job

- [ ] Click **Create** → **One-Off Job**
- [ ] Configure same environment variables as web service
- [ ] Run migration command
- [ ] Verify completion

### Option C: Local Migration (If needed)

- [ ] Update local `.env` with Render DATABASE_URL:
  ```env
  DATABASE_URL=postgresql+asyncpg://matrix:PASSWORD@hostname.onrender.com:5432/matrix
  ```
- [ ] Run locally:
  ```bash
  cd backend
  alembic upgrade head
  ```
- [ ] Or add your local IP to Render PostgreSQL firewall

## Phase 8: Verify Database Connection

- [ ] In Render Shell, test database:
  ```bash
  psql postgresql://matrix:PASSWORD@hostname.onrender.com:5432/matrix -c "SELECT COUNT(*) FROM users;"
  ```
- [ ] Test Redis connection:
  ```bash
  python -c "import redis; r = redis.from_url('redis://default:PASSWORD@hostname.onrender.com:6379'); print(r.ping())"
  ```

## Phase 9: Deploy Frontend

- [ ] Deploy frontend on Vercel
- [ ] Add environment variable:
  - [ ] `NEXT_PUBLIC_API_URL`: Your Render backend URL (https://matrix-xxxxx.onrender.com)
- [ ] Test frontend → backend communication

## Phase 10: Final Testing

- [ ] Test user login/signup
- [ ] Test database operations
- [ ] Test file scanning
- [ ] Check Render logs for errors
- [ ] Verify Redis cache is working
- [ ] Monitor CPU/memory usage

## Rollback Plan (If Issues)

- [ ] Keep original Railway databases as backup
- [ ] If Render deployment fails, revert to Railway configuration
- [ ] Or create new Render databases and re-migrate

## Monitoring & Maintenance

- [ ] Set up alerts for service restarts
- [ ] Monitor PostgreSQL disk usage
- [ ] Monitor Redis memory usage
- [ ] Review logs weekly
- [ ] Enable automatic backups for PostgreSQL
- [ ] Test backup restoration monthly

## Notes

- **Region consistency**: All services must be in the same region for optimal performance
- **Free tier limits**: Monitor resource usage; upgrade if needed
- **Restart policies**: Configure auto-restart for failed services
- **SSL/HTTPS**: Enabled by default on Render
- **Database snapshots**: Take snapshots before major changes

## Troubleshooting

If deployment fails:

1. Check **Build Logs** in Render dashboard
2. Verify all environment variables are set
3. Ensure DATABASE_URL uses `postgresql+asyncpg://` format
4. Check PostgreSQL service is running (green status)
5. Check Redis service is running (green status)
6. Verify firewall rules allow connections
7. See [RENDER_DEPLOYMENT_GUIDE.md](RENDER_DEPLOYMENT_GUIDE.md) for detailed troubleshooting

## Useful Links

- [Render Documentation](https://render.com/docs)
- [PostgreSQL on Render](https://render.com/docs/databases)
- [Redis on Render](https://render.com/docs/redis)
- [Web Services on Render](https://render.com/docs/deploy-web-services)
- [Environment Variables](https://render.com/docs/environment-variables)
