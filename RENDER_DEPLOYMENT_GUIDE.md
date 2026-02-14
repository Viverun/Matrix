# Render Deployment Guide for Redis and PostgreSQL

This guide explains how to deploy PostgreSQL and Redis on Render, with your backend application.

## Architecture

```
User Browser
   ↓
Vercel (Frontend Dashboard)
   ↓ (API Calls)
Render (FastAPI Backend + Workers)
   ↓ (Data)
Render (PostgreSQL Database + Redis Cache)
```

## Step 1: Create PostgreSQL Database on Render

### 1. Navigate to Render Dashboard
1. Go to [render.com](https://render.com) and log in
2. Click on **Create** → **PostgreSQL**

### 2. Configure PostgreSQL
- **Name**: `matrix-postgres` (or your preference)
- **Database**: `matrix`
- **Username**: `matrix`
- **Region**: Select closest to your backend region
- **PostgreSQL Version**: 16 (latest stable)
- **Instance Type**: Free tier (for development/testing)

### 3. Copy Connection String
After creation, you'll see the **External Database URL**:
```
postgresql://matrix:<PASSWORD>@<HOSTNAME>:<PORT>/matrix
```

For async SQLAlchemy, convert it to:
```
postgresql+asyncpg://matrix:<PASSWORD>@<HOSTNAME>:<PORT>/matrix
```

**Save this value** - you'll need it for environment variables.

---

## Step 2: Create Redis Database on Render

### 1. Navigate to Render Dashboard
1. Go to **Create** → **Redis**

### 2. Configure Redis
- **Name**: `matrix-redis` (or your preference)
- **Region**: Same region as PostgreSQL (important for performance)
- **Max Memory Policy**: `allkeys-lru` (evict least recently used keys)
- **Instance Type**: Free tier

### 3. Copy Connection String
After creation, you'll see the **Redis URL**:
```
redis://default:<PASSWORD>@<HOSTNAME>:<PORT>
```

**Save this value** - you'll need it for environment variables.

---

## Step 3: Deploy Backend on Render

### 1. Create Web Service
1. Go to **Create** → **Web Service**
2. **Connect your GitHub repository**
3. Configure settings:
   - **Name**: `matrix-backend`
   - **Root Directory**: `backend`
   - **Runtime**: Docker
   - **Region**: Same as databases (important!)
   - **Branch**: main (or your default branch)

### 2. Add Environment Variables
In the Render dashboard, add these environment variables:

```env
# Database
DATABASE_URL=postgresql+asyncpg://matrix:<PASSWORD>@<HOSTNAME>:<PORT>/matrix

# Redis
REDIS_URL=redis://default:<PASSWORD>@<HOSTNAME>:<PORT>

# JWT & Security
SECRET_KEY=your-super-secret-key-minimum-32-characters
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=10080

# Application
DEBUG=false
ENVIRONMENT=production
APP_NAME=Matrix
PORT=8080

# API Keys
GROQ_API_KEY_SCANNER=gsk_xxxxxxxxxxxx
GROQ_API_KEY_REPO=gsk_xxxxxxxxxxxx
GROQ_API_KEY_CHATBOT=gsk_xxxxxxxxxxxx
GROQ_API_KEY_FALLBACK=gsk_xxxxxxxxxxxx

# GitHub
GITHUB_TOKEN=ghp_xxxxxxxxxxxx

# CORS - Update with your Vercel frontend URL
ALLOWED_ORIGINS=https://your-vercel-app.vercel.app
```

### 3. Deploy
- Click **Create Web Service**
- Render will automatically build and deploy your application
- Wait for deployment to complete (5-10 minutes typically)
- Check the logs for any errors

### 4. Verify Backend is Running
Once deployed, visit:
```
https://<your-render-app-url>.onrender.com/health
```

You should see:
```json
{"status": "ok", "message": "Matrix API is operational"}
```

---

## Step 4: Database Migration

### Option A: Run Migration via Render Shell (Recommended)

1. In your Render dashboard, go to **matrix-backend** service
2. Click on **Shell** (top right)
3. Run migration command:
   ```bash
   cd backend
   alembic upgrade head
   ```

### Option B: Create a One-Off Job (Advanced)

1. Go to your PostgreSQL service settings
2. Create a one-off job with your migration script
3. Connect it to your backend service and run migrations

### Option C: Manual Migration (Local)

If the above doesn't work, you can migrate locally:

1. Update your local `.env` with the Render database URL:
   ```env
   DATABASE_URL=postgresql+asyncpg://matrix:<PASSWORD>@<HOSTNAME>:<PORT>/matrix
   ```

2. Run migrations:
   ```bash
   cd backend
   alembic upgrade head
   ```

---

## Step 5: Update Frontend Configuration

In your Vercel and local `.env`:

```env
NEXT_PUBLIC_API_URL=https://<your-render-app-url>.onrender.com
```

---

## Important Notes

### ⚠️ Security
- Change `SECRET_KEY` to a random, strong value (minimum 32 characters)
- Never commit `.env` files with real secrets
- Use Render's environment variables, not hardcoded values
- Keep all API keys secure

### 🔗 Region Selection
- All services (PostgreSQL, Redis, Backend) should be in the same region for optimal performance
- Cross-region communication adds latency

### 💾 Backup Strategy
- Enable **Backups** for PostgreSQL on Render
- Set backup frequency to daily (default)
- Download backups regularly for safety

### 📊 Monitoring
- Monitor CPU and memory usage in Render dashboard
- Check logs for errors: **Service** → **Logs**
- Set up alerts for high resource usage

### 🚀 Scaling
- Free tier may not be sufficient for production
- Upgrade to paid plans if you experience:
  - Frequent service restarts
  - Slow response times
  - "Out of memory" errors

---

## Troubleshooting

### Database Connection Error
**Error**: `could not connect to server: Connection refused`

**Solution**:
- Verify DATABASE_URL is correct (no `.railway.internal` domains)
- Check if PostgreSQL service is running (green status in dashboard)
- Wait a few minutes after creating the database for it to initialize

### Redis Connection Error
**Error**: `Error: WRONGPASS invalid username-password pair`

**Solution**:
- Verify REDIS_URL includes the password
- Use default username if not specified: `redis://default:password@hostname:port`
- Check Redis service is running (green status)

### Migration Hanging
**Solution**:
- Check Render Shell timeout (usually 10 minutes)
- Run migrations in smaller batches if your database is large
- Check logs for specific errors

### Application Not Starting
**Solution**:
1. Check **Service Logs** in Render dashboard
2. Verify all environment variables are set
3. Confirm DATABASE_URL and REDIS_URL format
4. Check if Docker build succeeded

---

## Useful Render Commands

### SSH into Backend Service
```bash
# Once deployed, Render provides shell access
# Click "Shell" in the service dashboard
```

### View Logs
```
Service Dashboard → Logs (real-time streaming)
```

### Restart Service
```
Service Dashboard → Settings → Manual Deploy → Redeploy
```

### Reset Database
1. Go to PostgreSQL service
2. **Settings** → **Danger Zone** → **Delete Database**
3. Re-create and run migrations fresh

---

## Next Steps

1. ✅ Deploy PostgreSQL on Render
2. ✅ Deploy Redis on Render
3. ✅ Deploy Backend on Render
4. ✅ Run database migrations
5. ✅ Test backend health endpoint
6. ✅ Update Frontend with new API URL
7. ✅ Test end-to-end functionality

For additional help, visit [Render Documentation](https://render.com/docs).
