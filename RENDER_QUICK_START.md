# Render Deployment - Quick Start (5 Steps)

Get your Matrix application running on Render in 30 minutes.

## Quick Summary

You're deploying:
- **PostgreSQL 16** → Render managed database
- **Redis** → Render managed cache
- **Backend API** → Render web service (using Docker)
- **Frontend** → Vercel (unchanged)

---

## Step 1: Create PostgreSQL (5 min)

1. Go to [render.com](https://render.com) → **Create** → **PostgreSQL**
2. Name: `matrix-postgres`
3. Database: `matrix`, User: `matrix`
4. Wait for status to be **green**
5. Copy the **External Database URL** → save it

**Expected URL format:**
```
postgresql://matrix:PASSWORD@<hostname>.onrender.com:5432/matrix
```

---

## Step 2: Create Redis (5 min)

1. Go to Render → **Create** → **Redis**
2. Name: `matrix-redis`
3. **IMPORTANT**: Select the same region as PostgreSQL
4. Max Memory Policy: `allkeys-lru`
5. Wait for status to be **green**
6. Copy the **Redis URL** → save it

**Expected URL format:**
```
redis://default:PASSWORD@<hostname>.onrender.com:6379
```

---

## Step 3: Deploy Backend (10 min)

1. Go to Render → **Create** → **Web Service**
2. Connect your GitHub repo (Matrix)
3. Configure:
   - Name: `matrix-backend`
   - Root Directory: `backend`
   - Runtime: `Docker`
   - **Same region as databases** ← Important!
4. Click **Create Web Service** → Wait for build (5-10 min)

---

## Step 4: Configure Environment Variables (5 min)

In Render backend service dashboard, add:

### Database & Cache
```env
DATABASE_URL=postgresql+asyncpg://matrix:PASSWORD@<hostname>.onrender.com:5432/matrix
REDIS_URL=redis://default:PASSWORD@<hostname>.onrender.com:6379
```

### Security & Credentials
```env
SECRET_KEY=your-random-32-char-string-here
GROQ_API_KEY_SCANNER=gsk_xxxxx
GROQ_API_KEY_REPO=gsk_xxxxx
GROQ_API_KEY_CHATBOT=gsk_xxxxx
GROQ_API_KEY_FALLBACK=gsk_xxxxx
GITHUB_TOKEN=ghp_xxxxx
```

### App Settings
```env
ENVIRONMENT=production
DEBUG=false
ALLOWED_ORIGINS=https://your-vercel-frontend.vercel.app
```

### Click **Save** and wait for redeploy

---

## Step 5: Run Database Migrations (5 min)

1. Go to your backend service → Click **Shell**
2. Run:
   ```bash
   cd backend
   alembic upgrade head
   ```
3. Wait for "INFO: Running upgrade(s)..." messages to complete
4. Exit shell

---

## Verify It Works ✓

### Test Backend Health
```
https://<your-backend>.onrender.com/health
```
Should return:
```json
{"status": "ok", "message": "Matrix API is operational"}
```

### Update Frontend
Add to Vercel environment variables:
```env
NEXT_PUBLIC_API_URL=https://<your-backend>.onrender.com
```

Redeploy frontend.

### Test End-to-End
1. Go to your frontend URL
2. Try logging in or creating a scan
3. Check backend logs for errors

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Database connection error | Check DATABASE_URL uses `postgresql+asyncpg://` (not `postgresql://`) |
| Redis connection error | Verify REDIS_URL includes the password and matches format: `redis://default:PASS@host:port` |
| Migration hanging | Check if PostgreSQL service is running (green status) and network is stable |
| Backend not starting | Check Service Logs tab for specific errors; verify all env vars are set |

---

## For Detailed Setup

See these documents:
- [RENDER_DEPLOYMENT_GUIDE.md](RENDER_DEPLOYMENT_GUIDE.md) - Complete guide with all options
- [RENDER_SETUP_CHECKLIST.md](RENDER_SETUP_CHECKLIST.md) - Interactive checklist
- [MAIN DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) - All deployment options

---

## Done! 🎉

Your Matrix application is now running on Render with managed PostgreSQL and Redis.

- **Next**: Monitor logs and set up backups
- **Questions**: Check the detailed guides above
- **Issues**: See Troubleshooting section in [RENDER_DEPLOYMENT_GUIDE.md](RENDER_DEPLOYMENT_GUIDE.md)
