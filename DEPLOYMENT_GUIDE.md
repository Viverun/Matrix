# Matrix Deployment Guide

This guide explains how to deploy the Matrix project. Choose your deployment platform:

### Platform Options
- **Option A**: Backend on Render + DBs on Railway + Frontend on Vercel
- **Option B**: Backend on Render + PostgreSQL on Render + Redis on Render + Frontend on Vercel (Recommended)

> **Recommendation**: Use **Option B** (Render for everything) for simplicity, better support, and more reliable infrastructure.

For **Option B**, see:
- [RENDER_DEPLOYMENT_GUIDE.md](RENDER_DEPLOYMENT_GUIDE.md) - Detailed step-by-step guide
- [RENDER_SETUP_CHECKLIST.md](RENDER_SETUP_CHECKLIST.md) - Interactive checklist to track progress

---

## 1. Backend Deployment (Render or Koyeb) - Combined Service

I have created a `Dockerfile` and `start.sh` so you can run the **Web Server** and **Background Worker** together in a single free service.

1. **Connect Repository**: Link your GitHub repository to [Render](https://render.com) or [Koyeb](https://www.koyeb.com).
2. **Create New Web Service**:
   - **Environment/Runtime**: Select **Docker**.
   - **Root Directory**: `backend` (If asked).
3. **Environment Variables**: Add these in the dashboard:
   - `DATABASE_URL`: Your Railway **External** Postgres URL (Must start with `postgresql+asyncpg://`). 
     > [!IMPORTANT]
     > Avoid URLs ending in `.railway.internal`. Use the **Public/External** URL provided in Railway settings.
   - `REDIS_URL`: Your Railway **External** Redis URL.
     > [!IMPORTANT]
     > Use the Public URL, NOT the one ending in `.railway.internal`.
   - `ALLOWED_ORIGINS`: Your Vercel URL.
   - `ENVIRONMENT`: `production`
   - `SECRET_KEY`: Random string.
   - `GROQ_API_KEY_SCANNER`: Your Key.
   - `GITHUB_TOKEN`: Your Token.
   - `PORT`: `8080` (Render/Koyeb usually set this automatically).

### ✅ Why this is better?
By using Docker, you only need **one free service** to run both the API and the worker, saving you from hitting plan limits.

### ✅ Backend Success Check
Visit: `https://<your-render-domain>/health`
You should see: `{"status": "ok", "message": "Matrix API is operational"}`

## 2. Frontend Deployment (Vercel)

1. **Connect Repository**: Link your GitHub repository to Vercel.
2. **Root Directory**: Set the root directory to `frontend`.
3. **Environment Variables**:
   - `NEXT_PUBLIC_API_URL`: Your Render Web Service URL (e.g., `https://matrix.onrender.com`).
4. **Deploy**: Vercel will automatically build and deploy.

## 3. Architecture Overview

```txt
User Browser
   ↓
Vercel (Dashboard)
   ↓ (API Calls)
Render (FastAPI + Workers)
   ↓ (Data)
Railway (Postgres + Redis)
```
