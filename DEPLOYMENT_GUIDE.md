# Matrix Deployment Guide

This guide explains how to deploy the Matrix project with the **Backend on Render**, **DBs on Railway**, and **Frontend on Vercel**.

## 1. Backend Deployment (Render or Koyeb) - Combined Service

I have created a `Dockerfile` and `start.sh` so you can run the **Web Server** and **Background Worker** together in a single free service.

1. **Connect Repository**: Link your GitHub repository to [Render](https://render.com) or [Koyeb](https://www.koyeb.com).
2. **Create New Web Service**:
   - **Environment/Runtime**: Select **Docker**.
   - **Root Directory**: `backend` (If asked).
3. **Environment Variables**: Add these in the dashboard:
   - `DATABASE_URL`: Your Railway Postgres (e.g. `postgresql+asyncpg://...`)
   - `REDIS_URL`: Your Railway Redis (e.g. `redis://...`)
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
