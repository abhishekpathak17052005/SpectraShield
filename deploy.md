# SpectraShield Deployment Guide: Vercel & Render

This guide walks you step-by-step through deploying **SpectraShield** into production:
- **Backend (FastAPI Engine)**: Deployed on **Render** as a Python Web Service.
- **Frontend (SOC Web Console)**: Deployed on **Vercel** as a high-performance React/Vite SPA.
- **Browser Extension**: Packaged and downloadable directly from your production web app (`/extension`).

---

## Architecture Overview

```
                        ┌───────────────────────────────┐
                        │   Chromium Browser Extension  │
                        │   (Manifest V3 / Gmail / DMs) │
                        └──────────────┬────────────────┘
                                       │ (HTTPS API Calls)
                                       ▼
┌─────────────────────────────┐        ┌─────────────────────────────┐
│       Vercel Frontend       │ =====> │        Render Backend       │
│  (React / Vite SOC Console) │ (REST) │  (FastAPI Security Engine)  │
│  https://your-app.vercel.app│        │ https://your-api.onrender.com
└─────────────────────────────┘        └──────────────┬──────────────┘
                                                      │ (Optional DB)
                                                      ▼
                                       ┌─────────────────────────────┐
                                       │   Supabase / Render Postgres│
                                       │   (or In-Memory Fallback)   │
                                       └─────────────────────────────┘
```

---

## Prerequisites Before Starting

1. A [GitHub](https://github.com) account with your SpectraShield repository pushed.
2. A free account on [Render](https://render.com).
3. A free account on [Vercel](https://vercel.com).
4. (Optional) A free PostgreSQL database on [Supabase](https://supabase.com) or Render PostgreSQL (in-memory mode works out of the box with zero setup).

---

## Step 1: Push Your Code to GitHub

Make sure your latest changes on the `deploy` branch are committed and pushed to GitHub:

```bash
# Verify status
git status

# Commit any pending files
git add .
git commit -m "chore(deploy): prepare vercel and render deployment configs"

# Push the deploy branch
git push -u origin deploy
```

> [!TIP]
> If you wish to merge `deploy` into `main` before deploying, run:
> ```bash
> git checkout main
> git merge deploy
> git push origin main
> ```

---

## Step 2: Deploy Backend on Render

Deploy the backend first so you have your live API URL ready for the frontend.

### Method A: Manual Web Service (Recommended)

1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** in the top right and select **Web Service**.
3. Choose **Build and deploy from a Git repository** and connect your GitHub repository (`SpectraShield`).
4. In the configuration form, fill in:
   - **Name**: `spectrashield-backend` (or your preferred name)
   - **Region**: Choose the region closest to your users (e.g., `Frankfurt`, `Oregon`, `Singapore`)
   - **Branch**: `main` (or `deploy`)
   - **Root Directory**: `backend` *(⚠️ Important: must be `backend`)*
   - **Runtime**: `Python 3`
   - **Build Command**:
     ```bash
     pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     uvicorn app.main:app --host 0.0.0.0 --port $PORT
     ```
   - **Instance Type**: `Free`

5. Scroll down to **Environment Variables** and add:

   | Key | Recommended Value | Purpose |
   | :--- | :--- | :--- |
   | `PYTHON_VERSION` | `3.11.9` | Python runtime version |
   | `DB_BACKEND` | `in-memory` *(or `supabase`)* | Database engine mode |
   | `JWT_SECRET` | *(Click "Generate" or random 32-char string)* | Auth tokens encryption |
   | `CORS_ORIGINS` | `https://spectrashield-tau.vercel.app` | Exact domain of your Vercel frontend |
   | `DATABASE_URL` | *(Optional: Your PostgreSQL URL)* | Persistent case storage |
   | `VT_API_KEY` | *(Optional: VirusTotal API Key)* | Real-time URL reputation |
   | `OPENPHISH_AUTO_SYNC`| `true` | Daily phishing feed sync |

6. Click **Create Web Service**.
7. Wait 2–4 minutes for the build to finish. Once live, Render gives you a URL like:
   ```
   https://spectrashield-backend.onrender.com
   ```
8. **Verify Backend**: Open `https://your-backend.onrender.com/health` in your browser. You should receive:
   ```json
   {
     "status": "healthy",
     "service": "SpectraShield 2.0 (Forensic Edition)",
     "version": "2.0.0-phase3",
     "engine": "active"
   }
   ```

---

## Step 3: Deploy Frontend on Vercel

With the backend URL in hand, deploy the Vite React frontend on Vercel.

1. Log in to the [Vercel Dashboard](https://vercel.com/dashboard).
2. Click **Add New...** > **Project**.
3. Select your `SpectraShield` repository and click **Import**.
4. In the **Configure Project** screen:
   - **Framework Preset**: `Vite` (automatically detected)
   - **Root Directory**: Click **Edit** and choose `frontend` *(⚠️ Crucial: Do not deploy repository root as frontend)*
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
   - **Install Command**: `npm install`
5. Expand the **Environment Variables** section:

   | Key | Value |
   | :--- | :--- |
   | `VITE_API_BASE_URL` | `https://spectrashield-backend.onrender.com` *(Your Render URL from Step 2, no trailing slash)* |

6. Click **Deploy**.
7. Vercel will build and deploy the application in under 60 seconds.
8. Once complete, you will receive your live domain, for example:
   ```
   https://spectrashield-tau.vercel.app
   ```

### Why SPA Routing Works on Vercel
The repository includes `frontend/vercel.json`:
```json
{
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```
This rewrite ensures client-side routes (`/overview`, `/investigations`, `/extension`, `/mail-intelligence`) will load seamlessly even when users refresh or share direct deep-links.

---

## Step 4: Finalize CORS & Domain Security

Once you deploy your frontend and obtain your exact Vercel production domain (e.g., `https://spectrashield-tau.vercel.app`):

1. Go back to your **Render Dashboard** > `spectrashield-backend` > **Environment**.
2. Set the `CORS_ORIGINS` variable to your **exact frontend URL**:
   ```
   https://spectrashield-tau.vercel.app
   ```
   *(If you have multiple domains or custom domains, separate them with commas, e.g. `https://spectrashield-tau.vercel.app,https://yourdomain.com`)*

> [!CAUTION]
> **Never use wildcard `https://*.vercel.app` in production CORS!**
> Anyone in the world can deploy a website on Vercel. If you whitelist `*.vercel.app`, any other user's malicious site on Vercel could execute cross-origin requests from a user's browser to your backend API. Always specify your exact domain.

3. Click **Save Changes**. Render will automatically apply the changes.

---

## Step 5: Test Your Deployed Application

1. **Dashboard & Workspaces**:
   - Open `https://spectrashield-tau.vercel.app/overview`.
   - Verify that the top right indicator shows **Engine Online** with a green status light.
   - Click through **Investigations**, **Threat Intelligence**, and **Settings**. Notice the sidebar stays fixed without reloading.

2. **Browser Extension Download**:
   - In your live frontend, click **Browser Extension** in the sidebar (or visit `https://spectrashield-tau.vercel.app/extension`).
   - Click **Download Extension (.zip)**.
   - Verify the download downloads `spectrashield-extension.zip`.

3. **Connecting the Browser Extension to Production**:
   - **Automatic (Recommended)**: When you download the extension zip from your live Vercel web console (`/extension`), the backend automatically packages it with your production Render API and Vercel URLs pre-configured.
   - **Interactive Switcher in Extension Popup**:
     - Click the SpectraShield icon in your browser toolbar.
     - Look at the top bar under the header: it displays **Target: Cloud (Vercel)** or **Target: Localhost (Dev)**.
     - Click **⚙️ Config** to switch between `☁️ Cloud` and `💻 Localhost`, or enter your custom Vercel domain. Click **Save**.
     - All Gmail badge clicks, LinkedIn triage buttons, and manual scans will immediately redirect to your live Vercel web console!

---

## Troubleshooting & FAQ

### 1. Render Free Tier "Spinning Up" (Cold Starts)
- On Render's free tier, backend instances sleep after 15 minutes of inactivity.
- The first request after sleep may take ~30–50 seconds to wake up.
- The frontend includes built-in retry logic and error boundaries, showing a *"Connecting to Engine"* badge until awake.
- **Tip**: To keep it continuously awake, configure a free monitoring ping (e.g., [UptimeRobot](https://uptimerobot.com) or [Cron-job.org](https://cron-job.org)) hitting `https://your-backend.onrender.com/health` every 10 minutes.

### 2. Mixed Content Errors (HTTP vs. HTTPS)
- Always use `https://` for `VITE_API_BASE_URL`. Modern browsers block insecure `http://` requests from an `https://` Vercel website.

### 3. Vercel Build Fails with "Cannot find module"
- Ensure the **Root Directory** on Vercel is set to `frontend`.
- Ensure Node version is 18.x or 20.x in Vercel project settings (General > Node.js Version).

### 4. Database Persistence with PostgreSQL
- To persist cases across Render restarts, provision a free PostgreSQL database on [Supabase](https://supabase.com) or [Neon](https://neon.tech).
- Paste the connection string into Render's `DATABASE_URL` environment variable:
  ```
  postgresql://postgres:password@db.supabase.co:5432/postgres
  ```
- SpectraShield will automatically initialize all tables on boot.
