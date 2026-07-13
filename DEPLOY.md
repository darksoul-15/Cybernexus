# Deploying CYBERNEXUS X

Free-tier stack: **MongoDB Atlas** (database) · **Render** (backend API + Socket.io)
· **Vercel** (React frontend). All three have free tiers. The config files
(`render.yaml`, `vercel.json`) are already in the repo.

> The account signups and the "click deploy" steps are yours to do (they need
> your credentials). Everything in the codebase is already deploy-ready.

## 1. Database — MongoDB Atlas (~5 min)
1. Create a free **M0** cluster at https://cloud.mongodb.com.
2. **Database Access** → add a user (username + password).
3. **Network Access** → Add IP → **Allow access from anywhere** (`0.0.0.0/0`)
   so Render can connect.
4. **Connect → Drivers** → copy the connection string. It looks like:
   `mongodb+srv://<user>:<pass>@cluster0.xxxx.mongodb.net/cybernexus?retryWrites=true&w=majority`
   (add `/cybernexus` before the `?` to name the database).

## 2. Backend — Render (~5 min)
1. https://render.com → **New → Blueprint** → connect your GitHub and pick this repo.
   Render reads `render.yaml` and provisions the `cybernexus-api` web service.
2. When prompted, set the env vars marked "sync:false":
   - `MONGODB_URI` = your Atlas string from step 1
   - `CLIENT_ORIGIN` = your Vercel URL (fill after step 3, then redeploy)
   - `JWT_SECRET` is auto-generated; add `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY`
     only if you want live threat-intel.
3. Deploy. Your API will be at `https://cybernexus-api.onrender.com` (or similar).
   Verify: open `<api-url>/api/health` → `{"status":"ok",...}`.

> Render's free tier sleeps after ~15 min idle; the first request then takes
> ~50s to wake. Fine for a portfolio demo.

## 3. Frontend — Vercel (~3 min)
1. https://vercel.com → **Add New → Project** → import this repo.
   Vercel reads `vercel.json` (build command + output dir + SPA rewrites).
2. Add an **Environment Variable**:
   - `VITE_API_URL` = your Render API URL from step 2 (no trailing slash)
3. Deploy. Your app will be at `https://<project>.vercel.app`.

## 4. Close the loop (CORS)
1. Copy your Vercel URL, go back to Render → the service's **Environment** →
   set `CLIENT_ORIGIN` to it → save (triggers a redeploy).
2. Open the Vercel URL, register an account, and you're live.

## Notes
- Create an admin (for the Compliance page) by registering with role `admin` via
  the API once, or temporarily allow it in the UI.
- Secrets live only in the Render/Vercel dashboards — never commit `.env`.
- Redeploys happen automatically on every push to `main`.
