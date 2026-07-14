# Deploying CYBERNEXUS X

**Recommended:** a **single Render service** hosting both the API and the React
client (Express serves `client/dist` in production), plus **MongoDB Atlas** for
the database. One URL, no CORS. `render.yaml` is already in the repo.

> Account signups and the "click deploy" steps are yours to do (they need your
> credentials). Everything in the codebase is already deploy-ready.

## Quick path (single service)
1. **MongoDB Atlas** — see step 1 below; get a connection string.
2. **Render → New → Blueprint** → pick this repo. It reads `render.yaml` and
   provisions one web service that builds shared + client + server and serves
   everything from one URL.
3. Set `MONGODB_URI` in the Render dashboard (the only required secret;
   `JWT_SECRET` is auto-generated, `SERVE_CLIENT=true` is preset).
4. Open the service URL → register → done.

The split option (Render backend + Vercel static frontend, using `vercel.json`
and `VITE_API_URL`) is documented at the bottom as an alternative.

## 1. Database — MongoDB Atlas (~5 min)
1. Create a free **M0** cluster at https://cloud.mongodb.com.
2. **Database Access** → add a user (username + password).
3. **Network Access** → Add IP → **Allow access from anywhere** (`0.0.0.0/0`)
   so Render can connect.
4. **Connect → Drivers** → copy the connection string. It looks like:
   `mongodb+srv://<user>:<pass>@cluster0.xxxx.mongodb.net/cybernexus?retryWrites=true&w=majority`
   (add `/cybernexus` before the `?` to name the database).

## 2. Deploy on Render — single service (~5 min)
1. https://render.com → **New → Blueprint** → connect GitHub and pick this repo.
   Render reads `render.yaml` and provisions one web service (`cybernexus-x`)
   whose build runs `build:shared && build client && build server`, then starts
   `node server/dist/server.js` with `SERVE_CLIENT=true`.
2. Set the one required secret (marked `sync:false`):
   - `MONGODB_URI` = your Atlas string from step 1
   - `JWT_SECRET` is auto-generated; optionally add `ABUSEIPDB_API_KEY` /
     `VIRUSTOTAL_API_KEY` / `SMTP_*` for live integrations.
3. Deploy. Your whole app (UI + API) will be at `https://cybernexus-x.onrender.com`
   (or similar). Verify: `<url>/api/health` → `{"status":"ok",...}`, and open the
   root URL to see the dashboard.

> Render's free tier sleeps after ~15 min idle; the first request then takes
> ~50s to wake. Fine for a portfolio demo.

## 3. Create an admin (for the Compliance page)
The UI register creates an `analyst`. Once, hit the API to make an admin:
```bash
curl -X POST https://<your-url>/api/auth/register \
  -H "content-type: application/json" \
  -d '{"email":"you@example.com","password":"a-strong-pass","name":"Admin","role":"admin"}'
```

## Notes
- Secrets live only in the Render dashboard — never commit `.env`.
- Redeploys happen automatically on every push to `main`.

---

## Alternative: split deploy (Render backend + Vercel frontend)
Prefer an always-on CDN frontend? Host them separately instead:
1. **Render** backend: set `SERVE_CLIENT` to `false` (or remove it) and set
   `CLIENT_ORIGIN` to your Vercel URL.
2. **Vercel**: import the repo (reads `vercel.json`), set `VITE_API_URL` to the
   Render API URL. Deploy → `https://<project>.vercel.app`.
3. Back on Render, set `CLIENT_ORIGIN` to the Vercel URL and redeploy (CORS).
