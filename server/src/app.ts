import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type Express } from 'express';
import cors from 'cors';
import { env } from './config/env.js';
import authRoutes from './modules/auth/auth.routes.js';
import assetRoutes from './modules/asset/asset.routes.js';
import vulnRoutes from './modules/vulnerability/vulnerability.routes.js';
import threatRoutes from './modules/threat/threat.routes.js';
import intelRoutes from './modules/intel/intel.routes.js';
import dashboardRoutes from './modules/dashboard/dashboard.routes.js';
import incidentRoutes from './modules/incident/incident.routes.js';
import evidenceRoutes from './modules/evidence/evidence.routes.js';
import complianceRoutes from './modules/compliance/compliance.routes.js';
import { notFound, errorHandler } from './middleware/error.js';

export function createApp(): Express {
  const app = express();

  // Same-origin when serving the client ourselves; else restrict to the SPA origin.
  app.use(cors({ origin: env.serveClient ? true : env.clientOrigin, credentials: true }));
  app.use(express.json());
  app.set('trust proxy', true);

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'cybernexus-x', time: new Date().toISOString() });
  });

  app.use('/api/auth', authRoutes);
  app.use('/api/assets', assetRoutes);
  app.use('/api/threats', threatRoutes);
  app.use('/api/intel', intelRoutes);
  app.use('/api/dashboard', dashboardRoutes);
  app.use('/api/incidents', incidentRoutes);
  app.use('/api/evidence', evidenceRoutes);
  app.use('/api/compliance', complianceRoutes);
  app.use('/api', vulnRoutes);

  // Single-service deploy: serve the built React client for non-API routes,
  // with SPA fallback so client-side routing works on refresh/deep links.
  if (env.serveClient) {
    // Resolve relative to this module (server/src or server/dist) → repo/client/dist,
    // so it works under tsx and compiled, independent of the working directory.
    const here = path.dirname(fileURLToPath(import.meta.url));
    const clientDist = path.resolve(here, '..', '..', 'client', 'dist');
    app.use(express.static(clientDist));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) return next();
      res.sendFile(path.join(clientDist, 'index.html'));
    });
  }

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
