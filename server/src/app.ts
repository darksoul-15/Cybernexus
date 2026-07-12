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

  app.use(cors({ origin: env.clientOrigin, credentials: true }));
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

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
