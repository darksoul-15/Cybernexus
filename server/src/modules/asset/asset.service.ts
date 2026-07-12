import { AssetModel } from '../../models/Asset.js';
import { HttpError } from '../../middleware/error.js';
import { isTargetAuthorized } from '../../utils/ipScope.js';
import type { AssetType } from '@cybernexus/shared';

export interface CreateAssetInput {
  name: string;
  type: AssetType;
  ipAddress: string;
  hostname?: string;
  tags?: string[];
  authorizedForScan?: boolean;
}

export async function createAsset(ownerId: string, input: CreateAssetInput) {
  const scope = isTargetAuthorized(input.ipAddress);
  // An asset outside authorized ranges can exist, but can never be marked scannable.
  const authorizedForScan = Boolean(input.authorizedForScan) && scope.allowed;
  const asset = await AssetModel.create({
    ...input,
    ipAddress: scope.normalized,
    owner: ownerId,
    authorizedForScan,
  });
  return asset.toJSON();
}

export async function listAssets() {
  return AssetModel.find().sort({ riskScore: -1, createdAt: -1 }).lean();
}

export async function getAsset(id: string) {
  const asset = await AssetModel.findById(id);
  if (!asset) throw new HttpError(404, 'Asset not found');
  return asset.toJSON();
}

export async function deleteAsset(id: string) {
  const res = await AssetModel.findByIdAndDelete(id);
  if (!res) throw new HttpError(404, 'Asset not found');
}
