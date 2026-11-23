import { validator } from '../contracts/schema.js';
import { parseStrictJson } from './strict-json.js';

/** Convert validated metadata only. Preserve values; never inspect engine data. */
export function convertProfileRecord(bytes: Uint8Array, id: string): Buffer {
  const record = parseStrictJson(bytes);
  if (!validator('profile.ProfileRecord')(record) || record.id !== id || !record.createdAt.endsWith('Z'))
    throw new Error('Invalid profile record');
  const converted = { ...record, format: 2 as const };
  if (!validator('profile2.ProfileRecord')(converted)) throw new Error('Invalid converted profile record');
  return Buffer.from(`${JSON.stringify(converted)}\n`, 'utf8');
}

export function convertEngineMarker(bytes: Uint8Array, profileInstance: string): Buffer {
  const marker = parseStrictJson(bytes);
  if (!validator('profile.EngineMarker')(marker) || marker.profileInstance !== profileInstance)
    throw new Error('Invalid engine marker');
  const converted = { ...marker, format: 2 as const };
  if (!validator('profile2.EngineMarker')(converted)) throw new Error('Invalid converted engine marker');
  return Buffer.from(`${JSON.stringify(converted)}\n`, 'utf8');
}
