const { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync,
  realpathSync, renameSync, unlinkSync, writeFileSync } = require('node:fs');
const { randomUUID } = require('node:crypto');
const { join } = require('node:path');

function privateDirectory(path) {
  try { mkdirSync(path, { mode: 0o700 }); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }

  const info = lstatSync(path);
  if (!info.isDirectory() || info.uid !== process.getuid() ||
      (info.mode & 0o7777) !== 0o700 || realpathSync(path) !== path)
    throw new Error('The preview needs an owner-only browser data directory.');
  return path;
}

function validAccount(label) {
  return typeof label === 'string' && /^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(label);
}

function validProfile(record) {
  if (!record || typeof record.site !== 'string' || !validAccount(record.account) ||
      typeof record.name !== 'string' || !record.name || record.name !== record.name.trim() ||
      record.name.length > 90 || /[\x00-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]/u.test(record.name)) return false;
  try {
    const site = new URL('https://' + record.site);
    return site.host === record.site && site.hostname === record.site &&
      site.href === 'https://' + record.site + '/' && !record.site.endsWith('.');
  } catch { return false; }
}

function profileId({ site, account }) { return site + '/' + account; }

function validateProfiles(records) {
  if (!Array.isArray(records) || records.length > 256 || !records.every(validProfile) ||
      new Set(records.map(profileId)).size !== records.length)
    throw new Error('The preview profile list is invalid or full.');
  return records.map(({ site, account, name }) => ({ site, account, name }));
}

function readProfiles(directory) {
  let handle;
  try { handle = openSync(join(directory, 'profiles.json'), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  try {
    const info = fstatSync(handle);
    if (!info.isFile() || info.uid !== process.getuid() || info.nlink !== 1 ||
        (info.mode & 0o7777) !== 0o600 || info.size > 256000)
      throw new Error('The preview profile list must be a private file.');
    const value = JSON.parse(readFileSync(handle, 'utf8'));
    if (value?.format !== 1) throw new Error('This preview profile list format is unsupported.');
    return validateProfiles(value.profiles);
  } finally { closeSync(handle); }
}

function writeProfiles(directory, records) {
  const data = JSON.stringify({ format: 1, profiles: validateProfiles(records) });
  const temporary = join(directory, '.profiles-' + randomUUID());
  writeFileSync(temporary, data + '\n', { flag: 'wx', mode: 0o600 });
  try { renameSync(temporary, join(directory, 'profiles.json')); }
  catch (error) { unlinkSync(temporary); throw error; }
}

module.exports = { privateDirectory, validAccount, profileId, readProfiles, writeProfiles };
