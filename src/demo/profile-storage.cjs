const { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync,
  realpathSync, renameSync, unlinkSync, writeFileSync } = require('node:fs');
const { createHash, randomUUID } = require('node:crypto');
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

function partitionKey({ site, account }) {
  return 'site-' + createHash('sha256').update(site).update('\0').update(account).digest('hex');
}

function existingPartition(directory, record) {
  const path = join(directory, partitionKey(record));
  const info = lstatSync(path);
  if (!info.isDirectory() || info.uid !== process.getuid() ||
      (info.mode & 0o7777) !== 0o700 || realpathSync(path) !== path)
    throw new Error('The saved preview partition is missing or unsafe.');
  return path;
}

function validateFormat2(directory, records) {
  const validated = validateProfiles(records);
  return validated.map((record, index) => {
    const partition = partitionKey(record);
    if (records[index].partition !== partition)
      throw new Error('The preview profile partition does not match its identity.');
    existingPartition(directory, record);
    return { ...record, partition };
  });
}

const legacyLimit = 256000;
const format2Limit = legacyLimit + 256 * 100;

function readPrivateFile(path, limit) {
  const handle = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = fstatSync(handle);
    if (!info.isFile() || info.uid !== process.getuid() || info.nlink !== 1 ||
        (info.mode & 0o7777) !== 0o600 || info.size > limit)
      throw new Error('The preview profile list must be a private bounded file.');
    return readFileSync(handle);
  } finally { closeSync(handle); }
}

function syncDirectory(directory) {
  const handle = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(handle); } finally { closeSync(handle); }
}

function stageFile(directory, data) {
  const path = join(directory, '.profiles-' + randomUUID());
  const handle = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(handle, data); fsyncSync(handle); }
  catch (error) { unlinkSync(path); throw error; }
  finally { closeSync(handle); }
  return path;
}

function convertProfiles(directory, original) {
  const value = JSON.parse(original.toString('utf8'));
  if (original.length > legacyLimit || value?.format !== 1)
    throw new Error('This preview profile list format is unsupported or too large.');
  const records = validateProfiles(value.profiles).map(record => ({ ...record, partition: partitionKey(record) }));
  validateFormat2(directory, records);
  const converted = Buffer.from(JSON.stringify({ format: 2, profiles: records }) + '\n');
  if (converted.length > format2Limit) throw new Error('The preview profile list is too large.');
  const backup = join(directory, 'profiles.format-1.before.json');
  let stagedBackup;
  try {
    try {
      if (!readPrivateFile(backup, legacyLimit).equals(original))
        throw new Error('The preview profile before-image conflicts with the current index.');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      stagedBackup = stageFile(directory, original);
      try { linkSync(stagedBackup, backup); }
      catch (linkError) {
        if (linkError.code !== 'EEXIST' || !readPrivateFile(backup, legacyLimit).equals(original)) throw linkError;
      }
      unlinkSync(stagedBackup);
      stagedBackup = null;
      syncDirectory(directory);
    }
    const stagedIndex = stageFile(directory, converted);
    try { syncDirectory(directory); renameSync(stagedIndex, join(directory, 'profiles.json')); }
    catch (error) { try { unlinkSync(stagedIndex); } catch {} throw error; }
    syncDirectory(directory);
  } finally { if (stagedBackup) try { unlinkSync(stagedBackup); } catch {} }
  return records;
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

module.exports = { privateDirectory, validAccount, profileId, partitionKey, existingPartition,
  validateFormat2, readPrivateFile, convertProfiles, readProfiles, writeProfiles };
