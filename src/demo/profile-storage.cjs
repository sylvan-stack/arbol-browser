const { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync,
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

function readPrivateFile(path, limit, links = 1) {
  const handle = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = fstatSync(handle);
    if (!info.isFile() || info.uid !== process.getuid() || info.nlink !== links ||
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

function recoverLinkedBackup(directory, backup, original) {
  let info;
  try { info = lstatSync(backup); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (info.nlink !== 2) return;
  if (!readPrivateFile(backup, legacyLimit, 2).equals(original))
    throw new Error('The preview profile before-image conflicts with the current index.');
  const matches = readdirSync(directory).filter(name =>
    /^\.profiles-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(name)).filter(name => {
    const candidate = lstatSync(join(directory, name));
    return candidate.isFile() && candidate.dev === info.dev && candidate.ino === info.ino;
  });
  if (matches.length !== 1) throw new Error('The preview profile before-image is unsafe.');
  unlinkSync(join(directory, matches[0]));
  syncDirectory(directory);
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
  recoverLinkedBackup(directory, backup, original);
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
  let data;
  try { data = readPrivateFile(join(directory, 'profiles.json'), format2Limit); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    if (readdirSync(directory).length !== 0)
      throw new Error('The preview profile index is missing from a nonempty store; recovery is required.');
    writeProfiles(directory, []);
    return [];
  }
  const value = JSON.parse(data.toString('utf8'));
  if (value?.format === 1) return convertProfiles(directory, data);
  if (value?.format !== 2) throw new Error('This preview profile list format is unsupported.');
  return validateFormat2(directory, value.profiles);
}

function createMarker(path, token) {
  const handle = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(handle, token); fsyncSync(handle); } finally { closeSync(handle); }
}

function createPartition(directory, record, records) {
  validateProfiles(records);
  const key = partitionKey(record);
  const path = join(directory, key);
  const intent = join(directory, '.creating-' + key);
  const marker = join(path, '.arbol-preview-creation');
  let token;
  try { token = readPrivateFile(intent, 128).toString('utf8'); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    try { lstatSync(path); throw new Error('An unexplained preview partition requires recovery.'); }
    catch (missing) { if (missing.code !== 'ENOENT') throw missing; }
    token = randomUUID();
    createMarker(intent, token);
    syncDirectory(directory);
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(token))
    throw new Error('The preview creation record is unsafe.');
  try { lstatSync(path); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const staged = join(directory, '.new-partition-' + randomUUID());
    mkdirSync(staged, { mode: 0o700 });
    createMarker(join(staged, '.arbol-preview-creation'), token);
    syncDirectory(staged);
    syncDirectory(directory);
    // The exclusive preview store lock serializes all legitimate writers.
    // Refuse an existing target instead of adopting it.
    try { lstatSync(path); throw new Error('An unexplained preview partition requires recovery.'); }
    catch (missing) { if (missing.code !== 'ENOENT') throw missing; }
    renameSync(staged, path);
    syncDirectory(directory);
  }
  existingPartition(directory, record);
  const entries = readdirSync(path);
  if (entries.length !== 1 || entries[0] !== '.arbol-preview-creation' ||
      readPrivateFile(marker, 128).toString('utf8') !== token)
    throw new Error('The interrupted preview partition is unexplained or not empty; recovery is required.');
  return path;
}

function finishPartitionCreation(directory, record) {
  const key = partitionKey(record);
  const path = existingPartition(directory, record);
  const intent = join(directory, '.creating-' + key);
  const marker = join(path, '.arbol-preview-creation');
  const token = readPrivateFile(intent, 128);
  if (!readPrivateFile(marker, 128).equals(token))
    throw new Error('The preview creation record does not match its partition.');
  unlinkSync(marker);
  syncDirectory(path);
  unlinkSync(intent);
  syncDirectory(directory);
}

function writeProfiles(directory, records) {
  const data = Buffer.from(JSON.stringify({ format: 2, profiles: validateFormat2(directory, records) }) + '\n');
  if (data.length > format2Limit) throw new Error('The preview profile list is too large.');
  const temporary = stageFile(directory, data);
  try { syncDirectory(directory); renameSync(temporary, join(directory, 'profiles.json')); }
  catch (error) { try { unlinkSync(temporary); } catch {} throw error; }
  syncDirectory(directory);
}

module.exports = { privateDirectory, validAccount, profileId, partitionKey, existingPartition,
  validateFormat2, readPrivateFile, convertProfiles, createPartition, finishPartitionCreation, readProfiles, writeProfiles };
