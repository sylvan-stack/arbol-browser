const { lstatSync, mkdirSync, realpathSync } = require('node:fs');

function privateDirectory(path) {
  try { mkdirSync(path, { mode: 0o700 }); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }

  const info = lstatSync(path);
  if (!info.isDirectory() || info.uid !== process.getuid() ||
      (info.mode & 0o7777) !== 0o700 || realpathSync(path) !== path)
    throw new Error('The preview needs an owner-only browser data directory.');
  return path;
}

module.exports = { privateDirectory };
