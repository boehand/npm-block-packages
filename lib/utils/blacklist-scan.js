const { readdir, readFile, stat } = require('node:fs/promises')
const { join, relative, sep } = require('node:path')

// Dirs we don't descend into when walking the source tree.
const SKIP_DIRS = new Set([
  '.git', '.hg', '.svn', '.cache',
  '__pycache__', 'venv', '.venv',
  '.next', '.nuxt', 'dist', 'build', 'target',
])

const readJsonSafe = async (path) => {
  try {
    return JSON.parse(await readFile(path, 'utf8'))
  } catch {
    return null
  }
}

// Yield blacklist hits from a single package-lock.json (v1, v2, v3).
const scanLockfile = async function* (lockPath, blacklist) {
  const lock = await readJsonSafe(lockPath)
  if (!lock) {
    return
  }
  if (lock.packages && typeof lock.packages === 'object') {
    for (const [loc, info] of Object.entries(lock.packages)) {
      if (!loc || !info || typeof info !== 'object') {
        continue
      }
      // The key is e.g. "node_modules/lodash" or
      // "node_modules/foo/node_modules/lodash". The trailing segment is
      // the resolved package, scope included.
      const idx = loc.lastIndexOf('node_modules/')
      const name = info.name || (idx >= 0 ? loc.slice(idx + 'node_modules/'.length) : loc)
      const version = info.version
      if (!name || !version) {
        continue
      }
      const hit = blacklist.matchVersion(name, version)
      if (hit) {
        yield { name, version, source: lockPath, location: loc, entry: hit }
      }
    }
    return
  }
  if (lock.dependencies && typeof lock.dependencies === 'object') {
    yield* walkLegacyTree(lock.dependencies, lockPath, 'node_modules', blacklist)
  }
}

const walkLegacyTree = async function* (deps, lockPath, prefix, blacklist) {
  for (const [name, info] of Object.entries(deps)) {
    if (!info || typeof info !== 'object' || !info.version) {
      continue
    }
    const loc = `${prefix}/${name}`
    const hit = blacklist.matchVersion(name, info.version)
    if (hit) {
      yield { name, version: info.version, source: lockPath, location: loc, entry: hit }
    }
    if (info.dependencies && typeof info.dependencies === 'object') {
      yield* walkLegacyTree(info.dependencies, lockPath, `${loc}/node_modules`, blacklist)
    }
  }
}

// Yield blacklist hits from a node_modules directory. Only inspects the
// immediate children (with one level of recursion for `@scope/` dirs);
// nested `node_modules` inside each package are picked up by the outer
// tree walk.
const scanNodeModules = async function* (nmPath, blacklist) {
  let entries
  try {
    entries = await readdir(nmPath, { withFileTypes: true })
  } catch {
    return
  }
  for (const ent of entries) {
    if (!ent.isDirectory() || ent.name === '.bin' || ent.name === '.cache') {
      continue
    }
    if (ent.name.startsWith('@')) {
      yield* scanNodeModules(join(nmPath, ent.name), blacklist)
      continue
    }
    const pkgJson = join(nmPath, ent.name, 'package.json')
    const pkg = await readJsonSafe(pkgJson)
    if (!pkg?.name || !pkg?.version) {
      continue
    }
    const hit = blacklist.matchVersion(pkg.name, pkg.version)
    if (hit) {
      yield {
        name: pkg.name,
        version: pkg.version,
        source: pkgJson,
        location: join(nmPath, ent.name),
        entry: hit,
      }
    }
  }
}

// Walk the whole source tree. For each directory found, scan its
// package-lock.json and node_modules/ (if any). Subdirectories are
// recursed except for `node_modules` (handled separately) and the
// SKIP_DIRS list.
const walkTree = async function* (dir, blacklist) {
  let entries
  try {
    entries = await readdir(dir, { withFileTypes: true })
  } catch {
    return
  }

  if (entries.some(e => e.isFile() && e.name === 'package-lock.json')) {
    yield* scanLockfile(join(dir, 'package-lock.json'), blacklist)
  }
  if (entries.some(e => e.isDirectory() && e.name === 'node_modules')) {
    yield* scanNodeModules(join(dir, 'node_modules'), blacklist)
  }

  for (const ent of entries) {
    if (!ent.isDirectory()) {
      continue
    }
    if (ent.name === 'node_modules' || SKIP_DIRS.has(ent.name)) {
      continue
    }
    if (ent.name.startsWith('.')) {
      continue
    }
    yield* walkTree(join(dir, ent.name), blacklist)
  }
}

// Collect hits and dedupe. The same compromised package is often listed
// in both the lockfile and the on-disk node_modules; we count each
// (name, version, installed-path) once.
const scanDirectory = async (root, blacklist) => {
  const dedup = new Map()
  for await (const hit of walkTree(root, blacklist)) {
    const key = `${hit.name}@${hit.version}|${hit.location}`
    if (!dedup.has(key)) {
      dedup.set(key, hit)
    }
  }
  return [...dedup.values()].sort((a, b) => {
    if (a.name !== b.name) {
      return a.name < b.name ? -1 : 1
    }
    return a.version.localeCompare(b.version)
  })
}

module.exports = {
  scanDirectory,
  // exported for tests
  scanLockfile,
  scanNodeModules,
  walkTree,
}
