const { resolve, join, dirname } = require('node:path')
const { mkdir, readFile, writeFile } = require('node:fs/promises')
const { log } = require('proc-log')
const fetch = require('make-fetch-happen')
const semver = require('semver')
const npa = require('npm-package-arg')

const BUNDLED = require('./blacklist-default.json')

const DEFAULT_URL = 'https://raw.githubusercontent.com/npm/blocked-packages/main/blocked.json'
const DEFAULT_TTL_MS = 6 * 60 * 60 * 1000 // 6 hours
const FETCH_TIMEOUT_MS = 5000
const CACHE_FILE = 'blocked-packages.json'

class Blacklist {
  #npm
  #data = null

  constructor (npm) {
    this.#npm = npm
  }

  get url () {
    return process.env.NPM_BLACKLIST_URL ||
      this.#npm?.config?.get('blacklist-url') ||
      DEFAULT_URL
  }

  get ttl () {
    const fromEnv = Number(process.env.NPM_BLACKLIST_TTL)
    if (Number.isFinite(fromEnv) && fromEnv >= 0) {
      return fromEnv
    }
    const fromConfig = this.#npm?.config?.get('blacklist-ttl')
    if (Number.isFinite(fromConfig) && fromConfig >= 0) {
      return fromConfig
    }
    return DEFAULT_TTL_MS
  }

  get cachePath () {
    const cacheDir = this.#npm?.cache || join(process.cwd(), '.npm-cache')
    return join(cacheDir, 'blacklist', CACHE_FILE)
  }

  get data () {
    return this.#data
  }

  async load ({ force = false } = {}) {
    if (this.#data && !force) {
      return this.#data
    }
    await this.update({ force, silentErrors: true })
    return this.#data
  }

  async update ({ force = false, silentErrors = false } = {}) {
    const now = Date.now()

    let cached = null
    try {
      cached = JSON.parse(await readFile(this.cachePath, 'utf8'))
    } catch {
      // no cache yet, that's fine
    }

    const isFresh = cached?.fetchedAt && (now - cached.fetchedAt) < this.ttl
    if (!force && isFresh) {
      this.#data = cached
      return this.#data
    }

    try {
      const res = await fetch(this.url, {
        retry: false,
        timeout: FETCH_TIMEOUT_MS,
        headers: { accept: 'application/json' },
      })
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`)
      }
      const body = await res.json()
      const packages = body.packages || body
      const fresh = {
        fetchedAt: now,
        source: this.url,
        packages,
      }
      await mkdir(dirname(this.cachePath), { recursive: true })
      await writeFile(this.cachePath, JSON.stringify(fresh, null, 2))
      log.verbose('blacklist', `updated from ${this.url} (${Object.keys(packages).length} entries)`)
      this.#data = fresh
      return this.#data
    } catch (err) {
      log.verbose('blacklist', `update failed: ${err.message}`)
      if (cached) {
        this.#data = cached
        return this.#data
      }
      if (!silentErrors && force) {
        throw err
      }
      this.#data = { ...BUNDLED, fetchedAt: 0, source: 'bundled-default' }
      return this.#data
    }
  }

  list () {
    return this.#data?.packages || {}
  }

  // Match a concrete (name, version) against the blacklist
  matchVersion (name, version) {
    if (!this.#data || !name) {
      return null
    }
    const entry = this.#data.packages[name]
    if (!entry) {
      return null
    }
    const versions = entry.versions
    if (!versions || versions === '*') {
      return entry
    }
    if (Array.isArray(versions)) {
      if (versions.includes('*')) {
        return entry
      }
      if (version && versions.includes(version)) {
        return entry
      }
      if (version) {
        for (const v of versions) {
          if (this.#rangeMatches(v, version)) {
            return entry
          }
        }
      }
      return null
    }
    if (typeof versions === 'string' && version) {
      return this.#rangeMatches(versions, version) ? entry : null
    }
    return null
  }

  #rangeMatches (range, version) {
    try {
      if (semver.valid(range) && semver.valid(version)) {
        return semver.eq(range, version)
      }
      return semver.satisfies(version, range, { includePrerelease: true })
    } catch {
      return range === version
    }
  }

  // Check an install argument (e.g. "lodash@1.2.3" or "react") and decide
  // whether installing it would be blocked.
  checkArg (arg) {
    if (!this.#data || !arg) {
      return null
    }
    let parsed
    try {
      parsed = npa(arg)
    } catch {
      return null
    }
    const name = parsed.name
    if (!name) {
      return null
    }
    const entry = this.#data.packages[name]
    if (!entry) {
      return null
    }

    if (parsed.type === 'version') {
      const hit = this.matchVersion(name, parsed.fetchSpec)
      return hit ? { name, version: parsed.fetchSpec, entry: hit, raw: arg } : null
    }

    // For tags, ranges, or unspecified specs, we don't yet know the resolved
    // version. The tree walk after buildIdealTree will catch concrete cases.
    // We still flag the package here when *all* versions are blocked so the
    // user gets feedback immediately.
    const versions = entry.versions
    if (!versions || versions === '*' || (Array.isArray(versions) && versions.includes('*'))) {
      return { name, entry, raw: arg }
    }
    return null
  }

  // Walk a built Arborist ideal tree and collect every package blocked by
  // the blacklist (including transitive deps).
  checkTree (idealTree) {
    const hits = []
    if (!idealTree?.inventory || !this.#data) {
      return hits
    }
    for (const node of idealTree.inventory.values()) {
      if (!node.package || !node.package.name) {
        continue
      }
      if (node.isProjectRoot || node.isWorkspace) {
        continue
      }
      const hit = this.matchVersion(node.package.name, node.package.version)
      if (hit) {
        hits.push({
          name: node.package.name,
          version: node.package.version,
          location: node.location,
          entry: hit,
        })
      }
    }
    return hits
  }
}

Blacklist.formatHit = (hit) => {
  const reason = hit.entry?.reason || 'flagged as compromised'
  const advisory = hit.entry?.advisory ? ` (${hit.entry.advisory})` : ''
  const v = hit.version ? `@${hit.version}` : ''
  const loc = hit.location ? ` at ${hit.location}` : ''
  return `  - ${hit.name}${v}${loc}: ${reason}${advisory}`
}

Blacklist.buildBlockedError = (hits, source) => {
  const lines = [
    `npm blocked the install because ${hits.length} package${hits.length === 1 ? ' is' : 's are'} on the compromised-packages blacklist:`,
    '',
    ...hits.map(Blacklist.formatHit),
    '',
    `Blacklist source: ${source}`,
    'Override at your own risk with --allow-blocked.',
  ]
  const err = new Error(lines.join('\n'))
  err.code = 'EBLOCKED'
  err.blocked = hits
  return err
}

module.exports = Blacklist
