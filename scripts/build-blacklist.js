#!/usr/bin/env node
// Aggregates ossf/malicious-packages OSV files for the npm ecosystem into
// the compact `blocked.json` format consumed by `lib/utils/blacklist.js`.
//
// Usage:
//   node scripts/build-blacklist.js <ossf-checkout-dir> [<out-file>]
//
// Expects <ossf-checkout-dir> to be a working copy of
// https://github.com/ossf/malicious-packages. The CI workflow shallow-clones
// the repo before invoking this script.

const { readdir, readFile, writeFile, mkdir } = require('node:fs/promises')
const { join, dirname } = require('node:path')

const NPM_DIR = ['osv', 'malicious', 'npm']

const rangeFromEvents = (events) => {
  // OSV SEMVER `events` is a list of {introduced|fixed|last_affected} markers.
  // We translate the simple cases; anything else falls through to "*".
  let introduced = null
  let fixed = null
  for (const ev of events || []) {
    if (ev.introduced !== undefined) {
      introduced = ev.introduced
    }
    if (ev.fixed !== undefined) {
      fixed = ev.fixed
    }
  }
  if (introduced === '0' && fixed === null) {
    return '*'
  }
  if (introduced && fixed) {
    return `>=${introduced} <${fixed}`
  }
  if (introduced && introduced !== '0') {
    return `>=${introduced}`
  }
  return '*'
}

const advisoryUrl = (refs) => {
  if (!Array.isArray(refs)) {
    return null
  }
  return refs.find(r => r.type === 'ADVISORY')?.url
    || refs.find(r => r.type === 'REPORT')?.url
    || refs.find(r => r.type === 'ARTICLE')?.url
    || refs[0]?.url
    || null
}

const cleanSummary = (s) => {
  if (!s) {
    return null
  }
  // Strip OSSF "Per source details" appendix and excess whitespace.
  return s.split(/\n+_?-?=?\s*Per source details/i)[0].trim().slice(0, 240) || null
}

const mergeVersions = (existing, incoming) => {
  if (existing === '*' || incoming === '*') {
    return '*'
  }
  if (Array.isArray(existing) && Array.isArray(incoming)) {
    return [...new Set([...existing, ...incoming])].sort()
  }
  if (typeof existing === 'string' || typeof incoming === 'string') {
    // Mixed semver ranges and arrays - widen to "*" to be safe.
    return '*'
  }
  return existing || incoming
}

const collectAdvisory = async (filePath) => {
  let doc
  try {
    doc = JSON.parse(await readFile(filePath, 'utf8'))
  } catch {
    return []
  }
  const out = []
  for (const aff of doc.affected || []) {
    if (aff.package?.ecosystem !== 'npm' || !aff.package?.name) {
      continue
    }
    let versions
    if (Array.isArray(aff.versions) && aff.versions.length) {
      versions = aff.versions
    } else if (Array.isArray(aff.ranges) && aff.ranges.length) {
      const semverRange = aff.ranges.find(r => r.type === 'SEMVER')
      versions = semverRange ? rangeFromEvents(semverRange.events) : '*'
    } else {
      versions = '*'
    }
    out.push({
      name: aff.package.name,
      versions,
      reason: cleanSummary(doc.summary) || `Malicious code in ${aff.package.name}`,
      advisory: advisoryUrl(doc.references) || `https://osv.dev/vulnerability/${doc.id}`,
      id: doc.id,
    })
  }
  return out
}

const walkJson = async (dir) => {
  const out = []
  let entries
  try {
    entries = await readdir(dir, { withFileTypes: true })
  } catch {
    return out
  }
  for (const e of entries) {
    const p = join(dir, e.name)
    if (e.isDirectory()) {
      out.push(...await walkJson(p))
    } else if (e.isFile() && e.name.endsWith('.json')) {
      out.push(p)
    }
  }
  return out
}

const main = async () => {
  const checkout = process.argv[2]
  const outFile = process.argv[3] || 'blocked.json'
  if (!checkout) {
    process.stderr.write('usage: build-blacklist.js <ossf-checkout-dir> [<out>]\n')
    process.exit(2)
  }

  const npmRoot = join(checkout, ...NPM_DIR)
  const files = await walkJson(npmRoot)
  process.stderr.write(`scanning ${files.length} OSV file(s) under ${npmRoot}\n`)

  const merged = {}
  // First pass: per-package metadata, used only for the human-readable
  // companion file. The compact list drops everything but the versions.
  const meta = {}
  for (const file of files) {
    for (const entry of await collectAdvisory(file)) {
      const existing = merged[entry.name]
      if (!existing) {
        merged[entry.name] = entry.versions
        meta[entry.name] = { reason: entry.reason, advisory: entry.advisory }
        continue
      }
      merged[entry.name] = mergeVersions(existing, entry.versions)
      const m = meta[entry.name]
      if (m && (entry.reason?.length || 0) > (m.reason?.length || 0)) {
        m.reason = entry.reason
      }
      if (m && !m.advisory) {
        m.advisory = entry.advisory
      }
    }
  }

  const compact = {
    fetchedAt: Date.now(),
    source: 'https://github.com/ossf/malicious-packages',
    generatedAt: new Date().toISOString(),
    entries: Object.keys(merged).length,
    packages: merged,
  }

  await mkdir(dirname(outFile), { recursive: true }).catch(() => {})
  await writeFile(outFile, JSON.stringify(compact) + '\n')
  process.stderr.write(`wrote ${compact.entries} packages to ${outFile}\n`)

  // Companion file with reasons/advisories for humans browsing the branch.
  // Not consumed by the CLI in production (would inflate downloads ~7x).
  const verboseOut = outFile.replace(/\.json$/, '-verbose.json')
  const verbose = {
    ...compact,
    packages: Object.fromEntries(
      Object.entries(merged).map(([k, v]) => [k, { versions: v, ...meta[k] }])
    ),
  }
  await writeFile(verboseOut, JSON.stringify(verbose, null, 2) + '\n')
  process.stderr.write(`wrote verbose companion to ${verboseOut}\n`)
}

main().catch(err => {
  process.stderr.write(`build-blacklist failed: ${err.stack || err.message}\n`)
  process.exit(1)
})
