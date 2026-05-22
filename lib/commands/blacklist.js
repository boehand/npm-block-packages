const { resolve } = require('node:path')
const { output, META } = require('proc-log')
const Blacklist = require('../utils/blacklist.js')
const { scanDirectory } = require('../utils/blacklist-scan.js')
const BaseCommand = require('../base-cmd.js')

class BlacklistCmd extends BaseCommand {
  static description = 'Inspect and refresh the compromised-packages blacklist consulted by `npm install`'
  static name = 'blacklist'
  static params = ['json']
  static usage = [
    'list',
    'update',
    'check <pkg>[@<version>] [<pkg>[@<version>] ...]',
    'scan [<dir>]',
  ]

  async exec (args) {
    const cmd = (args.shift() || 'list').toLowerCase()
    const blacklist = new Blacklist(this.npm)

    switch (cmd) {
      case 'ls':
      case 'list':
        await blacklist.load()
        return this.#list(blacklist)
      case 'update':
      case 'refresh':
        await blacklist.update({ force: true })
        return this.#summarize(blacklist, 'updated')
      case 'check':
        if (!args.length) {
          throw this.usageError('Provide at least one package spec to check.')
        }
        await blacklist.load()
        return this.#check(blacklist, args)
      case 'scan':
        await blacklist.load()
        return this.#scan(blacklist, args[0] || process.cwd())
      default:
        throw this.usageError(`Unknown blacklist subcommand: ${cmd}`)
    }
  }

  #list (blacklist) {
    const json = this.npm.config.get('json')
    const data = blacklist.data || { packages: {}, source: 'unknown', fetchedAt: 0 }

    if (json) {
      output.standard(JSON.stringify(data, null, 2), { [META]: true, redact: false })
      return
    }

    const packages = data.packages || {}
    const names = Object.keys(packages).sort()
    output.standard(`Source: ${data.source}`)
    output.standard(`Fetched: ${data.fetchedAt ? new Date(data.fetchedAt).toISOString() : 'never (bundled default)'}`)
    output.standard(`Entries: ${names.length}`)
    output.standard('')
    if (!names.length) {
      output.standard('No entries.')
      return
    }
    for (const name of names) {
      const entry = packages[name]
      const versions = Array.isArray(entry.versions)
        ? entry.versions.join(', ')
        : (entry.versions || '*')
      output.standard(`${name}  [${versions}]`)
      if (entry.reason) {
        output.standard(`  ${entry.reason}`)
      }
      if (entry.advisory) {
        output.standard(`  ${entry.advisory}`)
      }
    }
  }

  #summarize (blacklist, verb) {
    const json = this.npm.config.get('json')
    const data = blacklist.data || { packages: {}, source: 'unknown', fetchedAt: 0 }
    const count = Object.keys(data.packages || {}).length
    if (json) {
      output.standard(JSON.stringify({
        source: data.source,
        fetchedAt: data.fetchedAt,
        entries: count,
      }, null, 2), { [META]: true, redact: false })
      return
    }
    output.standard(`Blacklist ${verb}: ${count} entries from ${data.source}`)
  }

  #check (blacklist, args) {
    const json = this.npm.config.get('json')
    const results = args.map(arg => ({ arg, hit: blacklist.checkArg(arg) }))

    if (json) {
      output.standard(JSON.stringify(results, null, 2), { [META]: true, redact: false })
    } else {
      for (const { arg, hit } of results) {
        if (!hit) {
          output.standard(`${arg}: OK`)
        } else {
          output.standard(`${arg}: BLOCKED - ${hit.entry.reason || 'flagged'}`)
          if (hit.entry.advisory) {
            output.standard(`  ${hit.entry.advisory}`)
          }
        }
      }
    }

    if (results.some(r => r.hit)) {
      process.exitCode = 1
    }
  }

  async #scan (blacklist, dir) {
    const root = resolve(dir)
    const json = this.npm.config.get('json')
    const hits = await scanDirectory(root, blacklist)

    if (json) {
      output.standard(JSON.stringify({
        root,
        source: blacklist.data?.source,
        hits: hits.map(h => ({
          name: h.name,
          version: h.version,
          source: h.source,
          location: h.location,
          reason: h.entry?.reason,
          advisory: h.entry?.advisory,
        })),
      }, null, 2), { [META]: true, redact: false })
    } else if (!hits.length) {
      output.standard(`No blacklisted packages found under ${root}.`)
    } else {
      output.standard(`Found ${hits.length} blacklisted package install${hits.length === 1 ? '' : 's'} under ${root}:`)
      output.standard('')
      for (const h of hits) {
        output.standard(`  ${h.name}@${h.version}`)
        output.standard(`    at ${h.location}`)
        output.standard(`    via ${h.source}`)
        if (h.entry?.reason) {
          output.standard(`    ${h.entry.reason}`)
        }
        if (h.entry?.advisory) {
          output.standard(`    ${h.entry.advisory}`)
        }
        output.standard('')
      }
      output.standard('Future installs are guarded by the blacklist gate; for the hits above')
      output.standard('you need to rotate any secrets that may have been exposed and remove')
      output.standard('the installed copies (e.g. delete node_modules and reinstall).')
    }

    if (hits.length) {
      process.exitCode = 1
    }
  }
}

module.exports = BlacklistCmd
