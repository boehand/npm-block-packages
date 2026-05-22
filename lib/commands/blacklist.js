const { output, META } = require('proc-log')
const Blacklist = require('../utils/blacklist.js')
const BaseCommand = require('../base-cmd.js')

class BlacklistCmd extends BaseCommand {
  static description = 'Inspect and refresh the compromised-packages blacklist consulted by `npm install`'
  static name = 'blacklist'
  static params = ['json']
  static usage = [
    'list',
    'update',
    'check <pkg>[@<version>] [<pkg>[@<version>] ...]',
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
}

module.exports = BlacklistCmd
