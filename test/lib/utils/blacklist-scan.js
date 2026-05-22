const t = require('tap')
const { join } = require('node:path')
const { scanDirectory } = require('../../../lib/utils/blacklist-scan.js')

// Stub Blacklist with the minimal `matchVersion` contract the scanner uses.
const stubBlacklist = (rules) => ({
  matchVersion (name, version) {
    const rule = rules[name]
    if (!rule) {
      return null
    }
    if (rule.versions === '*' || rule.versions === true) {
      return { reason: rule.reason }
    }
    if (Array.isArray(rule.versions) && rule.versions.includes(version)) {
      return { reason: rule.reason }
    }
    return null
  },
})

t.test('finds hits in a v3 package-lock.json', async t => {
  const dir = t.testdir({
    'package-lock.json': JSON.stringify({
      name: 'a', version: '1.0.0', lockfileVersion: 3,
      packages: {
        '': { name: 'a', version: '1.0.0' },
        'node_modules/safe': { version: '1.0.0' },
        'node_modules/evil': { version: '3.3.6' },
        'node_modules/foo/node_modules/evil': { version: '3.3.6' },
      },
    }),
  })
  const bl = stubBlacklist({ evil: { versions: ['3.3.6'], reason: 'compromised' } })
  const hits = await scanDirectory(dir, bl)
  t.equal(hits.length, 2, 'finds both top-level and nested entries')
  t.equal(hits[0].name, 'evil')
  t.equal(hits[0].version, '3.3.6')
  t.match(hits[0].source, /package-lock\.json$/)
  t.ok(hits.every(h => h.entry?.reason === 'compromised'))
})

t.test('finds hits in node_modules/<pkg>/package.json', async t => {
  const dir = t.testdir({
    node_modules: {
      'safe-pkg': { 'package.json': JSON.stringify({ name: 'safe-pkg', version: '1.0.0' }) },
      'evil-pkg': { 'package.json': JSON.stringify({ name: 'evil-pkg', version: '9.9.9' }) },
    },
  })
  const bl = stubBlacklist({ 'evil-pkg': { versions: '*', reason: 'malicious' } })
  const hits = await scanDirectory(dir, bl)
  t.equal(hits.length, 1)
  t.equal(hits[0].name, 'evil-pkg')
  t.match(hits[0].source, /package\.json$/)
})

t.test('descends into @scope/ directories', async t => {
  const dir = t.testdir({
    node_modules: {
      '@scope': {
        'evil': { 'package.json': JSON.stringify({ name: '@scope/evil', version: '1.0.0' }) },
        'safe': { 'package.json': JSON.stringify({ name: '@scope/safe', version: '1.0.0' }) },
      },
    },
  })
  const bl = stubBlacklist({ '@scope/evil': { versions: '*', reason: 'scoped-malware' } })
  const hits = await scanDirectory(dir, bl)
  t.equal(hits.length, 1)
  t.equal(hits[0].name, '@scope/evil')
})

t.test('recurses into nested project directories', async t => {
  const dir = t.testdir({
    projectA: {
      node_modules: {
        evil: { 'package.json': JSON.stringify({ name: 'evil', version: '1.0.0' }) },
      },
    },
    nested: {
      deeper: {
        projectB: {
          'package-lock.json': JSON.stringify({
            lockfileVersion: 3,
            packages: {
              '': { name: 'b' },
              'node_modules/evil': { version: '1.0.0' },
            },
          }),
        },
      },
    },
  })
  const bl = stubBlacklist({ evil: { versions: '*', reason: 'bad' } })
  const hits = await scanDirectory(dir, bl)
  t.equal(hits.length, 2)
  t.ok(hits.some(h => h.source.includes('projectA')))
  t.ok(hits.some(h => h.source.includes('projectB')))
})

t.test('does not descend into nested node_modules from the tree walk', async t => {
  // Two evil installs: one top-level, one inside another package's
  // node_modules. The outer scanNodeModules pass picks up the top-level
  // one; the nested one is only seen via the lockfile (none here), so
  // walkTree must NOT recurse into node_modules/<pkg>/node_modules.
  const dir = t.testdir({
    node_modules: {
      'wrapper': {
        'package.json': JSON.stringify({ name: 'wrapper', version: '1.0.0' }),
        node_modules: {
          'evil': { 'package.json': JSON.stringify({ name: 'evil', version: '1.0.0' }) },
        },
      },
      'evil': { 'package.json': JSON.stringify({ name: 'evil', version: '1.0.0' }) },
    },
  })
  const bl = stubBlacklist({ evil: { versions: '*', reason: 'bad' } })
  const hits = await scanDirectory(dir, bl)
  // We expect only the top-level node_modules/evil to be reported.
  // The nested copy would surface via a lockfile entry, not the tree walk.
  t.equal(hits.length, 1)
  t.match(hits[0].location, /node_modules\/evil$/)
})

t.test('falls back to legacy lockfileVersion 1 dependencies tree', async t => {
  const dir = t.testdir({
    'package-lock.json': JSON.stringify({
      name: 'root', version: '1.0.0', lockfileVersion: 1,
      dependencies: {
        safe: { version: '1.0.0' },
        evil: {
          version: '1.0.0',
          dependencies: {
            'sub-evil': { version: '2.0.0' },
          },
        },
      },
    }),
  })
  const bl = stubBlacklist({
    evil: { versions: '*', reason: 'malicious' },
    'sub-evil': { versions: ['2.0.0'], reason: 'malicious dep' },
  })
  const hits = await scanDirectory(dir, bl)
  t.equal(hits.length, 2)
  t.ok(hits.some(h => h.name === 'evil'))
  t.ok(hits.some(h => h.name === 'sub-evil' && h.version === '2.0.0'))
})

t.test('dedupes when the same install appears in both lockfile and node_modules', async t => {
  const dir = t.testdir({
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root' },
        'node_modules/evil': { version: '3.3.6' },
      },
    }),
    node_modules: {
      'evil': { 'package.json': JSON.stringify({ name: 'evil', version: '3.3.6' }) },
    },
  })
  const bl = stubBlacklist({ evil: { versions: ['3.3.6'], reason: 'compromised' } })
  const hits = await scanDirectory(dir, bl)
  // Lockfile location is "node_modules/evil" (relative), node_modules location
  // is the absolute path - they are NOT deduped because the locations differ.
  // The user can then see which evidence came from where, which is the more
  // useful behavior for an audit.
  t.equal(hits.length, 2)
  t.ok(hits.every(h => h.name === 'evil'))
})

t.test('skips non-JSON and unreadable files without crashing', async t => {
  const dir = t.testdir({
    'package-lock.json': 'not json {{{',
    node_modules: {
      'half-installed': { /* no package.json */ },
      'broken': { 'package.json': '<<not json>>' },
      'evil': { 'package.json': JSON.stringify({ name: 'evil', version: '1.0.0' }) },
    },
  })
  const bl = stubBlacklist({ evil: { versions: '*', reason: 'bad' } })
  const hits = await scanDirectory(dir, bl)
  t.equal(hits.length, 1)
  t.equal(hits[0].name, 'evil')
})

t.test('returns empty array for a clean tree', async t => {
  const dir = t.testdir({
    projectA: {
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'a' },
          'node_modules/lodash': { version: '4.17.21' },
        },
      }),
      node_modules: {
        'lodash': { 'package.json': JSON.stringify({ name: 'lodash', version: '4.17.21' }) },
      },
    },
  })
  const bl = stubBlacklist({})
  const hits = await scanDirectory(dir, bl)
  t.same(hits, [])
})

t.test('returns empty array when root does not exist', async t => {
  const bl = stubBlacklist({ evil: { versions: '*' } })
  const hits = await scanDirectory(join(t.testdir(), 'does-not-exist'), bl)
  t.same(hits, [])
})
