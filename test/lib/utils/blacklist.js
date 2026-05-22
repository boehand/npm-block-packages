const t = require('tap')
const { join } = require('node:path')
const { mkdir, writeFile } = require('node:fs/promises')

const Blacklist = require('../../../lib/utils/blacklist.js')

// These tests drive the module directly and must not pick up the
// `NPM_BLACKLIST_DISABLED` flag set by the mock-npm fixture in sibling tests.
t.beforeEach(() => { delete process.env.NPM_BLACKLIST_DISABLED })

const fakeRemote = (response, { fail = false } = {}) => async () => {
  if (fail) {
    throw new Error('network down')
  }
  return {
    ok: response.ok ?? true,
    status: response.status ?? 200,
    json: async () => response.body,
  }
}

const makeNpm = (cache, overrides = {}) => ({
  cache,
  config: {
    get: (key) => overrides[key],
  },
})

t.test('falls back to bundled default when fetch fails and no cache', async t => {
  const cache = t.testdir()
  const npm = makeNpm(cache)
  const bl = new Blacklist(npm)
  // patch fetch dependency
  const Module = require('node:module')
  const originalResolve = Module._resolveFilename
  t.teardown(() => { Module._resolveFilename = originalResolve })

  // Without monkey-patching transports we just rely on the bundled default
  // by pointing the URL at an unreachable host.
  process.env.NPM_BLACKLIST_URL = 'http://127.0.0.1:1/should-not-exist.json'
  t.teardown(() => { delete process.env.NPM_BLACKLIST_URL })

  await bl.load()
  t.ok(bl.data, 'data populated')
  t.equal(bl.data.source, 'bundled-default')
  t.ok(Object.keys(bl.data.packages).length > 0, 'has bundled entries')
})

t.test('uses fresh cache without hitting the network', async t => {
  const cache = t.testdir()
  const cachePath = join(cache, 'blacklist', 'blocked-packages.json')
  await mkdir(join(cache, 'blacklist'), { recursive: true })
  const cached = {
    fetchedAt: Date.now(),
    source: 'test-cache',
    packages: {
      'evil-pkg': { versions: '*', reason: 'test' },
    },
  }
  await writeFile(cachePath, JSON.stringify(cached))

  process.env.NPM_BLACKLIST_URL = 'http://127.0.0.1:1/never.json'
  t.teardown(() => { delete process.env.NPM_BLACKLIST_URL })

  const npm = makeNpm(cache)
  const bl = new Blacklist(npm)
  await bl.load()

  t.equal(bl.data.source, 'test-cache')
  t.ok(bl.matchVersion('evil-pkg', '1.2.3'), 'star match works')
})

t.test('matchVersion handles arrays, ranges and wildcards', async t => {
  const cache = t.testdir()
  const cachePath = join(cache, 'blacklist', 'blocked-packages.json')
  await mkdir(join(cache, 'blacklist'), { recursive: true })
  await writeFile(cachePath, JSON.stringify({
    fetchedAt: Date.now(),
    source: 'test',
    packages: {
      'exact-pkg': { versions: ['1.0.0', '2.0.0'] },
      'range-pkg': { versions: '>=1.0.0 <2.0.0' },
      'star-pkg': { versions: '*' },
      'wild-array': { versions: ['*'] },
    },
  }))

  const bl = new Blacklist(makeNpm(cache))
  await bl.load()

  t.ok(bl.matchVersion('exact-pkg', '1.0.0'))
  t.ok(bl.matchVersion('exact-pkg', '2.0.0'))
  t.notOk(bl.matchVersion('exact-pkg', '3.0.0'))

  t.ok(bl.matchVersion('range-pkg', '1.5.0'))
  t.notOk(bl.matchVersion('range-pkg', '2.0.0'))

  t.ok(bl.matchVersion('star-pkg', '0.0.1'))
  t.ok(bl.matchVersion('wild-array', '9.9.9'))

  t.notOk(bl.matchVersion('unknown-pkg', '1.0.0'))
})

t.test('checkArg blocks exact versions and all-versions entries', async t => {
  const cache = t.testdir()
  const cachePath = join(cache, 'blacklist', 'blocked-packages.json')
  await mkdir(join(cache, 'blacklist'), { recursive: true })
  await writeFile(cachePath, JSON.stringify({
    fetchedAt: Date.now(),
    source: 'test',
    packages: {
      'malware': { versions: '*', reason: 'malicious' },
      'pinned': { versions: ['9.9.9'] },
    },
  }))

  const bl = new Blacklist(makeNpm(cache))
  await bl.load()

  t.ok(bl.checkArg('malware'), 'name-only with all-versions blocked')
  t.ok(bl.checkArg('malware@1.0.0'))
  t.notOk(bl.checkArg('pinned'), 'name-only with partial blocklist passes through')
  t.ok(bl.checkArg('pinned@9.9.9'))
  t.notOk(bl.checkArg('pinned@1.0.0'))
  t.notOk(bl.checkArg('safe-pkg@1.0.0'))
  t.notOk(bl.checkArg(''))
})

t.test('checkTree walks an ideal tree inventory', async t => {
  const cache = t.testdir()
  const cachePath = join(cache, 'blacklist', 'blocked-packages.json')
  await mkdir(join(cache, 'blacklist'), { recursive: true })
  await writeFile(cachePath, JSON.stringify({
    fetchedAt: Date.now(),
    source: 'test',
    packages: {
      'bad-dep': { versions: ['1.0.0'], reason: 'transient malware' },
    },
  }))

  const bl = new Blacklist(makeNpm(cache))
  await bl.load()

  const inventory = new Map([
    ['/root', { isProjectRoot: true, package: { name: 'root', version: '1.0.0' }, location: '' }],
    ['/a', { package: { name: 'good-dep', version: '1.0.0' }, location: 'node_modules/good-dep' }],
    ['/b', { package: { name: 'bad-dep', version: '1.0.0' }, location: 'node_modules/bad-dep' }],
    ['/c', { package: { name: 'bad-dep', version: '2.0.0' }, location: 'node_modules/x/node_modules/bad-dep' }],
  ])
  const tree = { inventory }
  const hits = bl.checkTree(tree)

  t.equal(hits.length, 1)
  t.equal(hits[0].name, 'bad-dep')
  t.equal(hits[0].version, '1.0.0')
})

t.test('accepts compact entries (versions value stored directly)', async t => {
  // Remote OSSF lists drop the wrapper object to keep payloads small;
  // values are the version list (array | "*" | semver-range) directly.
  const cache = t.testdir()
  const cachePath = join(cache, 'blacklist', 'blocked-packages.json')
  await mkdir(join(cache, 'blacklist'), { recursive: true })
  await writeFile(cachePath, JSON.stringify({
    fetchedAt: Date.now(),
    source: 'compact-test',
    packages: {
      'wild-pkg': '*',
      'list-pkg': ['1.0.0', '2.0.0'],
      'range-pkg': '>=1.0.0 <2.0.0',
    },
  }))

  const bl = new Blacklist(makeNpm(cache))
  await bl.load()

  t.ok(bl.matchVersion('wild-pkg', '9.9.9'), 'compact wildcard matches')
  t.ok(bl.matchVersion('list-pkg', '1.0.0'), 'compact array matches listed version')
  t.notOk(bl.matchVersion('list-pkg', '9.9.9'), 'compact array skips unlisted version')
  t.ok(bl.matchVersion('range-pkg', '1.5.0'), 'compact range matches')
  t.notOk(bl.matchVersion('range-pkg', '2.0.0'), 'compact range excludes upper bound')

  t.ok(bl.checkArg('wild-pkg'), 'checkArg flags compact wildcard by name alone')
  t.ok(bl.checkArg('list-pkg@1.0.0'), 'checkArg flags exact match in compact array')
  t.notOk(bl.checkArg('list-pkg'), 'checkArg defers tag-spec on partial compact list')
})

t.test('buildBlockedError attaches code and structured data', async t => {
  const hits = [{
    name: 'evil',
    version: '1.0.0',
    location: 'node_modules/evil',
    entry: { reason: 'rce', advisory: 'https://example.com/advisory' },
  }]
  const err = Blacklist.buildBlockedError(hits, 'test-source')
  t.equal(err.code, 'EBLOCKED')
  t.match(err.message, /evil@1\.0\.0/)
  t.match(err.message, /rce/)
  t.match(err.message, /test-source/)
  t.equal(err.blocked, hits)
})
