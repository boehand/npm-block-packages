const t = require('tap')
const { join } = require('node:path')
const { mkdirSync, writeFileSync, rmSync } = require('node:fs')
const { load: loadMockNpm } = require('../../fixtures/mock-npm.js')

// A fresh, in-cache blacklist so we never hit the network from these tests.
const stubBlacklist = (cachePath, packages, source = 'test-source') => {
  const dir = join(cachePath, 'blacklist')
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'blocked-packages.json'), JSON.stringify({
    fetchedAt: Date.now(),
    source,
    packages,
  }))
}

// mock-npm seeds a default empty cache; remove it for tests that explicitly
// want the "no cache" code path (forcing the bundled default or a real fetch).
const clearBlacklistCache = (cachePath) => {
  rmSync(join(cachePath, 'blacklist'), { recursive: true, force: true })
}

// Point the URL at an unreachable host so any accidental network attempt
// fails fast instead of stalling the suite.
const OFFLINE_CONFIG = { 'blacklist-url': 'http://127.0.0.1:1/none.json' }

// The mock-npm fixture disables the blacklist by default via the
// `NPM_BLACKLIST_DISABLED` env var. Tests in this file exercise the
// blacklist itself, so they re-enable it through the `globals` override
// which mockGlobals honors at the same level as the default.
const ENABLE_BLACKLIST = {
  'process.env.NPM_BLACKLIST_DISABLED': undefined,
}

t.test('list shows entries from cache', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  stubBlacklist(npm.cache, {
    'evil-pkg': { versions: '*', reason: 'malicious', advisory: 'https://ex/1' },
    'pinned-pkg': { versions: ['9.9.9'], reason: 'compromised release' },
  })

  await npm.exec('blacklist', ['list'])
  const out = joinedOutput()
  t.match(out, /Source: test-source/)
  t.match(out, /Entries: 2/)
  t.match(out, /evil-pkg/)
  t.match(out, /pinned-pkg/)
  t.match(out, /9\.9\.9/)
})

t.test('list defaults when no subcommand given', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  stubBlacklist(npm.cache, { 'one': { versions: '*' } })

  await npm.exec('blacklist', [])
  t.match(joinedOutput(), /Entries: 1/)
})

t.test('list --json emits structured output', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG, json: true },
    globals: ENABLE_BLACKLIST,
  })
  stubBlacklist(npm.cache, { 'evil': { versions: '*' } }, 'json-source')

  await npm.exec('blacklist', ['list'])
  const parsed = JSON.parse(joinedOutput())
  t.equal(parsed.source, 'json-source')
  t.ok(parsed.packages.evil)
})

t.test('list falls back to bundled default when no cache exists', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  clearBlacklistCache(npm.cache)

  await npm.exec('blacklist', ['list'])
  const out = joinedOutput()
  t.match(out, /Source: bundled-default/)
  t.match(out, /event-stream/, 'bundled default includes historical compromises')
})

t.test('check flags blocked packages and exits non-zero', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  stubBlacklist(npm.cache, {
    'evil': { versions: '*', reason: 'malicious', advisory: 'https://ex/1' },
    'pinned': { versions: ['1.0.0'] },
  })

  const originalExit = process.exitCode
  t.teardown(() => { process.exitCode = originalExit })

  await npm.exec('blacklist', ['check', 'evil', 'pinned@1.0.0', 'safe@1.0.0'])
  const out = joinedOutput()
  t.match(out, /evil: BLOCKED/)
  t.match(out, /pinned@1\.0\.0: BLOCKED/)
  t.match(out, /safe@1\.0\.0: OK/)
  t.equal(process.exitCode, 1, 'exit code signals a hit')
})

t.test('check leaves exit code untouched when nothing matches', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  stubBlacklist(npm.cache, { 'evil': { versions: ['9.9.9'] } })

  const originalExit = process.exitCode
  t.teardown(() => { process.exitCode = originalExit })

  await npm.exec('blacklist', ['check', 'evil@1.0.0', 'safe@1.0.0'])
  t.match(joinedOutput(), /evil@1\.0\.0: OK/)
  t.match(joinedOutput(), /safe@1\.0\.0: OK/)
  t.notOk(process.exitCode, 'no hit means no exit code change')
})

t.test('check requires at least one arg', async t => {
  const { npm } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  await t.rejects(
    npm.exec('blacklist', ['check']),
    { code: 'EUSAGE' },
    'usage error when no spec is provided'
  )
})

t.test('unknown subcommand throws usage error', async t => {
  const { npm } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  await t.rejects(
    npm.exec('blacklist', ['frobnicate']),
    { code: 'EUSAGE' },
    'usage error on unknown subcommand'
  )
})

t.test('update rejects when the network is unreachable and no cache exists', async t => {
  const { npm } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  clearBlacklistCache(npm.cache)
  await t.rejects(
    npm.exec('blacklist', ['update']),
    /ECONNREFUSED|network|fetch|HTTP/i,
    'forced update surfaces fetch errors so the user knows it stayed stale'
  )
})

t.test('update falls back to existing cache when the fetch fails', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  stubBlacklist(npm.cache, {
    'old-evil': { versions: '*', reason: 'still bad' },
  }, 'previous-source')

  await npm.exec('blacklist', ['update'])
  t.match(joinedOutput(), /Blacklist updated: 1 entries from previous-source/)
})
