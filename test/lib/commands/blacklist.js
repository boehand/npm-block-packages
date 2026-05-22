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
  // Total entry count is "test entries + bundled defaults" because the
  // module always overlays the curated bundled list onto whatever is loaded.
  t.match(out, /Entries: \d+/)
  t.match(out, /evil-pkg/)
  t.match(out, /pinned-pkg/)
  t.match(out, /9\.9\.9/)
  // A representative bundled entry must also appear.
  t.match(out, /event-stream/)
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
  t.match(joinedOutput(), /Blacklist updated: \d+ entries from previous-source/)
})

t.test('scan reports blacklisted installs found on disk', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
    otherDirs: {
      projects: {
        a: {
          'package-lock.json': JSON.stringify({
            lockfileVersion: 3,
            packages: {
              '': { name: 'a' },
              'node_modules/safe': { version: '1.0.0' },
              'node_modules/evil': { version: '3.3.6' },
            },
          }),
        },
        b: {
          node_modules: {
            'rogue': { 'package.json': JSON.stringify({ name: 'rogue', version: '1.0.0' }) },
          },
        },
      },
    },
  })
  stubBlacklist(npm.cache, {
    evil: { versions: ['3.3.6'], reason: 'compromised event-stream era' },
    rogue: { versions: '*', reason: 'typosquat malware', advisory: 'https://ex/r' },
  })
  const scanDir = join(npm.cache, '..', 'other', 'projects')

  const originalExit = process.exitCode
  t.teardown(() => { process.exitCode = originalExit })

  await npm.exec('blacklist', ['scan', scanDir])
  const out = joinedOutput()
  t.match(out, /Found 2 blacklisted package installs/)
  t.match(out, /evil@3\.3\.6/)
  t.match(out, /rogue@1\.0\.0/)
  t.match(out, /compromised event-stream era/)
  t.match(out, /typosquat malware/)
  t.match(out, /https:\/\/ex\/r/)
  t.equal(process.exitCode, 1, 'exit code signals hits were found')
})

t.test('scan reports clean tree without setting exit code', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
    otherDirs: {
      projects: {
        clean: {
          'package-lock.json': JSON.stringify({
            lockfileVersion: 3,
            packages: {
              '': { name: 'clean' },
              'node_modules/lodash': { version: '4.17.21' },
            },
          }),
          node_modules: {
            'lodash': { 'package.json': JSON.stringify({ name: 'lodash', version: '4.17.21' }) },
          },
        },
      },
    },
  })
  stubBlacklist(npm.cache, { evil: { versions: '*' } })
  const scanDir = join(npm.cache, '..', 'other', 'projects')

  const originalExit = process.exitCode
  t.teardown(() => { process.exitCode = originalExit })

  await npm.exec('blacklist', ['scan', scanDir])
  t.match(joinedOutput(), /No blacklisted packages found/)
  t.notOk(process.exitCode, 'clean scan leaves exit code untouched')
})

t.test('scan --json emits structured findings', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG, json: true },
    globals: ENABLE_BLACKLIST,
    otherDirs: {
      proj: {
        node_modules: {
          'evil': { 'package.json': JSON.stringify({ name: 'evil', version: '1.0.0' }) },
        },
      },
    },
  })
  stubBlacklist(npm.cache, { evil: { versions: '*', reason: 'rce', advisory: 'https://ex/a' } })
  const scanDir = join(npm.cache, '..', 'other', 'proj')

  const originalExit = process.exitCode
  t.teardown(() => { process.exitCode = originalExit })

  await npm.exec('blacklist', ['scan', scanDir])
  const parsed = JSON.parse(joinedOutput())
  t.equal(parsed.hits.length, 1)
  t.equal(parsed.hits[0].name, 'evil')
  t.equal(parsed.hits[0].version, '1.0.0')
  t.equal(parsed.hits[0].reason, 'rce')
  t.equal(parsed.hits[0].advisory, 'https://ex/a')
})

t.test('scan defaults to cwd when no dir is given', async t => {
  // We don't easily control cwd inside the mock fixture chdir, so this
  // just confirms the command runs without throwing when no dir arg is
  // supplied (the actual cwd is empty / clean in the test sandbox).
  const { npm } = await loadMockNpm(t, {
    config: { ...OFFLINE_CONFIG },
    globals: ENABLE_BLACKLIST,
  })
  stubBlacklist(npm.cache, {})
  await npm.exec('blacklist', ['scan'])
  t.pass('scan tolerated missing dir arg')
})
