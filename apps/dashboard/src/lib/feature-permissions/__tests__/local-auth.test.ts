import { ACTIONS_FEATURE_PERMISSION } from '../permissions'
import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test'
import { randomUUID, scrypt as scryptCallback } from 'node:crypto'
import { rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

mock.module('cloudflare:workers', () => ({ env: {} }))

const scrypt = promisify(scryptCallback)
const ENV_KEYS = ['CHM_AUTH_PROVIDER', 'CHM_LOCAL_AUTH_FILE'] as const
const saved: Record<string, string | undefined> = {}

async function writeAuthFile(): Promise<string> {
  const salt = Buffer.from('chmonitor-feature-permission-test-salt')
  const key = Buffer.from(
    await scrypt('change-me-now', salt, 32, { N: 16384, r: 8, p: 1 })
  )
  const file = join(tmpdir(), `chmonitor-auth-${randomUUID()}.yml`)
  await writeFile(
    file,
    `users:\n  - username: admin\n    password_hash: scrypt$16384$8$1$${salt.toString('base64')}$${key.toString('base64')}\n`
  )
  return file
}

beforeEach(async () => {
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key]
    delete process.env[key]
  }
  const { _resetAppConfigCache } = await import('../server')
  _resetAppConfigCache()
})

afterEach(async () => {
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) delete process.env[key]
    else process.env[key] = saved[key]
  }
  const { _resetAppConfigCache } = await import('../server')
  _resetAppConfigCache()
})

describe('local auth feature permissions', () => {
  test('allows a valid Basic user to access authenticated features', async () => {
    const file = await writeAuthFile()
    process.env.CHM_AUTH_PROVIDER = 'local'
    process.env.CHM_LOCAL_AUTH_FILE = file

    try {
      const { authorizeFeatureRequest } = await import('../server')
      const token = Buffer.from('admin:change-me-now').toString('base64')
      const response = await authorizeFeatureRequest(
        ACTIONS_FEATURE_PERMISSION,
        new Request('http://localhost/api/v1/actions', {
          headers: { authorization: `Basic ${token}` },
        })
      )

      expect(response).toBeNull()
    } finally {
      await rm(file, { force: true })
    }
  })
})
