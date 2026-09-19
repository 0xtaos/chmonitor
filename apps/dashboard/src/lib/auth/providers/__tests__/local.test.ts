import { LocalAuthProvider } from '../local'
import { afterEach, describe, expect, test } from 'bun:test'
import { randomUUID, scrypt as scryptCallback } from 'node:crypto'
import { rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCallback)
const originalPath = process.env.CHM_LOCAL_AUTH_FILE

async function writeAuthFile(
  content?: string,
  password = 'change-me-now',
  hashSuffix = ''
): Promise<string> {
  const salt = Buffer.from('chmonitor-local-auth-test-salt')
  const key = Buffer.from(
    await scrypt(password, salt, 32, { N: 16384, r: 8, p: 1 })
  )
  const file = join(tmpdir(), `chmonitor-auth-${randomUUID()}.yml`)
  await writeFile(
    file,
    content ??
      `users:\n  - username: admin\n    password_hash: scrypt$16384$8$1$${salt.toString('base64')}$${key.toString('base64')}${hashSuffix}\n`
  )
  process.env.CHM_LOCAL_AUTH_FILE = file
  return file
}

afterEach(() => {
  if (originalPath === undefined) delete process.env.CHM_LOCAL_AUTH_FILE
  else process.env.CHM_LOCAL_AUTH_FILE = originalPath
})

describe('LocalAuthProvider', () => {
  test('accepts valid HTTP Basic credentials from YAML', async () => {
    const file = await writeAuthFile()
    try {
      const token = Buffer.from('admin:change-me-now').toString('base64')
      const result = await new LocalAuthProvider().authenticateRequest(
        new Request('http://localhost/api/v1/health', {
          headers: { authorization: `Basic ${token}` },
        })
      )
      expect(result.authenticated).toBe(true)
      expect(result.subject).toBe('admin')
    } finally {
      await rm(file, { force: true })
    }
  })

  test('rejects a missing or invalid password', async () => {
    const file = await writeAuthFile()
    try {
      const provider = new LocalAuthProvider()
      expect(
        (await provider.authenticateRequest(new Request('http://localhost')))
          .authenticated
      ).toBe(false)
      const token = Buffer.from('admin:wrong-password').toString('base64')
      expect(
        (
          await provider.authenticateRequest(
            new Request('http://localhost', {
              headers: { authorization: `Basic ${token}` },
            })
          )
        ).authenticated
      ).toBe(false)
    } finally {
      await rm(file, { force: true })
    }
  })

  test('fails closed when the YAML config is malformed', async () => {
    const file = await writeAuthFile('users: not-an-array\n')
    try {
      const token = Buffer.from('admin:change-me-now').toString('base64')
      const result = await new LocalAuthProvider().authenticateRequest(
        new Request('http://localhost', {
          headers: { authorization: `Basic ${token}` },
        })
      )
      expect(result.authenticated).toBe(false)
    } finally {
      await rm(file, { force: true })
    }
  })

  test('rejects a password hash with extra fields', async () => {
    const file = await writeAuthFile(undefined, 'change-me-now', '$junk')
    try {
      const token = Buffer.from('admin:change-me-now').toString('base64')
      const result = await new LocalAuthProvider().authenticateRequest(
        new Request('http://localhost', {
          headers: { authorization: `Basic ${token}` },
        })
      )
      expect(result.authenticated).toBe(false)
    } finally {
      await rm(file, { force: true })
    }
  })
})
