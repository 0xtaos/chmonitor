import type { AuthResult, ServerAuthProvider } from './types'

import { scrypt as scryptCallback, timingSafeEqual } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { parse as parseYaml } from 'yaml'

const DEFAULT_AUTH_FILE = '/etc/chmonitor/auth.yml'
const HASH_PREFIX = 'scrypt'

type LocalUser = { username: string; password_hash: string }
type LocalAuthConfig = { users: LocalUser[] }

function getAuthFilePath(): string {
  return process.env.CHM_LOCAL_AUTH_FILE?.trim() || DEFAULT_AUTH_FILE
}

function parseBasicAuthorization(header: string | null): {
  username: string
  password: string
} | null {
  const match = header?.match(/^Basic\s+(.+)$/i)
  if (!match) return null

  try {
    const decoded = Buffer.from(match[1], 'base64').toString('utf8')
    const separator = decoded.indexOf(':')
    if (separator < 1) return null
    return {
      username: decoded.slice(0, separator),
      password: decoded.slice(separator + 1),
    }
  } catch {
    return null
  }
}

function parseConfig(input: unknown): LocalAuthConfig {
  if (
    !input ||
    typeof input !== 'object' ||
    !Array.isArray((input as { users?: unknown }).users)
  ) {
    throw new Error('Local auth YAML must contain a users array')
  }

  const users = (input as { users: unknown[] }).users.map((user) => {
    if (
      !user ||
      typeof user !== 'object' ||
      typeof (user as { username?: unknown }).username !== 'string' ||
      typeof (user as { password_hash?: unknown }).password_hash !== 'string' ||
      !(user as { username: string }).username.trim() ||
      !(user as { password_hash: string }).password_hash.trim()
    ) {
      throw new Error('Every local auth user needs username and password_hash')
    }
    return {
      username: (user as { username: string }).username,
      password_hash: (user as { password_hash: string }).password_hash,
    }
  })

  if (new Set(users.map((user) => user.username)).size !== users.length) {
    throw new Error('Duplicate username in local auth YAML')
  }
  return { users }
}

async function loadConfig(): Promise<LocalAuthConfig> {
  return parseConfig(parseYaml(await readFile(getAuthFilePath(), 'utf8')))
}

function decodeBase64(value: string): Buffer | null {
  if (
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value
    )
  ) {
    return null
  }

  const decoded = Buffer.from(value, 'base64')
  return decoded.toString('base64') === value ? decoded : null
}

function deriveScryptKey(
  password: string,
  salt: Buffer,
  keyLength: number,
  cost: number,
  blockSize: number,
  parallel: number
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(
      password,
      salt,
      keyLength,
      {
        N: cost,
        r: blockSize,
        p: parallel,
        maxmem: 256 * 1024 * 1024,
      },
      (error, derivedKey) => {
        if (error) {
          reject(error)
          return
        }
        resolve(derivedKey)
      }
    )
  })
}

async function verifyScryptPassword(
  password: string,
  encoded: string
): Promise<boolean> {
  const parts = encoded.split('$')
  if (parts.length !== 6) return false

  const [scheme, costRaw, blockSizeRaw, parallelRaw, saltRaw, expectedRaw] =
    parts
  const cost = Number(costRaw)
  const blockSize = Number(blockSizeRaw)
  const parallel = Number(parallelRaw)
  if (
    scheme !== HASH_PREFIX ||
    !Number.isInteger(cost) ||
    cost < 16384 ||
    cost > 1048576 ||
    (cost & (cost - 1)) !== 0 ||
    !Number.isInteger(blockSize) ||
    blockSize < 1 ||
    blockSize > 32 ||
    !Number.isInteger(parallel) ||
    parallel < 1 ||
    parallel > 16 ||
    !saltRaw ||
    !expectedRaw
  ) {
    return false
  }

  try {
    const salt = decodeBase64(saltRaw)
    const expected = decodeBase64(expectedRaw)
    if (!salt?.length || !expected?.length) return false
    const actual = await deriveScryptKey(
      password,
      salt,
      expected.length,
      cost,
      blockSize,
      parallel
    )
    return (
      actual.length === expected.length && timingSafeEqual(actual, expected)
    )
  } catch {
    return false
  }
}

/**
 * Node/Docker-only Basic auth provider backed by an operator-mounted YAML file.
 * Missing or invalid credentials, config, and password hashes always deny access.
 */
export class LocalAuthProvider implements ServerAuthProvider {
  async authenticateRequest(request: Request): Promise<AuthResult> {
    try {
      const credentials = parseBasicAuthorization(
        request.headers.get('authorization')
      )
      if (!credentials) return { authenticated: false }

      const user = (await loadConfig()).users.find(
        (candidate) => candidate.username === credentials.username
      )
      if (
        !user ||
        !(await verifyScryptPassword(credentials.password, user.password_hash))
      ) {
        return { authenticated: false }
      }
      return {
        authenticated: true,
        subject: user.username,
        principal: { subject: user.username, name: user.username },
      }
    } catch {
      return { authenticated: false }
    }
  }
}
