// cookieService.js
// Cryptographic Cookie Minting, Parsing & JWT Session Binding (LID-ARCH-REV-015 §2.2, §4.2)

const crypto = require('crypto');

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

function signJwt(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJwt(token, secret) {
  if (!token || typeof token !== 'string') {
    throw new Error('INVALID_TOKEN_FORMAT');
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('INVALID_TOKEN_STRUCTURE');
  }
  const [encodedHeader, encodedPayload, signature] = parts;
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expectedSignature);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    throw new Error('INVALID_TOKEN_SIGNATURE');
  }

  const payload = JSON.parse(base64UrlDecode(encodedPayload));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp <= now) {
    throw new Error('TOKEN_EXPIRED');
  }
  return payload;
}

class CookieService {
  constructor(config) {
    this.config = config;
    this.secret = config.sessionSigningSecret;
    this.cookieName = config.cookieName;
    this.cookieAttributes = config.cookieAttributes;
    this.appEnv = config.appEnv;
  }

  mintSessionToken({ sid, uid, absoluteExpiresAt }) {
    const now = Math.floor(Date.now() / 1000);
    const exp = absoluteExpiresAt || now + 30 * 24 * 60 * 60; // 30 days
    const payload = {
      sid,
      uid,
      env: this.appEnv,
      iat: now,
      exp
    };
    return signJwt(payload, this.secret);
  }

  createSetCookieHeader(jwtToken) {
    return `${this.cookieName}=${jwtToken}; ${this.cookieAttributes}`;
  }

  createClearCookieHeader() {
    // Determine attributes without max-age/expires
    let attrs = this.cookieAttributes.replace(/Max-Age=[^;]+/i, '');
    return `${this.cookieName}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; ${attrs}`;
  }

  parseCookieFromHeaders(headers) {
    const cookieHeader = headers.cookie || headers.Cookie;
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(';').map(c => c.trim());
    for (const c of cookies) {
      const [name, ...valParts] = c.split('=');
      if (name.trim() === this.cookieName) {
        return valParts.join('=').trim();
      }
    }
    return null;
  }

  verifySessionCookie(cookieValue) {
    if (!cookieValue) {
      throw new Error('NO_COOKIE_PRESENT');
    }
    const payload = verifyJwt(cookieValue, this.secret);
    if (payload.env !== this.appEnv) {
      const err = new Error('ENVIRONMENT_MISMATCH');
      err.code = 'ENVIRONMENT_MISMATCH';
      throw err;
    }
    return payload;
  }
}

module.exports = {
  CookieService,
  signJwt,
  verifyJwt
};
