
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const router = express.Router();

// These should come from your existing project modules.
const { users, sessionStore } = require('../services/authStore');

const SESSION_TTL = 60 * 60 * 1000;

const cookieOptions = {
  httpOnly: true,
  secure: process.env.COOKIE_SECURE === 'true',
  sameSite: 'lax',
  signed: true,
  path: '/',
  maxAge: SESSION_TTL
};

const clearCookieOptions = {
  httpOnly: true,
  secure: process.env.COOKIE_SECURE === 'true',
  sameSite: 'lax',
  signed: true,
  path: '/'
};

// LOGIN
router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: {
          code: 'INVALID_INPUT',
          message: 'Email and password are required'
        }
      });
    }

    const user = await users.findByEmail(email.trim());

    if (
      !user ||
      !(await bcrypt.compare(password, user.passwordHash))
    ) {
      return res.status(401).json({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        }
      });
    }

    // Create a cryptographically random session ID.
    const sessionId = crypto.randomUUID();

    // Store identity on the server, never in the cookie.
    await sessionStore.create({
      id: sessionId,
      userId: user.id,
      expiresAt: Date.now() + SESSION_TTL
    });

    res.cookie('sid', sessionId, cookieOptions);

    return res.status(200).json({
      data: {
        id: user.id,
        email: user.email
      }
    });
  } catch (err) {
    next(err);
  }
});

// PROTECTED IDENTITY
router.get('/me', async (req, res, next) => {
  try {
    // Requires cookie-parser configured with COOKIE_SECRET.
    const sessionId = req.signedCookies?.sid;

    if (typeof sessionId !== 'string' || !sessionId) {
      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required'
        }
      });
    }

    const session = await sessionStore.get(sessionId);

    if (
      !session ||
      session.expiresAt <= Date.now()
    ) {
      await sessionStore.destroy(sessionId);

      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required'
        }
      });
    }

    const user = await users.findPublicById(session.userId);

    if (!user) {
      await sessionStore.destroy(sessionId);

      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required'
        }
      });
    }

    return res.status(200).json({
      data: {
        id: user.id,
        email: user.email
      }
    });
  } catch (err) {
    next(err);
  }
});

// LOGOUT
router.post('/logout', async (req, res, next) => {
  try {
    const sessionId = req.signedCookies?.sid;

    // Revoke the server-side session first.
    if (typeof sessionId === 'string' && sessionId) {
      await sessionStore.destroy(sessionId);
    }

    // Clear using the same cookie scope/options.
    res.clearCookie('sid', clearCookieOptions);

    return res.status(204).send();
  } catch (err) {
    next(err);
  }
});

module.exports = router;