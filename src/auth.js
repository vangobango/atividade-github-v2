// auth.js - Módulo de autenticação com JWT
const crypto = require('crypto');

const SECRET_KEY = process.env.JWT_SECRET || 'chave-secreta-de-exemplo';

function base64url(input) {
  return Buffer.from(JSON.stringify(input))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64url(header);
  const encodedPayload = base64url(payload);

  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function login(user, password) {
  // Em um cenário real, validar credenciais contra o banco de dados
  if (!user || !password) {
    throw new Error('Usuário e senha são obrigatórios');
  }

  const token = generateToken({ user, iat: Date.now() });
  return { token };
}

module.exports = { login, generateToken };