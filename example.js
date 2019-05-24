const send = require('micro').send;
const microAuthAuth0 = require('.');
require('dotenv-safe').config();

const options = {
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  callbackUrl: process.env.AUTH0_CALLBACKURL, // 'http://localhost:3000/auth/auth0/callback'
  connection: null, // Forces the user to sign in with a specific connection
  path: '/auth/auth0',
  scope: 'openid email address phone profile offline_access'
};

const auth0 = microAuthAuth0(options);

const handler = async (req, res, auth) => {

  if (!auth) {
    return send(res, 404, 'Not Found');
  }

  if (auth.err) {
    // Error handler
    console.error(auth.err);
    return send(res, 403, 'Forbidden');
  }

  // Save something in database here

  return `Hello ${auth.result.info.user.nickname} !`;

};

module.exports = auth0(handler);
