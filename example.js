const send = require('micro').send;
const microAuthAuth0 = require('.');
require('dotenv-safe').config();

const options = {
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  callbackUrl: process.env.AUTH0_CALLBACKURL, // 'http://localhost:3000/auth/auth0/callback'
  connection: process.env.AUTH0_CONNECTION, // Forces the user to sign in with a specific connection
  audience: process.env.AUTH0_AUDIENCE, // Your API Identifier
  path: '/auth/auth0',
  scope: 'openid email address phone profile',
  noState: false, // disables state parameter (not recomended)
  basicAuth: false, // false to use post method
  send_ip: true, // send auth0-forwarded-for header
  algorithm: "RS256", // allowed algorithm to verify jwt tokens for - "HS256" or "RS256"
  allowPost: true, // allow sending credentials with POST
  realm: process.env.AUTH0_CONNECTION,
  PKCE: true,
  silentPrompt : true
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

  return send(res,200, auth);
  //return `Hello ${auth.result.info.user.nickname} !`;

};

module.exports = auth0(handler);
