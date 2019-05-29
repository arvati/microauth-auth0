const send = require('micro').send;
const microAuthAuth0 = require('.');
require('dotenv-safe').config();

const options = {
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
  //clientSecret: process.env.AUTH0_CLIENT_SECRET, // Not needed when PKCE enabled
  callbackUrl: '/auth/auth0/callback',
  //connection: process.env.AUTH0_CONNECTION, // Forces the user to sign in with a specific connection
  audience: process.env.AUTH0_AUDIENCE, // Optional : Your API Identifier
  path: '/auth/auth0/',
  scope: 'openid email address phone profile',
  //noState: false, // disables state parameter (not recomended)
  //basicAuth: false, // false to use post method
  //send_ip: true, // send auth0-forwarded-for header
  //algorithm: "RS256", // allowed algorithm to verify jwt tokens for - "HS256" or "RS256"
  //allowPost: false, // allow sending credentials with POST
  //realm: process.env.AUTH0_CONNECTION, // Verify POST credentials with this database
  PKCE: true, // Selects App Native in Auth0 Dashboard for this to work
  silentPrompt : true,
  trustProxy: true, // used when detecting origin and protocol
  whitelist : ['/imagine/(.*)','/favicon.ico'] // array of whitelist paths to not verify authorization with jwt tokens
};

const auth0 = microAuthAuth0(options);

const handler = async (req, res, auth) => {

  // This means path is whitelisted !!!
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
