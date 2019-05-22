const { send } = require('micro');
const microAuthAuth0 = require('.');

const options = {
  clientId: 'CLIENT_ID',
  clientSecret: 'CLIENT_SECRET',
  callbackUrl: 'http://localhost:3000/auth/auth0/callback',
  path: '/auth/auth0',
  scope: ''
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

  return `Hello ${auth.result.info}`;

};

module.exports = auth0(handler);
