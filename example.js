const { send } = require('micro');
const microAuthAuth0 = require('.');

const options = {
    domain: process.env.AUTH0_DOMAIN,
    clientId: process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET,
    callbackUrl: process.env.AUTH0_CALLBACKURL || 'http://localhost:3000/auth/auth0/callback',
    path: '/auth/auth0',
    scope: 'openid email address phone profile' // profile = name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at
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
