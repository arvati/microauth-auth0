const querystring = require('querystring');
const url = require('url');

const uuid = require('uuid');
const rp = require('request-promise-native');
const redirect = require('micro-redirect');
const pkg = require('./package.json');

const provider = 'auth0';

function encodeClientInfo(obj) {
  const str = JSON.stringify(obj);
  return new Buffer(str).toString('base64')
      .replace(/\+/g, '-') // Convert '+' to '-'
      .replace(/\//g, '_') // Convert '/' to '_'
      .replace(/=+$/, ''); // Remove ending '='
}
const clientInfoHeader = encodeClientInfo({ name: pkg.name, version: pkg.version });


const microAuth0 = ({ domain, clientId, clientSecret, callbackUrl, path = '/auth/auth0', scope = 'openid email profile' }) => {
    ['domain',
        'clientId',
        'clientSecret',
        'callbackUrl'].forEach(function (k) {
        if(!k){
          throw new Error('You must provide the ' + k + ' configuration value to use microauth-auth0.');
        }
      });


  const getRedirectUrl = state => {
    // https://auth0.com/docs/flows/guides/auth-code/add-login-auth-code#authorize-the-user
    return `https://${domain}/authorize?response_type=code&client_id=${clientId}&redirect_uri=${callbackUrl}&scope=${scope}&state=${state}`;
  };

  const states = [];

  return fn => async (req, res, ...args) => {
    const { pathname, query } = url.parse(req.url);

    if (pathname === path) {
      try {
        const state = uuid.v4();
        const redirectUrl = getRedirectUrl(state);
        states.push(state);
        return redirect(res, 302, redirectUrl);
      } catch (err) {
        args.push({ err, provider });
        return fn(req, res, ...args);
      }
    }

    const callbackPath = url.parse(callbackUrl).pathname;
    if (pathname === callbackPath) {
      try {
        const { state, code } = querystring.parse(query);

        if (!states.includes(state)) {
          const err = new Error('Invalid state');
          args.push({ err, provider });
          return fn(req, res, ...args);
        }

        states.splice(states.indexOf(state), 1);

        const response = await rp({
          method: 'POST',
          url: `https://${domain}/oauth/token`,
          headers: { 'Auth0-Client': clientInfoHeader,
                    'content-type': 'application/x-www-form-urlencoded' },
          form :
               { grant_type: 'authorization_code',
                 client_id: clientId,
                 client_secret: clientSecret,
                 code: code,
                 redirect_ui: callbackUrl }
                 };
        });

        if (response.error) {
          args.push({ err: response.error, provider });
          return fn(req, res, ...args);
        }

        const accessToken = response.access_token; //are used to call the Auth0 Authentication API's /userinfo endpoint or another API
        const refresh_token = response.refresh_token; //are used to obtain a new Access Token or ID Token after the previous one has expired.
        const id_token = response.id_token; //  contain user information that must be decoded and extracted.
        const token_type = response.token_type; // Example = "Bearer"

        const user = await rp({
            method: 'GET',
          url: `https://${domain}/userinfo`,
          headers: { 'Authorization': 'Bearer ' + accessToken,
                    'content-type': 'application/json'}
        });

        // User Object Reformatting like passport-auth0 strategy
        user.id = user.user_id || user.sub;
        user.user_id = user.id;
        user.name = {
            familyName: user.family_name,
            givenName: user.given_name
          };
        if (user.emails) {
        user.all_emails = user.emails.map(function (email) {
          return { value: email };
        });
      } else if (user.email) {
        user.all_emails = [{
          value: user.email
        }];
      }

        const result = {
          provider,
          accessToken,
          id_token,
          refresh_token,
          token_type,
          info: user
        };

        args.push({ result });
        return fn(req, res, ...args);
      } catch (err) {
        args.push({ err, provider });
        return fn(req, res, ...args);
      }
    }

    return fn(req, res, ...args)
  }
};

module.exports = microAuth0;
