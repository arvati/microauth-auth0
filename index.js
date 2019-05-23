const querystring = require('querystring');
const url = require('url');
const redirect = require('micro-redirect');
const Oauth2 = require('./Oauth2');

const provider = 'auth0';

const microAuth0 = ({ domain, clientId, clientSecret, callbackUrl, connection, path = '/auth/auth0', scope = 'openid email profile offline_access', scopeSeparator = ' ' }) => {
  ['domain',
      'clientId',
      'clientSecret',
      'callbackUrl'].forEach(function (k) {
      if(!k){
        throw new Error('You must provide the ' + k + ' configuration value to use microauth-auth0.');
      }
    });
    // optionally scope as array and scope separator to be used.
    if (Array.isArray(scope)) { scope = scope.join(scopeSeparator); }
  const states = [];
  const params = {
    clientId, 
    clientSecret, 
    domain, 
    callbackUrl,
    connection,
    scope
  }
  const oauth2 = new Oauth2(params);

  return fn => async (req, res, ...args) => {
    const { pathname, query } = url.parse(req.url);

    if (pathname === path) {
      try {
        const redirectUrl = oauth2.getAuthorizeUrl({});
        const {state} = querystring.parse(url.parse(redirectUrl).query);
        states.push(state);
        console.debug({states})
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
          console.debug({states})
          const err = new Error('Invalid state: ' + state);
          args.push({ err, provider });
          return fn(req, res, ...args);
        }
        states.splice(states.indexOf(state), 1);

        const response = await oauth2.getOAuthAccessToken({code})

        if (response.error) {
          args.push({ err: response.error, provider });
          return fn(req, res, ...args);
        }

        const access_token = response.access_token; //are used to call the Auth0 Authentication API's /userinfo endpoint or another API
        const refresh_token = response.refresh_token; //are used to obtain a new Access Token or ID Token after the previous one has expired.
        const id_token = response.id_token; //  contain user information that must be decoded and extracted.
        const token_type = response.token_type; // Example = "Bearer"

        const decoded_id = await oauth2.verifyToken({token: id_token})
        const info = await oauth2.getProfile({access_token})

        const result = {
          provider,
          access_token,
          id_token,
          decoded_id,
          refresh_token,
          token_type,
          info
        };
        //console.debug(result);

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