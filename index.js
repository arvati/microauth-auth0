const querystring = require('querystring');
const url = require('url');
const redirect = require('micro-redirect');
const Auth0 = require('./Auth0');

const provider = 'auth0';

const microAuth0 = ({ 
                      domain, 
                      clientId, 
                      clientSecret, 
                      callbackUrl, 
                      connection, 
                      path = '/auth/auth0', 
                      scope = 'openid email profile', 
                      noState = false,
                      basicAuth = false
                    }) => {
  ['domain',
      'clientId',
      'clientSecret',
      'callbackUrl'].forEach(function (k) {
      if(!k){
        throw new Error('You must provide the ' + k + ' configuration value to use microauth-auth0.');
      }
    });
  // optionally scope as array 
  if (Array.isArray(scope)) { scope = scope.join(' '); }
  const states = [];
  const params = {
    clientId, 
    clientSecret, 
    domain, 
    callbackUrl,
    connection,
    scope,
    noState,
    basicAuth
  }
  const auth0 = new Auth0(params);

  return middleware = (next) => { return handler = async (req, res, ...args) => {
    const { pathname, query } = url.parse(req.url);

    if (pathname === path) {
      try {
        const redirectUrl = auth0.getAuthorizeUrl({});
        if (!auth0.getNoState()) {
          const {state} = querystring.parse(url.parse(redirectUrl).query);
          states.push(state);
        }
        return redirect(res, 302, redirectUrl);
      } catch (err) {
        args.push({ err, provider });
        return next(req, res, ...args);
      }
    }

    if (pathname === url.parse(callbackUrl).pathname) {
      try {
        const { state, code } = querystring.parse(query);
        if (!auth0.getNoState() && !states.includes(state)) {
          const err = new Error('Invalid state: ' + state);
          args.push({ err, provider });
          return next(req, res, ...args);
        }
        states.splice(states.indexOf(state), 1);

        const tokens = await auth0.getOAuthAccessToken({code})
        // refresh token only if scope = offline_access
        if (tokens.error) {
          args.push({ err: tokens.error, provider });
          return next(req, res, ...args);
        }

        const user = await auth0.getUserInfo({token: tokens.access_token})
        if (user.error) {
          args.push({ err: user.error, provider });
          return next(req, res, ...args);
        }

        const token = await auth0.verifyToken({token: tokens.id_token})
        if (token.error) {
          args.push({ err: token.error, provider });
          return next(req, res, ...args);
        }

        const result = {
          provider,
          accessToken: tokens.access_token,
          tokens,
          info: {
            user,
            token
          }
        };
        args.push({ result });
        return next(req, res, ...args);
      } catch (err) {
        args.push({ err, provider });
        return next(req, res, ...args);
      }
    }

    return next(req, res, ...args)
  }}
};

module.exports = microAuth0;