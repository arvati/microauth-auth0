const querystring = require('querystring');
const url = require('url');
const redirect = require('micro-redirect');
const get_ip = require('ipware')().get_ip;
const json = require('micro').json;
//const parse = require('urlencoded-body-parser');
const Auth0 = require('./Auth0');

const provider = 'auth0';

const microAuth0 = ({ 
                      domain, 
                      clientId, 
                      clientSecret, 
                      callbackUrl, 
                      connection, 
                      audience,
                      path = '/auth/auth0', 
                      scope = 'openid email profile', 
                      noState = false,
                      basicAuth = false,
                      send_ip = false,
                      algorithm = "HS256 RS256",
                      allowPost = false
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
  return middleware = (next) => { return handler = async (req, res, ...args) => {
    if (send_ip) {
      const {clientIp, clientIpRoutable} = get_ip(req, false);
      send_ip = !clientIpRoutable ? false : clientIp // Only use Ip that is externally route-able / Public
    }
    const params = {
      clientId, 
      clientSecret, 
      domain, 
      callbackUrl,
      connection,
      audience,
      scope,
      noState,
      basicAuth,
      send_ip,
      algorithm,
      allowPost
    }
    const auth0 = new Auth0(params);
    const { pathname, query } = url.parse(req.url);

    if (pathname === path) {
      try {
        if (req.method !== 'POST') {
          const redirectUrl = auth0.getAuthorizeUrl({});
          if (!auth0.getNoState()) {
            const {state} = querystring.parse(url.parse(redirectUrl).query);
            states.push(state);
          }
          return redirect(res, 302, redirectUrl);
        } else if (allowPost) {
          // TODO : change getOAuthAccessToken check if clientSecret exists there and change grant_type if needed
          const {username, password} = await json(req)
          const tokens = await auth0.getOAuthAccessToken({username, password, grant_type: 'password'})
        }
      } catch (err) {
        args.push({ err, provider });
        return next(req, res, ...args);
      }
    }

    // callback pathname
    if (pathname === url.parse(callbackUrl).pathname) {
      try {
        const { state, code, error, error_description} = querystring.parse(query);
        if (error) {
          const err = new Error(error + ': ' + error_description);
          args.push({ err, provider });
          return next(req, res, ...args);
        } else if (!auth0.getNoState() && !states.includes(state)) {
          const err = new Error('Invalid state: ' + state);
          args.push({ err, provider });
          return next(req, res, ...args);
        }

        // deletes state from states array
        states.splice(states.indexOf(state), 1);

        const tokens = await auth0.getOAuthAccessToken({code})
        // refresh token only if scope = offline_access
        if (tokens.error) {
          args.push({ err: tokens.error, provider });
          return next(req, res, ...args);
        }

        const apiToken = await auth0.verifyApiToken(tokens.access_token)
        if (apiToken.error) {
          args.push({ err: apiToken.error, provider });
          return next(req, res, ...args);
        }
        
        const user = await auth0.getUserInfo({token: tokens.access_token})
        if (user.error) {
          args.push({ err: user.error, provider });
          return next(req, res, ...args);
        }

        const idToken = await auth0.verifyIdToken(tokens.id_token)
        if (idToken.error) {
          args.push({ err: idToken.error, provider });
          return next(req, res, ...args);
        }

        const result = {
          provider,
          accessToken: tokens.access_token,
          tokens,
          info: {
            user,
            idToken,
            apiToken
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