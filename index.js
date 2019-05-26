const querystring = require('querystring');
const url = require('url');
const crypto = require('crypto');
const redirect = require('micro-redirect');
const get_ip = require('ipware')().get_ip;
const parse = require('urlencoded-body-parser');
const Auth0 = require('./Auth0');

const provider = 'auth0';

function newCodeVerifier() {
  return crypto
  .randomBytes(32)
  .toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=/g, '');
}

module.exports = ({ 
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
                      allowPost = false,
                      realm,
                      PKCE = false,
                      silentPrompt = false
                    }) => {
  const states = [];
  var code_verifier = null;
  // optionally scope as array 
  if (Array.isArray(scope)) { scope = scope.join(' '); }
  code_verifier = !PKCE ? null : newCodeVerifier();

  return microauth = (next) => { return handler = async (req, res, ...args) => {
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
      allowPost,
      realm,
      code_verifier,
      silentPrompt
    }
    const auth0 = new Auth0(params);

    const getResult = async ({tokens}) => {
      const result = await Promise.all([
        auth0.verifyApiToken(tokens.access_token),
        auth0.getUserInfo({token: tokens.access_token}),
        auth0.verifyIdToken(tokens.id_token)
      ]).catch(e => {throw e});
      return {
        provider,
        accessToken: tokens.access_token,
        tokens,
        info: {
          apiToken: result[0],
          user: result[1],
          idToken: result[2]
        }
      };
    }

    const { pathname, query } = url.parse(req.url);
    try {
      if (pathname === path) {
        if (req.method !== 'POST') {
          const redirectUrl = auth0.getAuthorizeUrl({});
          if (!auth0.getNoState()) {
            const {state} = querystring.parse(url.parse(redirectUrl).query);
            states.push(state);
          }
          return redirect(res, 302, redirectUrl);
        } else if (allowPost && req.headers['content-type'] === 'application/x-www-form-urlencoded') {
          const {username, password} = await parse(req)
          const tokens = await auth0.getOAuthAccessToken({username, password, grant_type: 'password'})
          const result = await getResult({tokens})
                                .catch(e => {throw e});
          args.push({ result });
          return next(req, res, ...args);
        }

      }
      else if (pathname === url.parse(callbackUrl).pathname) {
        const { state, code, error, error_description} = querystring.parse(query);
        // error parameter from query send by authentication server
        if (error) {
          throw new Error(error + ': ' + error_description);
        } else if (!auth0.getNoState() && !states.includes(state)) {
          throw new Error('Invalid state: ' + state);
        }
        // getResult()
        const tokens = await auth0.getOAuthAccessToken({code})
                        .catch(e => {throw e});

        const result = await getResult({tokens})
                              .catch(e => {throw e});
        
        // deletes state from states array
        // states.splice(states.indexOf(state), 1);
        args.push({ result });
        return next(req, res, ...args);
      }
      else return next(req, res, ...args)
    } catch (err) {
      console.error(err)
      args.push({ err, provider });
      return next(req, res, ...args);
    }
  }}
};