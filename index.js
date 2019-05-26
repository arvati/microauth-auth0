const querystring = require('querystring');
const url = require('url');
const get_ip = require('ipware')().get_ip;
const parse = require('urlencoded-body-parser');
const Auth0 = require('./Auth0');
const Session = require('./Session');

const provider = 'auth0';


module.exports = ({ 
                      domain, 
                      clientId, 
                      clientSecret, 
                      callbackUrl, 
                      connection, 
                      audience,
                      path = '/auth/auth0', 
                      scope = 'openid email profile', 
                      noState,
                      basicAuth = false,
                      send_ip = false,
                      algorithm = "HS256 RS256",
                      allowPost = false,
                      realm,
                      PKCE,
                      silentPrompt = false
                    }) => {
  // optionally scope as array 
  if (Array.isArray(scope)) { scope = scope.join(' '); }
  session = new Session ({noState,PKCE});

  const redirect = (res, redirectUrl) => {
    const {state, prompt, redirect_uri} = querystring.parse(url.parse(redirectUrl).query);
    if (redirect_uri) {
      const callbackUri = url.parse(redirect_uri, true)
      // Check if callbackUri is relative misses host, protocol, port
    }
    // saves if noPrompt
    session.prompt = (prompt === 'none') ? false : true;
    // saves if state
    session.addState(state);
    // redirect
    res.statusCode = 302;
    res.setHeader('Location', redirectUrl);
    res.end();
  }

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
      noState : session.noState,
      basicAuth,
      send_ip,
      algorithm,
      allowPost,
      realm,
      code_verifier : session.code_verifier,
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
        if (req.method === 'POST' && req.headers['content-type'] === 'application/x-www-form-urlencoded') {
          // todo: another POST type = check if body contais refresh_token to revoke or refresh
          if (allowPost) {
            const {username, password} = await parse(req)
            const tokens = await auth0.getOAuthAccessToken({username, password, grant_type: 'password'})
            const result = await getResult({tokens})
                                  .catch(e => {throw e});
            args.push({ result });
            return next(req, res, ...args);
          }
        } else if (req.method === 'GET') {
          return redirect(res, auth0.getAuthorizeUrl({silentPrompt}));
        } else return next(req, res, ...args)
      }
      else if (pathname === url.parse(callbackUrl).pathname) {
        const { state, code, error, error_description} = querystring.parse(query);
        // error parameter from query send by authentication server
        if (error) {
          if (!session.prompt) {
            return redirect(res, auth0.getAuthorizeUrl({silentPrompt:false}));
          }
          else throw new Error(error + ': ' + error_description);
        } else if (!session.verifyState(state)) {
          throw new Error('Invalid state: ' + state);
        }

        const tokens = await auth0.getOAuthAccessToken({code})
                        .catch(e => {throw e});

        const result = await getResult({tokens})
                              .catch(e => {throw e});
        
        session.delState(state);
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