const parse = require('urlencoded-body-parser');
const pathToRegexp = require('path-to-regexp');
const requestUrl = require('./RequestUrl');
const Auth0 = require('./Auth0');
const Session = require('./Session');

const provider = 'auth0';


module.exports = ({ 
            domain, 
            clientId, 
            clientSecret, 
            callbackUrl = '/auth/auth0/callback', 
            connection, 
            audience,
            path = '/auth/auth0/', 
            scope = 'openid email profile', 
            noState,
            basicAuth = false,
            send_ip = false,
            algorithm = "HS256 RS256",
            allowPost = false,
            realm,
            PKCE,
            silentPrompt = true,
            trustProxy,
            whitelist
          }) => {
  // optionally scope as array 
  if (Array.isArray(scope)) { scope = scope.join(' '); }

  session = new Session ({noState,PKCE});

  const redirect = (req, res, redirectUrl) => {
    const params = new URL(redirectUrl).searchParams
    // saves if noPrompt
    session.prompt = (params.get('prompt') === 'none') ? false : true;
    // saves if state
    session.addState(params.get('state'));
    // redirect
    res.statusCode = 302;
    res.setHeader('Location', redirectUrl);
    res.end();
  }

  return microauth = (next) => { return handler = async (req, res, ...args) => {
    requestUrl(req,{trustProxy})
    const callbackURL = new URL(callbackUrl, req.origin )
    path = new URL(path,req.origin).pathname
    if (send_ip) {
      send_ip = !req.clientIpRoutable ? false : req.clientIp // Only use Ip that is externally route-able / Public
    }
    const params = {
      clientId, 
      clientSecret, 
      domain, 
      callbackUrl: callbackURL.toString(),
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
      const promises = [];
      if (tokens.access_token) {
        promises.push(auth0.verifyApiToken(tokens.access_token))
        promises.push(auth0.getUserInfo({token: tokens.access_token}))
      }
      if (tokens.id_token) {
        promises.push(auth0.verifyIdToken(tokens.id_token))
      }
      const result = await Promise.all(promises).catch(e => {throw e});
      const info = {};
      if (tokens.access_token) {
        info.apiToken = result[0]
        info.user = result[1]
        if (tokens.id_token) info.idToken = result[2]
      } else if (tokens.id_token) info.idToken = result[0]
      return {
        provider,
        accessToken: tokens.access_token,
        tokens,
        info
      }
    }
    try {
      if (req.path === path) {
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
          return redirect(req, res, auth0.getAuthorizeUrl({silentPrompt}));
        } else return next(req, res, ...args)
      }
      else if (req.path === callbackURL.pathname) {
        // https://nodejs.org/api/url.html#url_constructor_new_urlsearchparams_string
        const searchParams = new URLSearchParams (req.search)
        if (searchParams.has('error')) { // error parameter from query send by authentication server
          if (!session.prompt) {
            return redirect(req, res, auth0.getAuthorizeUrl({silentPrompt:false}));
          }
          else throw new Error(searchParams.get('error') + ': ' + searchParams.get('error_description') );
        } else if (!session.verifyState(searchParams.get('state'))) {
          throw new Error('Invalid state: ' + searchParams.get('state'));
        }

        const tokens = await auth0.getOAuthAccessToken({code: searchParams.get('code')})
                        .catch(e => {throw e});

        const result = await getResult({tokens})
                              .catch(e => {throw e});
        
        session.delState(searchParams.get('state'));
        args.push({ result });
        return next(req, res, ...args);
      }
      else if (Array.isArray(whitelist) && pathToRegexp(whitelist).test(req.path)) {
          return next(req, res, ...args)
        }
      else if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
        throw new Error('Missing Authorization header');
      }
      else {
        const result = await getResult({
          tokens : {
            access_token : req.headers.authorization.replace('Bearer ', '')
          }
        }).catch(e => {throw e});
        args.push({ result });
        return next(req, res, ...args);
      }
    } catch (err) {
      console.error(err)
      args.push({ err, provider });
      return next(req, res, ...args);
    }
  }}
};