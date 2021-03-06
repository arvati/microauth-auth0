const OAuth2 = require('oauth').OAuth2
const jws = require('jsonwebtoken'); //Uses jws
const uuid = require('uuid');
const crypto = require('crypto');
const jwksClient = require('jwks-rsa');
const pkg = require('./package.json');

function encodeClientInfo(obj) {
    const str = JSON.stringify(obj);
    return Buffer.from(str).toString('base64')
        .replace(/\+/g, '-') // Convert '+' to '-'
        .replace(/\//g, '_') // Convert '/' to '_'
        .replace(/=+$/, '') // Remove ending '='
}
function encodeBasicHeader({username, password}) {
    return 'Basic ' + Buffer.from(username.replace(/:\s*/g, '') + ':' + password).toString('base64');
}
function encodeChallenge(verifier) {
    return crypto
    .createHash('sha256')
    .update(verifier)
    .digest()
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

class Auth0 {
    constructor({
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
                    code_verifier
                }) {
        this._customHeaders = {
            "Auth0-Client": encodeClientInfo({ name: pkg.name, version: pkg.version })
        }
        this._clientId = clientId;
        this._callbackUrl = callbackUrl;
        this._connection = connection;
        this._audience = audience;
        this._scope = scope;
        this._clientSecret = clientSecret;
        this._domain = domain;
        this._noState = noState;
        this._send_ip = send_ip;
        this._algorithm = algorithm;
        this._allowPost = allowPost;
        this._realm = realm;
        this._code_verifier = code_verifier;
        this._basicAuth = !this._clientSecret ? false : basicAuth // Only Basic Auth when we have a password
        if (this._basicAuth) this._customHeaders["Authorization"] = encodeBasicHeader({username: this._clientId, password: this._clientSecret});
        if (this._send_ip) this._customHeaders["auth0-forwarded-for"] = this._send_ip
        this._oauth2 = new OAuth2(
            this._clientId, 
            this._clientSecret,
            'https://' + this._domain, 
            '/authorize', 
            '/oauth/token', 
            this._customHeaders
        );
        this._oauth2.useAuthorizationHeaderforGET(true);
        this._oauth2.setAccessTokenName("access_token");
        this._oauth2.setAuthMethod("Bearer");
    }

    decodeJws(signature){
        return jws.decode(signature, {complete: true, json:true})
    }
    async verifyIdToken(token){ // only verify token if scope contains openid
        return !this._scope.split(' ').includes('openid') ? {} : await this.verifyToken({token, audience: this._clientId}).catch(e => {throw e});
    }
    async verifyApiToken(token){ // only verify token if audience is set
        return !this._audience ? {} : await this.verifyToken({token, audience: this._audience}).catch(e => {throw e});
    }
    verifyToken({token, audience, algorithms = this._algorithm}) {
        var _self = this;
        return new Promise(function (resolve, reject) {
            const client = jwksClient({
                strictSsl: true, // Default value
                cache: true,
                cacheMaxEntries: 5, // Default value
                cacheMaxAge: 10 * 60 * 60 * 1000,  // 10 hours = Default value
                rateLimit: true,
                jwksRequestsPerMinute: 60, // Default value
                jwksUri: 'https://' + _self._domain + '/.well-known/jwks.json',
            });
            const SecretKey = (header,callback) => {
                if (header.alg === 'HS256' && _self._clientSecret) callback(null, _self._clientSecret) ;
                else if (header.alg === 'RS256') {
                    client.getSigningKey(header.kid, (error, key) => {
                        if (error) callback(error);
                        else {
                            var signingKey = key.publicKey || key.rsaPublicKey;
                            callback(null, signingKey);
                        }
                    })
                }
                else callback('Not valid algorithm: ' + header.alg);
            }
            jws.verify(token, SecretKey, {
                    algorithms: algorithms.split(" "),
                    audience,
                    issuer: 'https://' + _self._domain + '/',
                    complete: false,
                    ignoreExpiration: false
                }, 
                (err, decoded) => {
                    if (err) reject(err);
                    else {
                        resolve(decoded)
                    }
            });
        })
    }
    getAuthorizeUrl({silentPrompt, state = uuid.v4(), response_type = "code"}) {
        // https://auth0.com/docs/flows/guides/auth-code/add-login-auth-code#authorize-the-user
        const params = { response_type:response_type }
        if (this._code_verifier) {
            params.code_challenge_method = 'S256'
            params.code_challenge = encodeChallenge(this._code_verifier)
        }
        if (silentPrompt) params.prompt = 'none'
        if (this._callbackUrl) params.redirect_uri = this._callbackUrl
        if (this._scope) params.scope = this._scope
        if (this._audience) params.audience = this._audience
        if (!this._noState) params.state = state
        if (this._connection) params.connection = this._connection
        return this._oauth2.getAuthorizeUrl(params)
    }
    getOAuthAccessToken({code, grant_type = 'authorization_code', username, password}) {
        var _self = this;
        return new Promise(function (resolve, reject) {
            const params = { grant_type: grant_type }
            if (grant_type === 'password') {
                // Make sure there are all parameters set
                if (!username || !password || !_self._clientSecret || !_self._allowPost) 
                    reject(new Error('This grant type \"' + grant_type + '\" requires clientSecret, allowPost and user credentials' ))
                // if audience set and alloPost set to realm change grant_type to it
                if (_self._realm) {
                    params.grant_type = 'http://auth0.com/oauth/grant-type/password-realm'
                    params.realm = _self._realm
                }
                if (_self._audience) params.audience = _self._audience
                if (_self._scope) params.scope = _self._scope
                params.username = username
                params.password = password
                code = null
            } else if (grant_type === 'client_credentials') {
                if (!_self._clientSecret || !_self._audience) 
                    reject(new Error('This grant type \"' + grant_type + '\" requires clientSecret and audience' ))
                params.audience = _self._audience
                code = null
            } else if (grant_type === 'refresh_token') {
                if (!code && this._scope.split(' ').includes('offline_access')) 
                    reject(new Error('This grant type \"' + grant_type + '\" requires refresh_token as {code} parameter and scope contains offline_access' ))
            } else if (grant_type === 'authorization_code') {
                if (!code) 
                    reject(new Error('This grant type \"' + grant_type + '\" requires code received from /authorize' ))
                if (_self._callbackUrl) params.redirect_uri = _self._callbackUrl
                if (_self._code_verifier) params.code_verifier = _self._code_verifier
            }
            _self._oauth2.getOAuthAccessToken(code, params, 
                 (err, access_token, refresh_token, results) => {
                    if (err) reject(err);
                    else {
                        resolve({
                            access_token, 
                            refresh_token, 
                            id_token: results.id_token, 
                            token_type: results.token_type,
                            expires_in: results.expires_in,
                            scope: results.scope
                        })
                    }
                 });
            })
    }
    
    getUserInfo({token}) {
        var _self = this;
        return new Promise(function (resolve, reject) {
            _self._oauth2.get( 'https://' + _self._domain + '/userinfo',token,
            (err, result, response) => {
                if (err) reject(err);
                else {
                    resolve(JSON.parse(result))
                }
            })
        })
    }
};
module.exports = Auth0;