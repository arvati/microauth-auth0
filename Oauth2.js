const OAuth2 = require('oauth').OAuth2
const jws = require('jws');
const uuid = require('uuid');
const jwksClient = require('jwks-rsa');
const pkg = require('./package.json');
const Profile = require('./Profile');

function encodeClientInfo(obj) {
    const str = JSON.stringify(obj);
    return new Buffer(str).toString('base64')
        .replace(/\+/g, '-') // Convert '+' to '-'
        .replace(/\//g, '_') // Convert '/' to '_'
        .replace(/=+$/, ''); // Remove ending '='
  }
  

class Oauth2 {
    constructor({clientId, clientSecret, domain, callbackUrl, connection, scope}) {
        this._clientId = clientId;
        this._callbackUrl = callbackUrl;
        this._connection = connection;
        this._scope = scope;
        this._clientSecret = clientSecret;
        this._domain = domain;
        this._clientInfoHeader = encodeClientInfo({ name: pkg.name, version: pkg.version });
        this._oauth2 = new OAuth2(this._clientId, this._clientSecret,
            'https://' + this._domain, '/authorize', '/oauth/token', { 'Auth0-Client': this._clientInfoHeader});
        this._oauth2.useAuthorizationHeaderforGET(true);
        this._oauth2.setAccessTokenName("access_token");
        this._oauth2.setAuthMethod("Bearer");
    }

    decodeJws(signature){
        const jwt = jws.decode(signature)
        console.log(jwt)
        return jwt
    }
    verifyToken(signature){
        var result = false;
        this.getSecretKey({signature:signature})
        .then(({algorithm,secretOrKey}) => {
            result = jws.verify(signature, algorithm, secretOrKey)
        })
        return result;
    }
    getAuthorizeUrl({state = uuid.v4(), response_type = "code"}) {
        // https://auth0.com/docs/flows/guides/auth-code/add-login-auth-code#authorize-the-user
        const params = {
            response_type:response_type,
            client_id:this._clientId,
            redirect_uri:this._callbackUrl,
            scope:this._scope, 
            state:state}
        if (this._connection) params.connection = this._connection
        return this._oauth2.getAuthorizeUrl(params)
    }

    getOAuthAccessToken({code, grant_type = 'authorization_code'}) {
        var _self = this;
        return new Promise(function (resolve, reject) {
            _self._oauth2.getOAuthAccessToken(code,
                { grant_type: grant_type, client_id: _self._clientId, client_secret: _self._clientSecret, redirect_uri: _self._callbackUrl },
                 (error, access_token, refresh_token, results) => {
                    if (error) reject({error});
                    else {
                        resolve({access_token, refresh_token, id_token: results.id_token, token_type: results.token_type})
                    }
                 });
            })
    }
    getSecretKey({signature}) {
        var _self = this;
        const header = _self.decodeJws(signature).header;
        return new Promise(function (resolve, reject) {
            if (header.alg === 'HS256') resolve({algorithm: header.alg, secretOrKe: _self._clientSecret}) ;
            else if (header.alg === 'RS256') {
                const client = jwksClient({
                    strictSsl: true, // Default value
                    jwksUri: 'https://' + _self._domain + '/.well-known/jwks.json',
                  });
                client.getSigningKey(header.kid, (error, key) => {
                    if (error) reject({error});
                    else {
                        const signingKey = key.publicKey || key.rsaPublicKey;
                        resolve({
                            algorithm: header.alg,
                            secretOrKey: signingKey})
                    }
                })
            }
            else reject(new Error('Not valid algorithm'));
            });
    }
    getProfile({access_token}) {
        var _self = this;
        return new Promise(function (resolve, reject) {
            _self._oauth2.get( 'https://' + _self._domain + '/userinfo',access_token,
            (error, result, response) => {
                if (error) reject({error});
                else {
                    const json = JSON.parse(result);
                    const profile = new Profile(json, result);
                    resolve({profile})
                }
            })
        })
    }
};
module.exports = Oauth2;