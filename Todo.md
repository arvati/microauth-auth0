Implement implicit flow alternative
----
* with audience api - https://auth0.com/docs/api-auth/tutorials/implicit-grant
* with silent authentication - https://auth0.com/docs/api-auth/tutorials/silent-authentication
* authenticantion - https://auth0.com/docs/flows/guides/implicit/add-login-implicit

hints : 
* when implicit scope cannot be "offline_access"
* response_type of type "id_token" and/or "token"
* nonce has to be used
* prompt=none to be silent, check parameter error exists to force login page
* parameters using hash # fragment
* test what response_mode=web_message changes in the response
* http 302 response for /authorize endpoint (regular web too) -- all callback endpoint response
* response contains = id_token  (if id_token, must be decoded and verified), token  (if token, acces token), expires_in (if token), token_type (if token)
* regular web response contain only code and state

Session checking
----
* if session save state as session
* if session include "offline_access" scope and save refresh token into session


API authorization
----
* regular web = https://auth0.com/docs/flows/guides/auth-code/call-api-auth-code
* spa - implicit = https://auth0.com/docs/flows/guides/implicit/call-api-implicit
* token endpoint manual = https://auth0.com/docs/api/authentication#get-token

hints:
* Access Token has to be verified when audience differs from clientID =  https://auth0.com/docs/api-auth/tutorials/verify-access-token
* regular web (grant_type=authorization_code) /oauth/token endpoint http 200 response body POST ('content-type: application/x-www-form-urlencoded') contains access_token, refresh_token, id_token, and token_type.



Refresh Token
----
* grant_type=refresh_token
* client_id=
* refresh_token=
* endpoint is "/oauth/token"
* http 200 response for refresh POST
* response body contains = access_token, expires_in, scope, id_token (only if scopes include openid), token_type

To revoke an refresh_token
* https://auth0.com/docs/tokens/refresh-token/current#revoke-a-refresh-token
* endpoint /oauth/revoke
* POST with http 200 response empty except when error
* body POST with client_id, client_secret (when not implicit or PKCE) and token


Auth using PKCE
----
https://auth0.com/docs/flows/guides/auth-code-pkce/add-login-auth-code-pkce    

Create a code verifier
```js
// Dependency: Node.js crypto module
// https://nodejs.org/api/crypto.html#crypto_crypto
function base64URLEncode(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
var verifier = base64URLEncode(crypto.randomBytes(32));
```
Create a Code Challenge
```js
// Dependency: Node.js crypto module
// https://nodejs.org/api/crypto.html#crypto_crypto
function sha256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest();
}
var challenge = base64URLEncode(sha256(verifier));
```
send into /authorize endpoint parameters:
* response_type=code
* code_challenge_method=S256
* code_challenge=CODE_CHALLENGE  <=== calculated above
* prompt=none for silent


send into /oauth/token endpoint body POST parameters:
* code_verifier  <=== saved from above
* http 200 response contains access_token, refresh_token, id_token and token_type

Public vs Confidential appication
----
https://auth0.com/docs/applications/concepts/app-types-confidential-public#confidential-applications


Login and password
----
* https://auth0.com/docs/api-auth/tutorials/using-resource-owner-password-from-server-side
* https://auth0.com/docs/api-auth/tutorials/password-grant
* https://auth0.com/docs/api/authentication#resource-owner-password


Authentication:
* endpoint = /oauth/token
* application/x-www-form-urlencoded
* Post Body
    * grant_type=password or grant_type=http://auth0.com/oauth/grant-type/password-realm
    * realm if grant_type not password with name of realm (see connection in dashboard)
    * username
    * password
    * audience
    * client_id and client_secret
    * scope
* resource owner enabled connection of one of the following strategies: auth0-adldap, ad, auth0, email, sms, waad or adfs

Request token without user login and user id
----
* https://auth0.com/docs/api/authentication#client-credentials-flow
* This is the OAuth 2.0 grant that server processes use to access an API. Use this endpoint to directly request an Access Token by using the Client's credentials (a Client ID and a Client Secret).
* https://auth0.com/docs/flows/guides/client-credentials/call-api-client-credentials

/oauth/token endpoint
* POST body with http 200 response
* grant_type=client_credential
* client_id
* client_secret
* audience

Basic or Post Authentication
----
* https://community.auth0.com/t/token-endpoint-authentication-method-http-basic-what-is-it/8917/2  

Still POST (Content-Type: application/x-www-form-urlencoded) but client id and client secret goes into header not into body.   
Must before exclude colon ":" from username.

```js
var username = 'Test';
var password = '123';
var auth = 'Basic ' + Buffer.from(username.replace(/:\s*/g, '') + ':' + password).toString('base64');
// new Buffer() is deprecated from v6
//var auth = "Basic " + new Buffer(username + ":" + password).toString("base64");

// auth is: 'Basic VGVzdDoxMjM='
var header = {
    'Host': 'www.example.com', 
    'Authorization': auth
    };
var request = client.request('GET', '/', header);
```



Ip end user
----
* header auth0-forwarded-for = https://auth0.com/docs/api-auth/tutorials/using-resource-owner-password-from-server-side#sending-the-end-user-ip-from-your-server
* this will whitelist the user ip from anomaly detection = https://auth0.com/docs/anomaly-detection


API Authentication
----
* add option to protect self endpoints
* array of whitelist endpoints
* parameter access token or as a autentication bearer
* see micro-jwt-auth = https://github.com/kandros/micro-jwt-auth

Set callBackUrl relative
----
Concatenate Host header <host>:<port> with callback url when there is not a domain
* https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers


Multifactor authentication
----
* https://auth0.com/docs/api-auth/tutorials/multifactor-resource-owner-password
* https://auth0.com/docs/multifactor-authentication


Passwords Lists
----
* https://github.com/danielmiessler/SecLists
* https://haveibeenpwned.com/API/v2
