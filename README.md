# microauth-auth0

> Auth0 oauth for [micro](https://github.com/zeit/micro/)

Add [Auth0](https://auth0.com) authentication to your [micro](https://github.com/zeit/micro/) service as easy as a flick of your fingers.
This module is meant to be used like a module from [microauth](https://github.com/microauth/microauth) collection.

## Installation

```sh
npm install --save microauth-auth0
# or
yarn add microauth-auth0
```

## Configuration

Take your credentials from the settings section in the [Auth0 dashboard](https://manage.auth0.com/#/applications) :
* Allowed Callback URLs:	'http://localhost:3000/auth/auth0/callback'
* Domain:			'your-domain.auth0.com'
* Client ID:			'your-client-id'
* Client Secret:		'your-client-secret'

## Usage

app.js
```js
const send = require('micro').send;
const microAuthAuth0 = require('.');
require('dotenv-safe').config();

const options = {
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  callbackUrl: process.env.AUTH0_CALLBACKURL, // 'http://localhost:3000/auth/auth0/callback'
  connection: null, // Forces the user to sign in with a specific connection
  path: '/auth/auth0',
  scope: 'openid email address phone profile offline_access' 
  // profile scope = name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at
};

const auth0 = microAuthAuth0(options);

// Third `auth` argument will provide error or result of authentication
// so it will { err: errorObject} or { result: {
//  provider: 'auth0',
//  accessToken: 'blahblah',
//  tokens: all tokens
//  info.userInfo
//  info.token // decoded token id
// }}

const handler = async (req, res, auth) => {

  if (!auth) {
    return send(res, 404, 'Not Found');
  }

  if (auth.err) {
    // Error handler
    console.error(auth.err);
    return send(res, 403, 'Forbidden');
  }

  // Save something in database here

  return `Hello ${auth.result.info.user.nickname} !`;

};

module.exports = auth0(handler);

```

Run:
```sh
micro app.js
```

Now visit `http://localhost:3000/auth/auth0`


## Author
[Ademar Arvati Filho](https://github.com/arvati)    
[Contributors](AUTHORS.md)
