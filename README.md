# microauth-auth0

> Auth0 oauth for [micro](https://github.com/zeit/micro/)

Add [Auth0](https://auth0.com) authentication to your [micro](https://github.com/zeit/micro/) service as easy as a flick of your fingers.
This module is meant to be used like a module from [microauth](https://github.com/microauth/microauth) collection.

## Installation (soon)

```sh
npm install --save microauth-auth0
# or
yarn add microauth-auth0
```

## Usage (soon)

app.js
```js
const { send } = require('micro');
const microAuthAuth0 = require('microauth-auth0');

const options = {
  clientId: 'CLIENT_ID',
  clientSecret: 'CLIENT_SECRET',
  callbackUrl: 'http://localhost:3000/auth/auth0/callback',
  path: '/auth/auth0',
  scope: ''
};

const auth0 = microAuthAuth0(options);

// Third `auth` argument will provide error or result of authentication
// so it will { err: errorObject} or { result: {
//  provider: 'slack',
//  accessToken: 'blahblah',
//  info: userInfo
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

  return `Hello ${auth.result......}`;

};

module.exports = auth0(handler);

```

Run:
```sh
micro app.js
```

Now visit `http://localhost:3000/auth/auth0`


## Author
