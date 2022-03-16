const jose = require('node-jose');

const opts = {
  handlers: {
    "exp": {
      complete: function(jws) {
        // {jws} is the JWS verify output, post-verification
        const payload = JSON.parse(jws.payload.toString());
        jws.payload = payload;
        jws.signature = jws.signature.toString('hex');
      }
    }
  }
};

async function verifyJTW(jwks, jwt) {
  const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64'));
  const jwk = jwks.keys.find(jwk => jwk.kid == header.kid) || jwks.keys[0];
  const key = await jose.JWK.asKey(Buffer.from(jwk.x5c[0], 'base64'), "x509");
  return await jose.JWS.createVerify(key, opts).verify(jwt);
}

// browserify verify_jwt.js --standalone sgx -o ../docs/attest.js
module.exports.verifyJTW = verifyJTW;
