# Anonymous Credentials

Anonymous credential scheme based on https://eprint.iacr.org/2017/115.pdf

## Usage

### Issuer
```js
const issuer = new Issuer('./some-storage-path')

const schema = {
  "age": "number",
  "nationality": "string",
  "residence": "string",
  "drivers licence": "boolean",
  "employed": "boolean",
  "gender": "string"
}

issuer.addCertification(schema, (certId) => {
  // do something with certId, e.g list online

  // answer a verifier's request for this certification
  const certInfo = issuer.getCertInfo(certId)
})
```

Now the issuer is ready to grant credentials from the certification.

### Verifier

A new verifier must first add the certifications it is willing to accept. They may request the necessary info associated with `certId` from the issuer

```js
const verifier = new Verifier('./some-other-storage')

verifier.registerCertification(certInfo, () => {
  // verifier online
})
```

### User

The user should have obtained `certId` from a public list. Now they may send an application for a credential:

```js
const user = new User()

const application = {
  "age": 66,
  "nationality": "italy",
  "residence": "austria",
  "drivers licence": true,
  "employed": true,
  "gender": "male"
}

 /* --- Client Side --- */

const app = user.apply(application, certId)

(app, { metadata }) --> server // metadata should be proof of ID

 /* --- Server Side --- */
(app) => {
  const issuanceInit = issuer.addIssuance(app)
}

(issuanceInit) --> client

 /* --- Client Side --- */

(issuanceInit) => {
  const issuanceResponse = user.obtain(issuanceInit)
}

(issuanceResponse) --> server

 /* --- Server Side --- */

(issuanceResponse) => {
  const final = issuer.grantCredential(issuanceResponse)
}

(final) --> client

 /* --- Client Side --- */

(final) => {
  user.store(final)
}
```

Now the user has a credential, which they may present to a verifier:

```js
 /* --- Client Side --- */

const transcript = user.present(['age', 'nationality'])

(transcript) --> verifier

 /* --- Server Side --- */

verifier.validate(transcript, (err, identifier) => {
  if (err) {
    // handle reject user
  }

  // identifier should be associated with this user
  // as it is needed to report malicious parties
})
```

If a malicious user is detected, the `transcript` associated with their credential may be reported to the issuer and, if appropriate, the issuer may revoke the entire credential:

```js
/* --- Verifier --- */ 

(identifier, { incidentReport }) --> issuer

/* --- Issuer --- */ 

// check incidentReport, if user is at fault:
(identifier) => {
  issuer.revokeCredential(identifier, (err) => {
    // user has now been revoked
  })
}
```

## API

### Issuer

#### const org = new Issuer(storage)

Instatiate a new Issuer instance. `storage` designates the path which shall be used to store revocation list information.

#### org.addIssuance(application)

Begin a new issuance protocol. This method takes a user's `application`, which is the output of `user.apply` and outputs a `setup` object, encoding blinded curve points that are used to generate the credential, which may be passed straight to the user.

#### org.grantCredential(res)

This is the Issuer's final step during issuance and takes the output of `user.obtain`. In this step the Issuer contributes entropy towards the users credential and seals the credential by exponentiating the product of all curve points in the credential by the Issuer's secret key. This term is used in a bilinear pairing equality to verify the sum of exponents during verification of the credential.

#### async org.revokeCredential(identifier, cb())

Revoke a credential associated with a given `identifier`. This method shall publish the root id associated with this key to the certifications revocation list, anyone subscribed to the revocation list may then derive all keys associated with the root id and checks against these keys during verification.

#### async org.addCertification(schema, cb(certId))

Register a new certification. Takes a JSON `schema` specifying field titles and types and returns the resulting ertification's `certId`,  a unique identifier string, to the callback provided.

The certification is stored in `issuer.certifications` under it's `certId` and may be accessed by `issuer.certifications[certId]`.

#### const certInfo = org.getPublicCert(certId)

Get the public keys and revocation list informnation associated with a given `certId`. This info is passed to a verifier for them to recognise new certifications. `certInfo` is returned as a `buffer` containing the serialized information to be passed to a verifier.


### User

#### const user = new User()

Instantiate a new User.

### const application = user.apply(details, certId)

Generate an application with the relevant details to send to the Issuer responsible for `certId`. When sending this to the issuer, this should be accompanied by a document proving these properties, e.g. photo ID.

### const issuanceResponse = user.obtain(msg)

The user's contribution in the issuance protocol. This takes the output of `issuer.addIssuance` as a `buffer` and returns an `buffer` containing the serialized response.

In this step the user generates random scalars used to exponentiate the blinded curve points received from `addIssuance` message and returns them to the issuer, thereby contributing her own entropy to the certificate.

### user.store(msg)

Store a completed credential. `msg` should be a `buffer` outputted by a call to `issuer.grantCredential`, which contains the serialization of the finalised credential and the issuer's signatures for all pseudonyms associated with this id.

This will be stored internally as a new `Identity`, which has associated with it a credential as well as the `root` from which all pseudonyms are derived. This `Identity` can be later accessed using the `findId` method below or accessed directly from `user.identities`.

### const transcript = user.present(attributes)

Generate a transcript showing a valid credential, only disclosing the properties specified in `attributes`. `properties` should be passed as an `array` of `strings`, e.g `['age', 'nationality']`; an appropriate identity with the required attributes is then chosen to present.

Returns a `buffer` containing the serialized data required by a verifier to validate the credential. `transcript` should be passed as an argument to `verifier.validate`

### const id = user.findId(required)

Access an identity containing the attributes listed in `required`. Takes an `array` of `strings`, e.g `['age', 'nationality']`, and returns `id` as an instance of an `Identity` object.


### Verifier

#### const verifier = new Verifier(storage)

Instantiate a new Verifier. `storage` should be a path designated where revocation list data shall be stored.

#### async verifier.validate(transcript, cb(err, identifier))

Validate a given `transcript`, which is the `buffer` returned by `user.present`. `cb` should have the signature `cb(err)` . An error message shall be passed to `cb` if validation fails.

`identifier` is needed when reporting bad users to the issuing party, therefore it should be associated with that user account.

#### async verifier.registerCertification(cert, cb())

Recognise a new certification. `cert` is a `buffer` as outputted of `org.getCertInfo(certId)`, containing the serialization of the certification public keys and the information needed to sync the `revocation list` associated with the certification.


## How it works

### Credential

The credential scheme itself is described in [An efficient self-blindable attribute-based credential scheme](https://eprint.iacr.org/2017/115.pdf). The principle is that each field has an associated curve point in G1. The user's attributes are encoded as scalars and used exponentiate their associated curve point. Express the product of these exponentiated curve points as `C`, the issuer provides a signature over this product by exponentiating `C` by a secret key, `z`, yielding `T = C * z`. The user's public key is the tuple of curve points in G1 and the corresponding secret key is the tuple of associated attributes encoded as scalars.

When showing the credential, the user presents it's public key and the attributes they wish to disclose. We exponentiate the curve points associated with disclosed attributes and negate the terms and then calculate the product of these terms as D = S<sub>1</sub><sup>-k<sub>1</sub></sup> * S<sub>3</sub><sup>-k<sub>3</sub></sup> * ... * S<sub>i</sub><sup>-k<sub>i</sub></sup> (for all i in disclosure set). To prove they know the undisclosed terms, the user can negate C and demonstrate proof of knowledge of all terms needed to satisfy: D = C<sup>-1</sup> * S<sub>0</sub><sup>k<sub>0</sub></sup> * S<sub>2</sub><sup>k<sub>2</sub></sup> * ... * S<sub>j</sub><sup>k<sub>j</sub></sup> (for all j in undisclosed set).

Once this has been proved, the verifier uses a bilinear pairing to check that the relationship `T = C * z` still holds and a second pairing to verifier the user's public key against the issuers public key.

#### Blinding

Because bilinear pairing is verifying the product of exponents, we may exponentiate both sides of the equality with the same blinding factor whilst maintaining the pairing equality. This allows the user to 'self blind' their credential, thus ensuring unlinkability between separate showings.


### Pseudonym

The unlinkability presents an issue in the case of a bad acting user. A service may want to ban a user, but since each showing is unlinkable, they have no way of distinguishing whether a credential belongs to this user. Therefore, a set of pseudonyms are generated from a unique root and signed by the Issuer for each credential. Each pseudonym has a keypair associated with it and each credential showing is signed by the pseudonym's keypair. The user then presents the verifier with the `transcript`, `transcriptSignature`, `pseudonymPublicKey` and `certSig`. The `certSig` is first validated over the `pseudonymPublicKey` against the organisation's key to make sure this pseudonym is certified. Then the transcript signature is validated, and finally the credential showing is validated.

### Revocability

A service can report a `pseudonymPublicKey` to the Issuer to have them revoked. The Issuer may then determine which identity this pseudonym belongs to and publish the `root` to a revocation list associated with the certification. Verifiers interested in this certification subscribe to the revocation list and calculate the `pseudonymPublicKey`s associated with the revocation listed user and can check each new user against this list.
