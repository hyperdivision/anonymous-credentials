# Anonymous Credentials

Anonymous credential scheme based on https://eprint.iacr.org/2017/115.pdf


## API

### Issuer

#### const org = new Issuer(storage)

Instatiate a new Issuer instance. `storage` designates the path which shall be used to store blacklist information.

#### org.addIssuance(application)

Begin a new issuance protocol. This method takes a user's `application`, which is the output of `user.apply` and outputs a `setup` object, encoding blinded curve points that are used to generate the credential, which may be passed straight to the user.

#### org.grantCredential(res)

This is the Issuer's final step during issuance and takes the output of `user.obtain`. In this step the Issuer contributes entropy towards the users credential and seals the credential by exponentiating the product of all curve points in the credential by the Issuer's secret key. This term is used in a bilinear pairing equality to verify the sum of exponents during verification of the credential.

#### org.revokeCredential(revokeKey, certId, [callback])

Revoke a credential associated with a given `revokeKey`. This method shall publish the root id associated with this key to the certifications blacklist, anyone subscribed to the blacklist may then derive all keys associated with the root id and checks against these keys during verification.

#### org.registerCertification(schema, [callback])

Register a new credential. Providing a JSON `schema` specifying field titles and types.

#### org.getCertInfo(certId)

Get the public keys and blacklist informnation associated with a given `certId`. This info is passed to a verifier for them to recognise new certifications. 


### User

#### const user = new User()

Instantiate a new User.

### user.apply(details, certId)

Generate an application with the relevant details to send to the Issuer responsible for `certId`. When sending this to the issuer, this should be accompanied by a document proving these properties, e.g. photo ID.

### user.obtain(msg)

The user's part in the issuance protocol, the user generates random scalars to exponentiate the blinded curve points received from `org.addIssuance` and returns them to the issuer.

### user.store(msg)

Store a completed credential. `msg` contains the finalised credential and the Issuer's signatures for all pseudonyms associated with this id. This will be stored internally as a new `Identity`, which has associated with it a credential as well as the `root` from which all pseudonyms are derived.

### user.present(attributes)

Generate a transcript showing a valid credential, only disclosing the properties specified in `attributes`.

### user.findId(required) 


### Verifier

#### const verifier = new Verifier(storage)

Instantiate a new Verifier. `storage` should be a path designated where blacklist data shall be stored.

#### verifier.validate(transcript, cb)

Validate a given `transcript` output from `user.present`. Returns `false` if validation fails and `true` otherwise

#### verifier.addCertification(cert, cb)

Recognise a new certification. `cert` is the output of `org.getCertInfo(certId)`, containing the certification public keys and the information needed to sync the `blacklist` associated with the certification.


## How it works

### Credential

The credential scheme itself is described in [An efficient self-blindable attribute-based credential scheme](https://eprint.iacr.org/2017/115.pdf). The principle is that each field has an associated curve point in G1. The user's attributes are encoded as scalars and used exponentiate their associated curve point. Express the product of these exponentiated curve points as `C`, the issuer provides a signature over this product by exponentiating `C` by a secret key, `z`, yielding `T = C * z`. The user's public key is the tuple of curve points in G1 and the corresponding secret key is the tuple of associated attributes encoded as scalars.

When showing the credential, the user presents it's public key and the attributes they wish to disclose. We exponentiate the curve points associated with disclosed attributes and negate the terms and then calculate the product of these terms as `D = S<sub>1</sub.<sup>-k<sub>1</sub></sup> * S<sub>3</sub.<sup>-k<sub>3</sub></sup> * ... * S<sub>i</sub.<sup>-k<sub>i</sub></sup> (for all i in disclosure set)`. To prove they know the undisclosed terms, the user can negate `C` and demonstrate proof of knowledge of all terms needed to satisfy: `D = C<sup>-1</sup> * S<sub>0</sub.<sup>k<sub>0</sub></sup> * S<sub>2</sub.<sup>k<sub>2</sub></sup> * ... * S<sub>j</sub.<sup>k<sub>j</sub></sup> (for all j in undisclosed set)`.

Once this has been proved, the verifier uses a bilinear pairing to check that the relationship `T = C * z` still holds and a second pairing to verifier the user's public key against the issuers public key.

#### Blinding

Because bilinear pairing is verifying the product of exponents, we may exponentiate both sides of the equality with the same blinding factor whilst maintaining the pairing equality. This allows the user to 'self blind' their credential, thus ensuring unlinkability between separate showings.


### Pseudonym

The unlinkability presents an issue in the case of a bad acting user. A service may want to ban a user, but since each showing is unlinkable, they have no way of distinguishing whether a credential belongs to this user. Therefore, a set of pseudonyms are generated from a unique root and signed by the Issuer for each credential. Each pseudonym has a keypair associated with it and each credential showing is signed by the pseudonym's keypair. The user then presents the verifier with the `transcript`, `transcriptSignature`, `pseudonymPublicKey` and `certSig`. The `certSig` is first validated over the `pseudonymPublicKey` against the organisation's key to make sure this pseudonym is certified. Then the transcript signature is validated, and finally the credential showing is validated.

### Revocability

A service can report a `pseudonymPublicKey` to the Issuer to have them revoked. The Issuer may then determine which identity this pseudonym belongs to and publish the `root` to a blacklist associated with the certification. Verifiers interested in this certification subscribe to the blacklist and calculate the `pseudonymPublicKey`s associated with the blacklisted user and can check each new user against this list.
