const Issuer = require('./issuer')
const User = require('./user')
const Verifier = require('./verifier')
const curve = require('./lib/curve')

const schema = {
  "age": "number",
  "nationality": "string",
  "residence": "string",
  "drivers licence": "boolean",
  "employed": "boolean",
  "gender": "string"
}

const application = {
  "age": 66,
  "nationality": "italy",
  "residence": "austria",
  "drivers licence": true,
  "employed": true,
  "gender": "male"
}

const org = new Issuer('./storage/org')
const user = new User()
const verifier = new Verifier('./storage/verifier')

// register the certification
org.addCertification(schema, function (certId) {
  // add the cert to the verifiers recognised certifications
  verifier.registerCertification(org.getPublicCert(certId), function () {
    // user applies for an identity
    const app = user.apply(application, certId)

    // issuer starts the issuing protocol
    const setup = org.addIssuance(app)

    // user completes issuing protocol
    const obtain = user.obtain(setup)

    // issuer finalises the credential
    const granted = org.grantCredential(obtain)

    // user stores the credential
    user.store(granted)

    // const buf = user.encode()
    // const sameUser = User.decode(buf)

    const rev = org.certifications[certId].revoker.revoke(curve.randomScalar())
    user.identities[0].identifier.update(rev)

    // verifier.certifications[certId].pk.acc = org.certifications[certId].revoker.pubkey
    // user selects which attributes to show
    const present = user.present(['age', 'drivers licence'])

    verifier.certifications[certId].pk.acc = org.certifications[certId].revoker.pubkey
    verifier.validate(present, function (err, identifier) {
      if (err) throw err
      console.log('credential has been accepted.')

      org.revokeCredential(identifier, function (err, revinfo) {
        verifier.certifications[certId].pk.acc = org.certifications[certId].revoker.pubkey

        const acc = org.certifications[certId].revoker.acc
        const id = user.identities[0].identifier

        user.identities[0].identifier.update(revinfo)

        const presentRevoked = user.present(['age', 'drivers licence'])

        const failure = verifier.validate(presentRevoked, function (err) {
          if (err) throw err
        })
      })
    })
  })
})
