const Issuer = require('./issuer')
const User = require('./user')
const Verifier = require('./verifier')

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

    const buf = user.encode()
    const sameUser = User.decode(buf)

    // user selects which attributes to show
    const present = sameUser.present(['age', 'drivers licence'])

    verifier.validate(present, function (err, identifier) {
      if (err) throw err
      console.log('credential has been accepted.')

      const keys = {
        pk: Buffer.alloc(32),
        sk: Buffer.alloc(64)
      }

      identifier.pk = user.identities[0].pseudonym.loadIdentity(130, keys).pk

      org.revokeCredential(identifier, function (err, i) {
        verifier.certifications[certId].revocationList.feed.on('download', async () => {
          const presentRevoked = user.present(['age', 'drivers licence'])

          const failure = verifier.validate(presentRevoked, function (err) {
            if (err) throw err
          })
        })
      })
    })
  })
})
