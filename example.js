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
org.registerCertification(schema, function (certId) {
  // add the cert to the verifiers recognised certifications
  verifier.addCertification(org.getCertInfo(certId), function () {
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

    // user selects which attributes to show
    const present = user.present(['age', 'drivers licence'])
    verifier.validate(present, function (err, success) {
      if (err) throw err
      console.log('credential has been accepted:', success)
      console.log('userId:', present.sig.pk, '\n')

      const keys = {
        pk: Buffer.alloc(32),
        sk: Buffer.alloc(64)
      }

      const revoke = user.identities[0].pseudonym.loadIdentity(130, keys).pk

      org.revokeCredential(revoke, certId, function (err, i) {
        verifier.certifications[certId].revocationList.feed.on('download', () => {
          const presentRevoked = user.present(['age', 'drivers licence'])
          const failure = verifier.validate(presentRevoked, function (err, success) {
            if (err) throw err
          })
        })
      })
    })
  })
})
