const util = require('util')
const Issuer = require('./issuer')
const User = require('./prover')
const Verifier = require('./verifier')
const curve = require('./lib/curve')

const schema = {
  'drivers licence': 'boolean',
  age: 'number',
  nationality: 'string',
  gender: 'string',
  residence: 'string',
  employed: 'boolean'
}

const application = {
  gender: 'male',
  age: 66,
  'drivers licence': true,
  residence: 'austria',
  nationality: 'italy',
  employed: true
}

const org = new Issuer('./storage/org')
const users = []
const verifier = new Verifier('./storage/verifier')

// register the certification
org.addCertification(schema, function (certId) {
  // add the cert to the verifiers recognised certifications
  verifier.registerCertification(org.getPublicCert(certId), function () {
    newUsers(3, () => {
      // user selects which attributes to show
      let index = Math.floor(Math.random() * users.length)
      const user = users[index]

      const present = user.present(['age', 'drivers licence', 'gender'])
      // console.log(util.inspect(present, false, null, true /* enable colors */))
      const newVerifier = Verifier.decode(verifier.encode())

      newVerifier.validate(present, function (err, identifier) {
        if (err) throw err
        console.log('credential has been accepted.')

        const newOrg = Issuer.decode(org.encode())

        // 1400ms
        // console.log(util.inspect(org.certifications[0].keys.pk, false, null, true /* enable colors */))
        // console.log(util.inspect(newOrg.certifications[0].keys.pk, false, null, true /* enable colors */))
        // throw new Error
        newOrg.revokeCredential(identifier, function (err, revinfo) {
          newVerifier.updateCertifications(revinfo)

          users.forEach(u => u.updateNonRevocationWitnesses(revinfo))
          const presentRevoked = user.present(['age', 'drivers licence'])

          const failure = newVerifier.validate(presentRevoked, function (err) {
            if (err) console.error(err)

            while (true) {
              const newIndex = Math.floor(Math.random() * users.length)
              if (newIndex === index) continue

              index = newIndex
              break
            }

            const newUser = users[index]

            newVerifier.validate(newUser.present(['age', 'nationality', 'drivers licence', 'employed']), (err) => {
              if (err) console.log(err)
              else console.log('success')
            })
          })
        })
      })
    })

    function newUsers (i, cb) {
      if (i === 0) return cb()

      const user = new User()
      users.push(user)

      // ~0.06ms
      const app = user.apply(application, certId)
      // ~7ms
      const setup = org.addIssuance(app)
      // ~15ms
      const obtain = user.obtain(setup)
      // ~31ms
      const granted = org.grantCredential(obtain)

      // ~1050ms
      user.store(granted)

      newUsers(--i, cb)
    }
  })
})
