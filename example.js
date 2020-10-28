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

let org = new Issuer('./storage/org')
const users = []
let verifier = new Verifier('./storage/verifier')

// register the certification
org.addCertification(schema, function (certId) {
  // add the cert to the verifiers recognised certifications
  verifier.registerCertification(org.getPublicCert(certId), function () {
    newUsers(3, () => {
      // user selects which attributes to show
      let index = Math.floor(Math.random() * users.length)
      let user = users[index]

      // test user encoding
      user = User.decode(user.encode())

      // 512ms
      const present = user.present(['age', 'drivers licence', 'gender'])

      // test verifier encoding
      verifier = Verifier.decode(verifier.encode())

      // 1130ms
      verifier.validate(present, function (err, identifier) {
        if (err) throw err
        console.log('credential has been accepted.')

        // test issuer encoding
        org = Issuer.decode(org.encode())

        // 390ms
        org.revokeCredential(identifier, function (err, revinfo) {
          verifier.updateCertifications(revinfo)

          users.forEach(u => u.updateNonRevocationWitnesses(revinfo))
          const presentRevoked = user.present(['age', 'drivers licence'])

          verifier.validate(presentRevoked, function (err) {
            if (err) console.error(err)

            while (true) {
              const newIndex = Math.floor(Math.random() * users.length)
              if (newIndex === index) continue

              index = newIndex
              break
            }

            const newUser = users[index]

            verifier.validate(newUser.present(['age', 'nationality', 'drivers licence', 'employed']), (err) => {
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

      // ~0.3ms
      const app = user.apply(application, certId)

      // ~24ms
      const setup = org.addIssuance(app)

      // ~67ms
      const obtain = user.obtain(setup)

      // ~188ms
      const granted = org.grantCredential(obtain)

      // ~216ms
      user.store(granted)

      newUsers(--i, cb)
    }
  })
})
