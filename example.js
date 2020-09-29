const util = require('util')
const Issuer = require('./issuer')
const User = require('./user')
const Verifier = require('./verifier')
const curve = require('./lib/curve')

const schema = {
  "drivers licence": "boolean",
  "age": "number",
  "nationality": "string",
  "gender": "string",
  "residence": "string",
  "employed": "boolean"
}

const application = {
  "gender": "male",
  "age": 66,
  "drivers licence": true,
  "residence": "austria",
  "nationality": "italy",
  "employed": true
}

const org = new Issuer('./storage/org')
const users = []
const verifier = new Verifier('./storage/verifier')

// register the certification
org.addCertification(schema, function (certId) {
  // add the cert to the verifiers recognised certifications
  verifier.registerCertification(org.getPublicCert(certId), function () {
    newUsers(3, () => {
      const rev = org.certifications[certId].revoker.revoke(curve.randomScalar())
      users.forEach(u => u.identities[0].identifier.update(rev))

      // verifier.certifications[certId].pk.acc = org.certifications[certId].revoker.pubkey
      // user selects which attributes to show
      let index = Math.floor(Math.random() * users.length)
      let user = users[index]

      const present = user.present(['age', 'drivers licence', 'gender'])
      // console.log(util.inspect(present, false, null, true /* enable colors */))

      verifier.certifications[certId].pk.acc = org.certifications[certId].revoker.pubkey

      verifier.validate(present, function (err, identifier) {
        if (err) throw err
        console.log('credential has been accepted.')

        // 1400ms
        org.revokeCredential(identifier, function (err, revinfo) {
          verifier.certifications[certId].pk.acc = org.certifications[certId].revoker.pubkey

          const acc = org.certifications[certId].revoker.acc
          const id = user.identities[0].identifier

          users.forEach(u => u.identities[0].identifier.update(revinfo))
          const presentRevoked = user.present(['age', 'drivers licence'])

          const failure = verifier.validate(presentRevoked, function (err) {
            if (err) console.error(err)

            while (true) {
              let newIndex = Math.floor(Math.random() * users.length)
              if (newIndex === index) continue

              index = newIndex
              break
            }

            let newUser = users[index]

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
