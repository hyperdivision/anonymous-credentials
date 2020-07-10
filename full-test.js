const Issuer = require('./issuer')
const User = require('./user')
const cert = require('./example.json')
const Verifier = require('./verifier')
const verify = require('./verify')
const attributes = require('./gen-attributes')

const org = new Issuer()
const user = new User()
const verifier = new Verifier()

// register the certification
const certId = org.registerCertification(cert)

// add the cert to the verifiers recognised certifications
verifier.addCertification(org.certifications[certId].getInfo())

const application = {
  "age": 66,
  "nationality": "italy",
  "residence": "austria",
  "drivers licence": true,
  "employed": true,
  "gender": "male"
}

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
const success = verifier.validate(present)
console.log(success)

const keys = {
  pk: Buffer.alloc(32),
  sk: Buffer.alloc(64)
}

const revoke = user.identities[0].pseudonym.loadIdentity(130, keys).pk

org.revokeCredential(revoke, certId)
verifier.certifications[certId].blacklist = org.certifications[certId].blacklist

const presentRevoked = user.present(['age', 'drivers licence'])
const failure = verifier.validate(presentRevoked)
console.log(failure)
