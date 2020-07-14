const assert = require('nanoassert')
const keys = require('./lib/keygen')
const hash = require('sha256-wasm')
const RevocationList = require('./revocation-list')
const IssuingProtocol = require('./issuance.js')

const hasProperty = Object.prototype.hasOwnProperty

module.exports = class Certification {
  constructor (schema, storage, opts) {
    this.schema = schema
    this.credentials = []
    this.certId = shasum(JSON.stringify(schema)).toString('hex')

    this.revocationList = null

    this.keys = {}
    this.keys.signing = keys.signingKeys()
    this.keys.cert = keys.issuingKeys(Object.keys(schema).length + 1)
    this.keys.pk = {
      org: this.keys.signing.pk,
      credential: this.keys.cert.pk
    }

    this.init(storage, opts.oninit)
  }

  init (storage, cb) {
    this.revocationList = new RevocationList(storage, this.certId)
    this.revocationList.create(cb)
  }

  validate (application) {
    for (const [field, type] of Object.entries(this.schema)) {
      check(Object.prototype.hasOwnProperty.call(application, field), `${field} is required.`)
      check(typeof application[field] === type)
    }
  }

  getInfo () {
    return {
      pk: this.keys.pk,
      schema: this.schema,
      certId: this.certId,
      revocationListKey: this.revocationList.feed.key
    }
  }

  genIdentity () {
    return keys.userIds(this.keys.signing, 256)
  }

   issue (details) {
    this.validate(details)

    const issuance = new IssuingProtocol(this.keys.cert, Object.values(details))
    issuance.certId = this.certId

    return issuance
  }

   revoke (revokeKey, cb) {
    const revokeRoot = this.credentials.map(c => c.root).find(keys.findRoot(revokeKey, 256))

    if (this.credentials.find(cred => cred.root === revokeRoot) === undefined) {
      throw new Error('credential does not belong to this certificate')
    }

    this.revocationList.add(revokeRoot, cb)
  }
}

function check (cond, msg) {
  if (!cond) throw new Error(msg)
}

function shasum (data) {
  return hash().update(data).digest()
}
