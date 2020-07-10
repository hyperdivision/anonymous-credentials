const assert = require('nanoassert')
const keys = require('./keygen')
const hash = require('sha256-wasm')
const IssuingProtocol = require('./issuance.js')

const hasProperty = Object.prototype.hasOwnProperty

module.exports = class {
  constructor (schema) {
    this.schema = schema
    this.blacklist = []
    this.credentials = []
    this.certId = shasum(JSON.stringify(schema)).toString('hex')

    this.keys = {}
    this.keys.signing = keys.signingKeys()
    this.keys.cert = keys.issuingKeys(Object.keys(schema).length + 1)
    this.keys.pk = {
      org: this.keys.signing.pk,
      credential: this.keys.cert.pk
    }
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
      blacklist: this.blacklist
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

   revoke (revokeKey) {
    const revokeRoot = this.credentials.map(c => c.root).find(keys.findRoot(revokeKey, 256))
    console.log(revokeRoot)

    if (this.credentials.find(cred => cred.root === revokeRoot) === undefined) {
      throw new Error('credential does not belong to this certificate')
    }

    const revokedKeys = keys.genIdentifiers(revokeRoot, 256).map(keys.idToKeys)
    for (let key of revokedKeys) this.blacklist.push(key.pk)
    return revokeRoot
  }
}

function check (cond, msg) {
  if (!cond) throw new Error(msg)
}

function shasum (data) {
  return hash().update(data).digest()
}
