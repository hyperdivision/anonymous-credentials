const assert = require('nanoassert')
const keys = require('./lib/keygen')
const sodium = require('sodium-native')
const RevocationList = require('./revocation-list')
const { Revoker, Identifier } = require('./experiment/revoker')
const IssuingProtocol = require('./issuance.js')
const inspect = Symbol.for('nodejs.util.inspect.custom');
const curve = require('./lib/curve')

const hasProperty = Object.prototype.hasOwnProperty

class PrivateCertification {
   constructor (opts = {}) {
    this.schema = opts.schema
    this.credentials = opts.credentials || []
    this.certId = opts.certId || null

    this.revoker = opts.revoker || new Revoker()
    // this.revocationList = null
    this.keys = opts.keys || {}

    return this.init(opts, opts.oninit)
  }

  init (opts, cb) {
    if (!this.certId) this.certId = shasum(Buffer.from(JSON.stringify(this.schema))).toString('hex')

    this.keys.cert = opts.issuingKeys || keys.issuingKeys.generate(Object.keys(this.schema).length + 1)
    this.keys.pk = {
      acc: this.revoker.pubkey,
      credential: this.keys.cert.pk
    }

    // this.revocationList = new RevocationList(opts.storage, this.certId)
    // this.revocationList.create(cb)
    return this
  }

  validate (application) {
    for (const [field, type] of Object.entries(this.schema)) {
      check(Object.prototype.hasOwnProperty.call(application, field), `${field} is required.`)
      check(typeof application[field] === type)
    }
  }

  toPublicCertificate () {
    const publicInfo = {
      pk: this.keys.pk,
      schema: this.schema,
      certId: this.certId,
      revocationListKey: Buffer.alloc(32)
    }

    const pubCert = new PublicCertification(publicInfo)
    return pubCert.encode()
  }

  addCredential (cred) {
    const g0 = this.revoker.pubkey.basepoints[0]
    cred.revocationPoint = curve.G1.mulScalar(g0, cred.identifier.y)
    this.credentials.push(new RegisteredCredential(cred))
  }

  genIdentifier (k) {
    return this.revoker.issueIdentifier(k)
  }

  issue (details) {
    this.validate(details)

    const issuance = new IssuingProtocol(this.keys.cert, Object.values(details))
    issuance.certId = this.certId

    return issuance
  }

  revoke (identifier, cb) {
    const toRevoke = this.revoker.open(identifier)

    // if (this.credentials.find(cred => curve.G1.eq(cred.identifier.w.c, revokeUser)) === undefined) {
    //   throw new Error('credential does not belong to this certificate')
    // }

    const revokeUser = this.credentials.find(c =>
      curve.G1.eq(c.revocationPoint, toRevoke))

    const revinfo = this.revoker.revoke(revokeUser.identifier.y)
    // this.revocationList.add({
    //   newValue: this.revoker.acc.current,
    //   revoked: revokeUser
    // }, cb)

    return cb(null, revinfo)
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc()
    if (!offset) offset = 0
    const startIndex = offset

    buf.writeUInt32LE(this.credentials.length, offset)
    offset += 4

    for (const cred of this.credentials) {
      cred.encode(buf, offset)
      offset += cred.encode.bytes
    }

    buf.set(this.certId, offset)
    offset += 32

    this.revoker.encode(buf, offset)
    offset += this.revoker.encode.bytes

    keys.issuingKeys.encode(this.keys.cert, buf, offset)
    offset += keys.issuingKeys.encode.bytes

    const serializedSchema = Buffer.from(JSON.stringify(this.schema))
    buf.writeUInt32LE(serializedSchema.byteLength, offset)
    offset += 4

    buf.set(serializedSchema, offset)
    offset += serializedSchema.byteLength

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = 4

    for (let cred of this.credentials) len += cred.encodingLength()
    len += 32
    len += this.revoker.encodingLength()
    len += keys.issuingKeysEncodingLength(this.keys.cert)
    len += 4
    len += Buffer.from(JSON.stringify(this.schema)).byteLength

    return len
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}
    opts.keys = {}

    const credentialsLen = buf.readUInt32LE(offset)
    offset += 4

    opts.credentials = []
    for (let i = 0; i < credentialsLen; i++) {
      opts.credentials.push(RegisteredCredential.decode(buf, offset))
      offset += RegisteredCredential.decode.bytes
    }

    opts.certId = buf.subarray(offset, offset + 32)
    offset += 32

    opts.revoker = Revoker.decode(buf, offset)
    offset += Revoker.decode.bytes

    opts.issuingKeys = keys.issuingKeys.decode(buf, offset)
    offset += keys.issuingKeys.decode.bytes

    const schemaLen = buf.readUInt32LE(offset)
    offset += 4

    opts.schema = JSON.parse(buf.subarray(offset, offset + schemaLen).toString())
    offset += schemaLen

    PrivateCertification.decode.bytes = offset - startIndex
    return new PrivateCertification(opts)
  }
}

class PublicCertification {
  constructor (opts) {
    this.pk = opts.pk
    this.certId = opts.certId
    this.revocationListKey = opts.revocationListKey
    this.schema = opts.schema
  }

  validate (application) {
    for (const [field, type] of Object.entries(this.schema)) {
      check(Object.prototype.hasOwnProperty.call(application, field), `${field} is required.`)
      check(typeof application[field] === type)
    }
  }

  encode (buf, offset) {
    const serializedSchema = Buffer.from(JSON.stringify(this.schema))

    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    keys.encodeCertKeys(this.pk, buf, offset)
    offset += keys.encodeCertKeys.bytes

    buf.write(this.certId, offset, 'hex')
    offset += this.certId.length / 2

    buf.set(this.revocationListKey, offset)
    offset += this.revocationListKey.byteLength

    buf.writeUInt32LE(serializedSchema.byteLength, offset)
    offset += 4

    buf.set(serializedSchema, offset)
    offset += serializedSchema.byteLength

    this.encode.bytes = startIndex - offset
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}

    opts.pk = keys.decodeCertKeys(buf, offset)
    offset += keys.decodeCertKeys.bytes

    opts.certId = buf.subarray(offset, offset + 32).toString('hex')
    offset += 32

    opts.revocationListKey = buf.subarray(offset, offset + 32)
    offset += 32

    const schemaLen = buf.readUInt32LE(offset)
    offset += 4

    opts.schema = JSON.parse(buf.subarray(offset, offset + schemaLen).toString())
    offset += schemaLen

    PublicCertification.decode.bytes = offset - startIndex
    return new PublicCertification(opts)
  }

  encodingLength () {
    let len = 0

    len += keys.certKeysEncodingLength(this.pk)
    len += 68
    len += Buffer.from(JSON.stringify(this.schema)).byteLength

    return len
  }
}

class RegisteredCredential {
  constructor (opts) {
    this.attr = opts.attr
    this.identifier = opts.identifier
    this.revocationPoint = opts.revocationPoint
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    const encodedAttr = Buffer.from(JSON.stringify(this.attr))
    buf.writeUInt32LE(encodedAttr.byteLength, offset)
    offset += 4

    buf.set(encodedAttr, offset)
    offset += encodedAttr.byteLength

    this.identifier.encode(buf, offset)
    offset += this.identifier.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = 4
    len += Buffer.from(JSON.stringify(this.attr)).byteLength
    len += this.identifier.encodingLength()

    return len
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}

    const attrLen = buf.readUInt32LE(offset)
    offset += 4

    opts.attr = JSON.parse(buf.subarray(offset, offset + attrLen).toString())
    offset += attrLen

    opts.identifier = Identifier.decode(buf, offset)
    offset += Identifier.decode.bytes

    RegisteredCredential.decode.bytes = offset - startIndex
    return new Credential(opts)
  }
}

function check (cond, msg) {
  if (!cond) throw new Error(msg)
}

function shasum (data) {
  const hash = Buffer.alloc(sodium.crypto_hash_sha256_BYTES)
  sodium.crypto_hash_sha256(hash, data)
  return hash
}

module.exports = {
  PrivateCertification,
  PublicCertification
}
