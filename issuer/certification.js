const keys = require('../lib/keygen')
const sodium = require('sodium-native')
const RevocationList = require('../revocation-list')
const Revoker = require('./revoker')
const IssuingProtocol = require('./issuance.js')
const curve = require('../lib/curve')
const { Identifier } = require('../lib/wire')
const PublicCertification = require('../lib/public-certification')

const rand = curve.randomScalar

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

    this.keys.cert = opts.issuingKeys || new CertificateKeys(Object.keys(this.schema).length + 1)
    this.keys.pk = new keys.CertificatePublicKey({
      acc: this.revoker.pubkey,
      credential: this.keys.cert.pk
    })

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
    cred.revocationPoint = g0.multiply(cred.identifier.y)
    this.credentials.push(new RegisteredCredential(cred))
  }

  genIdentifier (k) {
    return this.revoker.issueIdentifier(k)
  }

  issue (details) {
    this.validate(details)
    const attributes = Object.keys(this.schema).map(k => k + details[k])

    const issuance = new IssuingProtocol(this.keys.cert, attributes)
    issuance.certId = this.certId

    return issuance
  }

  revoke (identifier, cb) {
    const toRevoke = this.revoker.open(identifier)

    // if (this.credentials.find(cred => curve.G1.eq(cred.identifier.w.c, revokeUser)) === undefined) {
    //   throw new Error('credential does not belong to this certificate')
    // }

    const revokeUser = this.credentials.find(c =>
      toRevoke.equals(c.revocationPoint))

    const revinfo = this.revoker.revoke(revokeUser.identifier.y)
    revinfo.certId = this.certId
    // this.revocationList.add(revinfo, cb)

    return cb(null, revinfo.encode())
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

    buf.write(this.certId, offset, 'hex')
    offset += 32

    this.revoker.encode(buf, offset)
    offset += this.revoker.encode.bytes

    this.keys.cert.encode(buf, offset)
    offset += this.keys.cert.encode.bytes

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

    for (const cred of this.credentials) len += cred.encodingLength()
    len += 32
    len += this.revoker.encodingLength()
    len += this.keys.cert.encodingLength()
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

    opts.certId = buf.subarray(offset, offset + 32).toString('hex')
    offset += 32

    opts.revoker = Revoker.decode(buf, offset)
    offset += Revoker.decode.bytes

    opts.issuingKeys = CertificateKeys.decode(buf, offset)
    offset += CertificateKeys.decode.bytes

    const schemaLen = buf.readUInt32LE(offset)
    offset += 4

    opts.schema = JSON.parse(buf.subarray(offset, offset + schemaLen).toString())
    offset += schemaLen

    PrivateCertification.decode.bytes = offset - startIndex
    return new PrivateCertification(opts)
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

    this.revocationPoint.encode(buf, offset)
    offset += this.revocationPoint.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = 4
    len += Buffer.from(JSON.stringify(this.attr)).byteLength
    len += this.identifier.encodingLength()
    len += curve.PointG1.encodingLength()

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

    opts.revocationPoint = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    RegisteredCredential.decode.bytes = offset - startIndex
    return new RegisteredCredential(opts)
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

class CertificateKeys {
  constructor (n) {
    this.sk = {}
    this.pk = {}

    this.sk.a = curve.Fr.random()
    this.sk.z = curve.Fr.random()

    this.sk._a = []
    for (let i = 0; i < n; i++) this.sk._a[i] = curve.Fr.random()

    this.pk = new keys.CredentialPublicKey()

    // Q is just a random generator, so don't store discrete log
    this.pk.Q = curve.PointG2.mulGen(curve.Fr.random())
    this.pk.A = this.pk.Q.multiply(this.sk.a)
    this.pk.Z = this.pk.Q.multiply(this.sk.z)
    this.pk._A = this.sk._a.map(k => this.pk.Q.multiply(k))
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.sk.a.encode(buf, offset)
    offset += this.sk.a.encode.bytes

    buf.writeUInt32LE(this.sk._a.length, offset)
    offset += 4

    for (const k of this.sk._a) {
      k.encode(buf, offset)
      offset += k.encode.bytes
    }

    this.sk.z.encode(buf, offset)
    offset += this.sk.z.encode.bytes

    this.pk.Q.encode(buf, offset)
    offset += this.pk.Q.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const keys = new CertificateKeys()

    keys.sk.a = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    const aLen = buf.readUInt32LE(offset)
    offset += 4

    keys.sk._a = new Array(aLen)
    for (let i = 0; i < aLen; i++) {
      keys.sk._a[i] = curve.Fr.decode(buf, offset)
      offset += curve.Fr.decode.bytes
    }

    keys.sk.z = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    keys.pk.Q = curve.PointG2.decode(buf, offset)
    offset += curve.PointG2.decode.bytes

    keys.pk.A = keys.pk.Q.multiply(keys.sk.a)
    keys.pk.Z = keys.pk.Q.multiply(keys.sk.z)
    keys.pk._A = keys.sk._a.map(k => keys.pk.Q.multiply(k))

    CertificateKeys.decode.bytes = offset - startIndex
    return keys
  }

  encodingLength () {
    return 192 + 4 + 32 * (2 + this.sk._a.length)
  }

  toPublicKey (buf, offset) {
    return this.pk.encode(buf, offset)
  }
}
