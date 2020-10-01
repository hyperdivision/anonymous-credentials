const assert = require('nanoassert')
const { CertificatePublicKey } = require('./keygen')

module.exports = class PublicCertification {
  constructor (opts) {
    this.pk = opts.pk
    this.certId = opts.certId
    this.revocationListKey = opts.revocationListKey
    this.schema = opts.schema
    this.certId = opts.certId
  }

  validate (application) {
    for (const [field, type] of Object.entries(this.schema)) {
      assert(Object.prototype.hasOwnProperty.call(application, field), `${field} is required.`)
      assert(typeof application[field] === type)
    }
  }

  updateAccumulator (info) {
    this.pk.acc.updateAccumulator(info)
  }

  encode (buf, offset) {
    const serializedSchema = Buffer.from(JSON.stringify(this.schema))

    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.pk.encode(buf, offset)
    offset += this.pk.encode.bytes

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

    opts.pk = CertificatePublicKey.decode(buf, offset)
    offset += CertificatePublicKey.decode.bytes

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

    len += this.pk.encodingLength()
    len += 68
    len += Buffer.from(JSON.stringify(this.schema)).byteLength

    return len
  }
}
