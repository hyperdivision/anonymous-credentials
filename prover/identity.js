const assert = require('nanoassert')
const sodium = require('sodium-native')
const keygen = require('../lib/keygen')
const Credential = require('./credential')
const { Presentation, Signature } = require('../lib/wire')
const Identifier = require('./active-identifier')
const attributes = require('../lib/gen-attributes')
const hash = require('../lib/challenge')

module.exports = class Identity {
  constructor (attrs, certId) {
    this.credential = new Credential(Object.keys(attrs).length)
    this.identifier = null
    this.attributes = attrs
    this.certId = certId
  }

  finalize ({ identity, info, pk }) {
    this.identifier = new Identifier(identity, pk)
    this.credential.finalize(info)
  }

  present (disclosure) {
    const disclosed = {}
    for (let item of disclosure) disclosed[item] = this.attributes[item]

    // TODO: validate against credential
    const encoded = Object.entries(disclosed).map(([k, v]) =>
      attributes.encode(k + v))

    const nym = this.identifier.prover(this.identifier.pk.basepoints)
    const cred = this.credential.show(encoded)

    const challenge = hash(...cred.generators, ...nym.U, nym.C)

    const witness = nym.prove(cred.secrets[2], challenge)
    const showing = cred.prove(challenge)

    return {
      disclosed,
      showing,
      witness,
      certId: this.certId
    }

    // return new Presentation(disclosed, showing, witness, this.certId)
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    const json = JSON.stringify(this.attributes)
    buf.writeUInt32LE(json.length, offset)
    offset += 4

    buf.write(json, offset)
    offset += json.length

    buf.write(this.certId, offset, 'hex')
    offset += 32

    this.credential.encode(buf, offset)
    offset += this.credential.encode.bytes

    this.pseudonym.encode(buf, offset)
    offset += this.pseudonym.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = 4
    const json = JSON.stringify(this.attributes)

    len += json.length
    len += 32
    len += this.credential.encodingLength()
    len += this.pseudonym.encodingLength()

    return len
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const jsonLen = buf.readUInt32LE(offset)
    offset += 4

    const attrs = JSON.parse(buf.subarray(offset, offset + jsonLen).toString())
    offset += jsonLen

    const certId = buf.subarray(offset, offset + 32).toString('hex')
    offset += 32

    const id = new Identity(attrs, certId)

    id.credential = Credential.decode(buf, offset)
    offset += Credential.decode.bytes

    id.pseudonym = Identifier.decode(buf, offset)
    offset += Identifier.decode.bytes

    Identity.decode.bytes = offset - startIndex
    return id
  }
}
