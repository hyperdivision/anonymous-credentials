const curve = require('../lib/curve')
const Accumulator = require('./accumulator')
const sha256 = require('sha512-wasm')
const assert = require('nanoassert')

const { F, F12, G1, G2 } = curve

module.exports = {
  Issuer,
  verify,
  show
}

function Issuer () {
  if (!(this instanceof Issuer)) return new Issuer()

  const acc = new Accumulator()

  const users = []

  const secrets = {}
  secrets.alpha = acc.alpha
  secrets.xi1 = curve.randomScalar()
  secrets.xi2 = curve.randomScalar()

  const pubkey = {}
  pubkey.g1 = acc.g1
  pubkey.u = curve.randomPointG1()
  pubkey.h = G1.mulScalar(pubkey.u, secrets.xi1)
  pubkey.v = G1.mulScalar(pubkey.h, F.inv(secrets.xi2))

  pubkey.g2 = acc.g2
  pubkey.a = G2.mulScalar(pubkey.g2, secrets.alpha)

  pubkey.secrets = secrets
  
  pubkey.e = {}
  pubkey.e.gg = curve.pairing(pubkey.g1, pubkey.g2)
  pubkey.e.vg = curve.pairing(acc.acc, pubkey.g2)
  pubkey.e.hg = curve.pairing(pubkey.h, pubkey.g2)
  pubkey.e.ha = curve.pairing(pubkey.h, pubkey.a)
  pubkey.acc = acc

  function issue () {
    const id = acc.new()
    
    users.push(id)
    return id
  }

  function open (showing, r) {
    assert(verify(showing, pubkey), 'opening failed: invalid signature')

    const { T } = showing
    const c = G1.sub(T[2], G1.add(G1.mulScalar(T[0], secrets.xi1), G1.mulScalar(T[1], secrets.xi2)))

    const user = users.find(u => G1.eq(u.witness.c, c))
    return user
  }

  function getPubkey () {
    return pubkey
  }

  return {
    issue,
    open,
    getPubkey
  }
}

function verify (showing, pk) {
  const { T, R, c, cBlinds } = showing

  const precomp_r1 = F.neg(F.add(cBlinds[0], cBlinds[1]))
  const precomp_r2 = F.neg(F.add(cBlinds[5], cBlinds[6]))
  const precomp_r1y = F.neg(F.add(cBlinds[3], cBlinds[4]))
  const precomp_vg_c = F12.exp(pk.e.vg, F.neg(c))
  const precomp = F12.mul(F12.mul(F12.exp(pk.e.ha, precomp_r1), F12.exp(pk.e.hg, precomp_r1y)), F12.exp(pk.e.hg, precomp_r2))

  const pairingT3 = curve.pairing(T[2], G2.add(G2.mulScalar(pk.a, c), G2.mulScalar(pk.g2, cBlinds[2])))
  const pairingT6 = curve.pairing(T[5], G2.mulScalar(pk.g2, c))

  const R_ = []
  R_[0] = G1.affine(G1.sub(G1.mulScalar(pk.u, cBlinds[0]), G1.mulScalar(T[0], c)))
  R_[1] = G1.affine(G1.sub(G1.mulScalar(pk.v, cBlinds[1]), G1.mulScalar(T[1], c)))
  R_[2] = F12.mul(F12.mul(F12.mul(pairingT3, precomp_vg_c), precomp), pairingT6)
  R_[3] = G1.affine(G1.sub(G1.mulScalar(T[0], cBlinds[2]), G1.mulScalar(pk.u, cBlinds[3])))
  R_[4] = G1.affine(G1.sub(G1.mulScalar(T[1], cBlinds[2]), G1.mulScalar(pk.v, cBlinds[4])))
  R_[5] = G1.affine(G1.sub(G1.mulScalar(pk.u, cBlinds[5]), G1.mulScalar(T[3], c)))
  R_[6] = G1.affine(G1.sub(G1.mulScalar(pk.v, cBlinds[6]), G1.mulScalar(T[4], c)))

  const check = hash(...T, ...R_)
  return F.eq(c, check)
}

function show (id, pk) {
  const alpha = curve.randomScalar()
  const beta = curve.randomScalar()
  const gamma = curve.randomScalar()
  const delta = curve.randomScalar()

  const T = []
  T[0] = G1.affine(G1.mulScalar(pk.u, alpha))
  T[1] = G1.affine(G1.mulScalar(pk.v, beta))
  T[2] = G1.affine(G1.add(id.witness.c, G1.mulScalar(pk.h, F.add(alpha, beta))))
  T[3] = G1.affine(G1.mulScalar(pk.u, gamma))
  T[4] = G1.affine(G1.mulScalar(pk.v, delta))
  T[5] = G1.affine(G1.add(G1.mulScalar(pk.g1, id.witness.d), G1.mulScalar(pk.h, F.add(gamma, delta))))

  const delta1 = F.mul(id.y, alpha)
  const delta2 = F.mul(id.y, beta)

  const blinds = []
  for (let i = 0; i < 7; i++) blinds.push(curve.randomScalar())

  const precomp_r1 = F.neg(F.add(blinds[0], blinds[1]))
  const precomp_r1y_r2 = F.neg(F.add(F.add(blinds[3], blinds[4]), F.add(blinds[5], blinds[6])))
  const precomp = F12.mul(F12.exp(pk.e.ha, precomp_r1), F12.exp(pk.e.hg, precomp_r1y_r2))

  const pairingT3 = F12.exp(curve.pairing(T[2], pk.g2), blinds[2])
  const pairingT6 = curve.pairing(T[5], pk.g2)

  const R = []
  R[0] = G1.affine(G1.mulScalar(pk.u, blinds[0]))
  R[1] = G1.affine(G1.mulScalar(pk.v, blinds[1]))
  R[2] = F12.mul(pairingT3, precomp)
  R[3] = G1.affine(G1.sub(G1.mulScalar(T[0], blinds[2]), G1.mulScalar(pk.u, blinds[3])))
  R[4] = G1.affine(G1.sub(G1.mulScalar(T[1], blinds[2]), G1.mulScalar(pk.v, blinds[4])))
  R[5] = G1.affine(G1.mulScalar(pk.u, blinds[5]))
  R[6] = G1.affine(G1.mulScalar(pk.v, blinds[6]))

  const r1 = F.neg(F.add(alpha, beta))
  const r2 = F.neg(F.add(gamma, delta))
  const T3g = curve.pairing(T[2], pk.g2)
  const T3a = curve.pairing(T[2], pk.a)
  const T6g = curve.pairing(T[5], pk.g2)
  const r1y = F.mul(r1, id.y)

  const c = hash(...T, ...R)

  const cBlinds = [alpha, beta, id.y, delta1, delta2, gamma, delta].map((scalar, i) => {
    return F.add(blinds[i], F.mul(c, scalar))
  })

  return {
    T,
    c,
    cBlinds,
  }
}

function hash (...elements) {
  const data = Buffer.alloc(48 * 32)
  let offset = 0

  const strings = elements.flatMap((a, i) => { 
    if (i === 8) return a.flatMap(b => b.flatMap(c => c.map(n => n.toString(16).padStart('0', 32))))
    else return a.map(n => n.toString(16).padStart('0', 32))
  })

  for (let n of strings) {
    data.write(n, offset, 'hex')
    offset += 32
  }

  const digest = sha256().update(data).digest()
  return curve.scalarFrom(digest)
}

function invModulo (a, mod) {
  // assert(a, "Division by zero");

  let t = 0n;
  let r = mod

  let newt = 1n
  let newr = a % mod

  while (newr) {
    let q = r / newr;
    [t, newt] = [newt, t - q * newt];
    [r, newr] = [newr, r - q * newr];
  }

  if (t<0n) t += mod
  return t
}
