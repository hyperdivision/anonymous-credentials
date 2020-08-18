const curve = require('./curve')
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

  const users = []

  const secrets = {}
  secrets.gamma = curve.randomScalar()
  secrets.xi1 = curve.randomScalar()
  secrets.xi2 = curve.randomScalar()

  const pubkey = {}
  pubkey.g1 = G1.g
  pubkey.u = curve.randomPointG1()
  pubkey.h = G1.mulScalar(pubkey.u, secrets.xi1)
  pubkey.v = G1.mulScalar(pubkey.h, F.inv(secrets.xi2))

  pubkey.g2 = G2.g
  pubkey.w = G2.mulScalar(pubkey.g2, secrets.gamma)

  pubkey.secrets = secrets
  
  pubkey.e = {}
  pubkey.e.gg = curve.pairing(pubkey.g1, pubkey.g2)
  pubkey.e.hg = curve.pairing(pubkey.h, pubkey.g2)
  pubkey.e.hw = curve.pairing(pubkey.h, pubkey.w)

  function issue () {
    const x = curve.randomScalar()

    const exponent = F.inv(F.add(secrets.gamma, x))
    const A = G1.mulScalar(pubkey.g1, exponent)

    const id = {
      A,
      x
    }

    users.push(id)
    return id
  }

  function open (showing, r) {
    assert(verify(showing, pubkey), 'opening failed: invalid signature')

    const { T1, T2, T3 } = showing
    const A = G1.sub(T3, G1.add(G1.mulScalar(T1, secrets.xi1), G1.mulScalar(T2, secrets.xi2)))

    const user = users.find(u => G1.eq(u.A, A))
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
  const { T1, T2, T3, c, cBlinds } = showing

  const precomp_ra_rb = F.neg(F.add(cBlinds[0], cBlinds[1]))
  const precomp_rd1_rd2 = F.neg(F.add(cBlinds[3], cBlinds[4]))
  const precomp_g1g2_c = F12.exp(pk.e.gg, F.neg(c))
  const precomp = F12.mul(F12.exp(pk.e.hw, precomp_ra_rb), F12.exp(pk.e.hg, precomp_rd1_rd2))

  const pairing = curve.pairing(T3, G2.add(G2.mulScalar(pk.w, c), G2.mulScalar(pk.g2, cBlinds[2])))

  const R1_ = G1.affine(G1.sub(G1.mulScalar(pk.u, cBlinds[0]), G1.mulScalar(T1, c)))
  const R2_ = G1.affine(G1.sub(G1.mulScalar(pk.v, cBlinds[1]), G1.mulScalar(T2, c)))
  const R3_ = F12.mul(F12.mul(pairing, precomp_g1g2_c), precomp)
  const R4_ = G1.affine(G1.sub(G1.mulScalar(T1, cBlinds[2]), G1.mulScalar(pk.u, cBlinds[3])))
  const R5_ = G1.affine(G1.sub(G1.mulScalar(T2, cBlinds[2]), G1.mulScalar(pk.v, cBlinds[4])))

  const check = hash(T1, T2, T3, R1_, R2_, R3_, R4_, R5_)
  return F.eq(c, check)
}

function show (id, pk) {
  const alpha = curve.randomScalar()
  const beta = curve.randomScalar()

  const T1 = G1.affine(G1.mulScalar(pk.u, alpha))
  const T2 = G1.affine(G1.mulScalar(pk.v, beta))
  const T3 = G1.affine(G1.add(id.A, G1.mulScalar(pk.h, F.add(alpha, beta))))

  const delta1 = F.mul(id.x, alpha)
  const delta2 = F.mul(id.x, beta)

  const blinds = []
  for (let i = 0; i < 5; i++) blinds.push(curve.randomScalar())

  const precomp_ra_rb = F.neg(F.add(blinds[0], blinds[1]))
  const precomp_rd1_rd2 = F.neg(F.add(blinds[3], blinds[4]))
  const precomp = F12.mul(F12.exp(pk.e.hw, precomp_ra_rb), F12.exp(pk.e.hg, precomp_rd1_rd2))

  const pairing = F12.exp(curve.pairing(T3, pk.g2), blinds[2])

  const R1 = G1.affine(G1.mulScalar(pk.u, blinds[0]))
  const R2 = G1.affine(G1.mulScalar(pk.v, blinds[1]))
  const R3 = F12.mul(pairing, precomp)
  const R4 = G1.affine(G1.sub(G1.mulScalar(T1, blinds[2]), G1.mulScalar(pk.u, blinds[3])))
  const R5 = G1.affine(G1.sub(G1.mulScalar(T2, blinds[2]), G1.mulScalar(pk.v, blinds[4])))

  const c = hash(T1, T2, T3, R1, R2, R3, R4, R5)

  const cBlinds = [alpha, beta, id.x, delta1, delta2].map((scalar, i) => {
    return F.add(blinds[i], F.mul(c, scalar))
  })

  return {
    T1, T2, T3,
    c,
    cBlinds,
  }
}

function hash (...elements) {
  const data = Buffer.alloc(33 * 32)
  let offset = 0

  const strings = elements.flatMap((a, i) => {
    if (i === 5) return a.flatMap(b => b.flatMap(c => c.map(n => n.toString(16).padStart('0', 32))))
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
