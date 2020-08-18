const Accumulator = require('./accumulator')

const acc = new Accumulator()

// acc.add(acc.new().y)
// acc.add(acc.new().y)
// acc.add(acc.new().y)
// acc.add(acc.new().y)

const p = acc.new()

console.log(acc.verifyWitness(p.witness, p.y))
