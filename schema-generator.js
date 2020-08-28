const path = require('path')
const fs = require('fs')
const crypto = require('crypto')

const types = [
  'string',
  'boolean',
  'number'
]

const length = Number(process.argv[2])
const dirname = process.argv[3]

writeToFile(length)

function writeToFile (i) {
  if (i < 0) process.exit(0)
  
  const scheme = generateScheme()
  const application = generateApplication(scheme)  

  const id = shasum(Buffer.from(JSON.stringify(scheme))).toString('hex')

  fs.writeFile(path.join(dirname, 'schema', id + '.json'), JSON.stringify(scheme), (err) => {
    if (err) throw err

    fs.writeFile(path.join(dirname, 'app', id + '.json'), JSON.stringify(application), (err) => {
      if (err) throw err

      writeToFile(--i)
    })
  })
}

function generateScheme () {
  const scheme = {}
 
  for (let i = 0; i < Math.random() * 6 + 4; i++) {
    const label = crypto.randomBytes(8).toString('hex')
    scheme[label] = types[Math.floor(Math.random() * 3)]
  }

  return scheme
}

function generateApplication (scheme) {
  const app = {}

  for (let [field, type] of Object.entries(scheme)) {
    app[field] = generate(type)
  }

  return app

  function generate (type) {
    switch (type) {
      case 'number':
        return Math.ceil(Math.random() * 200)

      case 'boolean':
        return Math.random() < 0.5

      case 'string':
        return crypto.randomBytes(20).toString('hex')
    }
  }
}
