const axios = require('axios')
const dns = require('dns')
const api = require('./api')
const pkg = require('../package.json')
async function verify({ authorization, accountKey, type }) {
  if (!authorization || !accountKey || !type) {
    throw 'Invalid input: authorization, accountKey and type are required.'
  }
  const validtypes = ['http-01', 'dns-01', 'tls-alpn-01']
  if (!validtypes.includes(type)) {
    throw 'Invalid type. Please provide a valid type (http-01, dns-01, or tls-alpn-01).'
  }
  if (type == 'tls-alpn-01') {
    throw 'Type tls-alpn-01 is not supported yet.'
  }
  const types = authorization.challenges.map(challenge => challenge.type)
  if (!types.includes(type)) {
    throw 'Type is not found in authorization.'
  }
  const domain = authorization.identifier.value
  const challenge = authorization.challenges.find(challenge => challenge.type == type)
  const keyauthorization = api.getChallengeKeyAuthorization({
    challenge: challenge,
    accountKey: accountKey
  })
  try {
    if (type == 'http-01') {
      const url = 'http://' + domain + '/.well-known/acme-challenge/' + challenge.token
      const res = await axios.get(url, {
        headers: {
          'User-Agent': pkg.name + pkg.version
        }
      })
      if (res.data == keyauthorization) {
        return 'success'
      }
      return 'fail'
    }
    if (type == 'dns-01') {
      const domainout = '_acme-challenge.' + domain
      async function getcname(domain) {
        try {
          const cnames = await dns.promises.resolveCname(domain)
          if (cnames.length > 0) {
            return await getcname(cnames[0])
          }
          return domain
        } catch {
          return domain
        }
      }
      const finaldomain = await getcname(domainout)
      const txts = await dns.promises.resolveTxt(finaldomain)
      const records = txts.flat()
      if (records.includes(keyauthorization)) {
        return 'success'
      }
      return 'fail'
    }
  } catch (err) {
    throw err
  }
}
module.exports = {
  verify
}