const axios = require('axios')
const dns = require('dns')
const api = require('./api')
const pkg = require('../package.json')
async function verify({ authorization, accountKey, type }) {
  const domain = authorization.identifier.value
  const challenge = authorization.challenges.find(challenge => challenge.type == type)
  const keyauthorization = api.getChallengeKeyAuthorization({
    challenge: challenge,
    accountKey: accountKey
  })
  try {
    if (type == 'http-01') {
      const res = await axios.get('http://' + domain + '/.well-known/acme-challenge/' + challenge.token, {
        headers: {
          'User-Agent': pkg.name + '/' + pkg.version
        }
      })
      if (res.data == keyauthorization) {
        return 'success'
      }
      return 'fail'
    }
    if (type == 'dns-01') {
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
      const finaldomain = await getcname('_acme-challenge.' + domain)
      const txts = await dns.promises.resolveTxt(finaldomain)
      if (txts.flat().includes(keyauthorization)) {
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