const crypto = require('crypto')

module.exports = function (context, cb) {
  const key = Buffer.from(context.secrets.superSecretKey, 'base64')
  const iv = Buffer.from(context.secrets.iv, 'base64')

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(Buffer.from(context.body.tag, 'base64'))

  let decrypted = decipher.update(context.body.msg, 'base64', 'utf8')
  decrypted += decipher.final('utf8')
  cb(null, { msg: decrypted })
}
