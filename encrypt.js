const crypto = require('crypto')

module.exports = function (context, cb) {
  const key = Buffer.from(context.secrets.superSecretKey, 'base64')
  const iv = Buffer.from(context.secrets.iv, 'base64')

  const cipher = crypto.Cipheriv('aes-256-gcm', key, iv)
  let encrypted = cipher.update(context.body.msg, 'utf8', 'base64')
  encrypted += cipher.final('base64')
  const tag = cipher.getAuthTag()
  cb(null, { msg: encrypted, tag: tag.toString('base64') })
}
