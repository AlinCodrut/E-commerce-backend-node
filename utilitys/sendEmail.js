const nodemailer = require("nodemailer")
const nodeMailerConfig = require("./nodemailerConfig")

const sendEmail = async ({ to, subject, html }) => {
  let testAccount = await nodemailer.createTestAccount()

  const transporter = nodemailer.createTransport(nodeMailerConfig)

  return transporter.sendMail({
    from: '"test" <info.jdm.ro@gmail.com>',
    to,
    subject,
    html
  })
}

module.exports = sendEmail
