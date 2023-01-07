const User = require("../models/User")
const Token = require("../models/Token")
const { StatusCodes } = require("http-status-codes")
const { BadRequestError, UnauthenticatedError } = require("../errors")
const { attachCookiesToResponse, createTokenuser, sendVerificationEmail, sendResetPasswordEmail, createHash } = require("../utilitys")
const crypto = require("crypto")
const { off } = require("../models/Token")

const register = async (req, res) => {
  const { email, name, password } = req.body
  const emailAlreadyExists = await User.findOne({ email })

  if (emailAlreadyExists) {
    throw new BadRequestError("Email already exists, please provide another email address")
  }

  // First registrated user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0 //sa vedem daca nu este nici un cont in database

  const role = isFirstAccount ? "admin" : "user" // facem conditia if direct in constanta

  const verificationToken = crypto.randomBytes(40).toString("hex") //creemm un token random

  const user = await User.create({ name, email, password, role, verificationToken })

  const devOrigin = "http://localhost:5000/"
  const productionOrigin = "https://medicstore.onrender.com"

  await sendVerificationEmail({ name: user.name, email: user.email, verificationToken: user.verificationToken, origin: productionOrigin })

  res.status(StatusCodes.CREATED).json({
    msg: "Success! Please check your email to verify account"
  })
}

const login = async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    throw new BadRequestError("Must provide an email and a password")
  }

  const user = await User.findOne({ email })

  if (!user) {
    throw new UnauthenticatedError("No user whit this credentials")
  }

  const isPasswordCorrect = await user.comparePassword(password)
  if (!isPasswordCorrect) {
    throw new UnauthenticatedError("Invalid Credentials")
  }

  // if (!user.isVerified) {
  //   throw new UnauthenticatedError("Please verify your email")
  // }
  const tokenUser = createTokenuser(user) //ce informatii vrem sa trimitem in raspuns

  // creem refresh token

  let refreshToken = ""

  //controlam sa vedem daca exista vreun token si  il atasam incat sa nu creem unul nou de cate ori userul da login
  const existingToken = await Token.findOne({ user: user._id })

  if (existingToken) {
    const { isValid } = existingToken
    if (!isValid) {
      throw new UnauthenticatedError("Invalid Credentials")
    }
    refreshToken = existingToken.refreshToken

    attachCookiesToResponse({ res, user: tokenUser, refreshToken }) //creem token si atasam la cookie cu functia pe care am importato din utilitys si trimitem raspunsul
    res.status(StatusCodes.OK).json({ user: tokenUser })
    return
  }

  refreshToken = crypto.randomBytes(40).toString("hex")
  const userAgent = req.headers["user-agent"]
  const ip = req.ip

  const userToken = { refreshToken, ip, userAgent, user: user._id } //creem obietul care sa-l trimitem inapoi

  await Token.create(userToken)

  attachCookiesToResponse({ res, user: tokenUser, refreshToken }) //creem token si atasam la cookie cu functia pe care am importato din utilitys si trimitem raspunsul
  res.status(StatusCodes.OK).json({ user: tokenUser })
}

const logout = async (req, res) => {
  await Token.findOneAndDelete({ user: req.user.userId })

  res.cookie("accesstoken", "logout", {
    httpOnly: true,
    expires: new Date(Date.now())
  })

  res.cookie("refreshtoken", "logout", {
    httpOnly: true,
    expires: new Date(Date.now())
  })
  res.status(StatusCodes.OK).json({ msg: "user logged out!" })
}

const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body

  if (!email) {
    throw new BadRequestError("Please provide an email")
  }

  const user = await User.findOne({ email })

  if (!user) {
    throw new UnauthenticatedError("Invalid Credentials")
  }

  if (user.verificationToken !== verificationToken) {
    throw new UnauthenticatedError("Verification failed")
  }

  user.isVerified = true
  user.verified = Date.now()
  user.verificationToken = ""

  await user.save()

  res.status(StatusCodes.OK).json({ msg: "Email verified" })
}

const forgotPassword = async (req, res) => {
  const { email } = req.body

  if (!email) {
    throw new BadRequestError("Please provide an email")
  }

  const user = await User.findOne({ email })

  if (user) {
    const passwordToken = crypto.randomBytes(70).toString("hex")
    //send email
    const productionOrigin = "https://medicstore.onrender.com"
    await sendResetPasswordEmail({ name: user.name, email: user.email, token: passwordToken, origin: productionOrigin })

    const tenMinutes = 1000 * 60 * 10

    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes)

    user.passwordToken = createHash(passwordToken)
    user.passwordTokenExpirationDate = passwordTokenExpirationDate

    await user.save()
  }

  res.status(StatusCodes.OK).json({ msg: "Please check you email for the reset password link" })
}

const resetPassword = async (req, res) => {
  const { token, email, password } = req.body

  if (!email || !password || !token) {
    throw new BadRequestError("Please provide all valueas")
  }

  const user = await User.findOne({ email })

  if (user) {
    const currentDate = new Date()

    if (user.passwordToken === createHash(token) && user.passwordTokenExpirationDate > currentDate) {
      user.password = password
      user.passwordToken = null
      user.passwordTokenExpirationDate = null

      await user.save()
    }
  }

  res.status(StatusCodes.OK).json({ msg: "Please check you email for the reset password link" })
}

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword
}
