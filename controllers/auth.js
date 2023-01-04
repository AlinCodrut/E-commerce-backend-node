const User = require("../models/User")
const { StatusCodes } = require("http-status-codes")
const { BadRequestError, UnauthenticatedError } = require("../errors")
const { attachCookiesToResponse, createTokenuser } = require("../utilitys")

const register = async (req, res) => {
  const { email, name, password } = req.body
  const emailAlreadyExists = await User.findOne({ email })

  if (emailAlreadyExists) {
    throw new BadRequestError("Email already exists, please provide another email address")
  }

  // First registrated user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0 //sa vedem daca nu este nici un cont in database

  const role = isFirstAccount ? "admin" : "user" // facem conditia if direct in constanta

  const user = await User.create({ name, email, password, role })

  const tokenUser = createTokenuser(user) //ce informatii vrem sa trimitem in raspuns
  attachCookiesToResponse({ res, user: tokenUser }) //creem token si atasam la cookie cu functia pe care am importato din utilitys si trimitem raspunsul

  res.status(StatusCodes.CREATED).json({ user: tokenUser })
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
  const tokenUser = createTokenuser(user) //ce informatii vrem sa trimitem in raspuns
  attachCookiesToResponse({ res, user: tokenUser }) //creem token si atasam la cookie cu functia pe care am importato din utilitys si trimitem raspunsul
  res.status(StatusCodes.OK).json({ user: tokenUser })
}

const logout = async (req, res) => {
  res.cookie("token", "logout", {
    httpOnly: true,
    expires: new Date(Date.now() + 5 * 1000)
  })
  res.status(StatusCodes.OK).json({ msg: "user logged out!" })
}

module.exports = {
  register,
  login,
  logout
}
