const User = require("../models/User")
const { StatusCodes } = require("http-status-codes")
const { BadRequestError, UnauthenticatedError, NotFoundError } = require("../errors")
const { attachCookiesToResponse, createTokenuser, checkPermission } = require("../utilitys")

const getAllUsers = async (req, res) => {
  const allUsers = await User.find({ role: "user" }).select("-password")

  res.status(StatusCodes.OK).json({ allUsers })
}

const getSingleUser = async (req, res) => {
  const user = await User.findOne({ _id: req.params.id }).select("-password")

  if (!user) {
    throw new NotFoundError("No user whit the selected id")
  }

  checkPermission(req.user, user._id)
  res.status(StatusCodes.OK).json({ user })
}

const showCurrentUsers = async (req, res) => {
  res.status(StatusCodes.OK).json({ user: req.user })
}

const updateUser = async (req, res) => {
  const { email, name } = req.body

  if (!email || !name) {
    throw new BadRequestError("Please provide all values")
  }

  const user = await User.findOneAndUpdate({ _id: req.user.userId }, { email, name }, { new: true, runValidators: true })

  const tokenUser = createTokenuser(user) //ce informatii vrem sa trimitem in raspuns
  attachCookiesToResponse({ res, user: tokenUser }) //creem token si atasam la cookie cu functia pe care am importato din utilitys si trimitem raspunsul
  res.status(StatusCodes.OK).json({ user: tokenUser })
}

const updateUserPassword = async (req, res) => {
  const { newPassword, oldPassword } = req.body

  if (!newPassword || !oldPassword) {
    throw new BadRequestError("Must provide a password")
  }

  const user = await User.findOneAndUpdate({ _id: req.user.userId })

  const isPasswordCorrect = await user.comparePassword(oldPassword)
  if (!isPasswordCorrect) {
    throw new UnauthenticatedError("Invalid credentials")
  }
  user.password = newPassword
  await user.save()
  res.status(StatusCodes.OK).json({ msg: "Password updated successfully" })
}

module.exports = {
  getAllUsers,
  getSingleUser,
  updateUser,
  showCurrentUsers,
  updateUserPassword
}
