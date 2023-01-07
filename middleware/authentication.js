// cu acest middleware controlam tokenul si rertunam userul (authenticateUser)
// tot cu acest token vedem dacare userul este admin (authorizePermissions)
// !!!!!! ORDINEA E FOARTE IMPORTANTA, MAI INTAI VERIFICM TOKEN INCAT SA AVEM ACCES LA OBIECTUL USER, APOI DOAR VERIFICA DE ADMIN

const { UnauthenticatedError, UnauthorizedError } = require("../errors")
const { isTokenValid } = require("../utilitys/jwt")
const Token = require("../models/Token")
const { attachCookiesToResponse } = require("../utilitys")
const { rawListeners } = require("../models/Token")

const authenticateUser = async (req, res, next) => {
  const { refreshToken, accessToken } = req.signedCookies

  try {
    if (accessToken) {
      const payload = isTokenValid(accessToken)
      req.user = payload.user
      return next()
    }

    const payload = isTokenValid(refreshToken)

    const existingToken = await Token.findOne({
      user: payload.user.userId,
      refreshToken: payload.refreshToken
    })

    if (!existingToken || !existingToken?.isValid) {
      throw new UnauthenticatedError("Authentication invalid")
    }

    attachCookiesToResponse({ res, user: payload.user, refreshToken: existingToken.refreshToken })
    req.user = payload.user
    next()
  } catch (error) {
    throw new UnauthenticatedError("Authentication invalid")
  }
}

const authorizePermissions = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      throw new UnauthorizedError("Unauthorized acces")
    }
    next()
  }
  next()
}

module.exports = { authenticateUser, authorizePermissions }
