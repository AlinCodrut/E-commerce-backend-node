const jwt = require("jsonwebtoken")

const createJWT = ({ payload }) => {
  // Creem token , si in argument este mai mine daca trecem sa fie un obiect pentru usurinta pentru alte lucruri

  const token = jwt.sign(payload, process.env.JWT_SECRET)

  return token
}

const isTokenValid = token => jwt.verify(token, process.env.JWT_SECRET)

const attachCookiesToResponse = async ({ res, user, refreshToken }) => {
  const accessTokenJWT = createJWT({ payload: { user } })
  const refreshTokenJWT = createJWT({ payload: { user, refreshToken } })

  const oneDay = 1000 * 60 * 60 * 24 //punem aceiasi data in care expira si token-ul
  res.cookie("accessToken", accessTokenJWT, {
    //primul argument este numele pe care vrem sa-l dam la cookie, iar al doilea este tokenul pe car tocmai l-am creat
    httpOnly: true,
    expires: new Date(Date.now() + oneDay),
    secure: process.env.NODE_ENV === "production",
    signed: true
  })

  const longerExpiration = 1000 * 60 * 60 * 24 * 30
  res.cookie("refreshToken", refreshTokenJWT, {
    //primul argument este numele pe care vrem sa-l dam la cookie, iar al doilea este tokenul pe car tocmai l-am creat
    httpOnly: true,
    expires: new Date(Date.now() + longerExpiration),
    secure: process.env.NODE_ENV === "production",
    signed: true
  })
}

module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse
}

// Doar ca si referinta la ce am facut inainte cand aveam doar un cookie fara sa avem refresh token
const attachSingleToResponse = async ({ res, user }) => {
  const token = createJWT({ payload: user })
  const oneDay = 1000 * 60 * 60 * 24 * 30 //punem aceiasi data in care expira si token-ul
  res.cookie("token", token, {
    //primul argument este numele pe care vrem sa-l dam la cookie, iar al doilea este tokenul pe car tocmai l-am creat
    httpOnly: true,
    expires: new Date(Date.now() + oneDay),
    secure: process.env.NODE_ENV === "production",
    signed: true
  })
}

module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse
}
