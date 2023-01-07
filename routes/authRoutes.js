const express = require("express")
const route = express.Router()
const { register, login, logout, verifyEmail, forgotPassword, resetPassword } = require("../controllers/auth")
const { authenticateUser } = require("../middleware/authentication")

route.post("/register", register)
route.post("/login", login)
route.delete("/logout", authenticateUser, logout)
route.post("/verify-mail", verifyEmail)
route.post("/forgot-password", forgotPassword)
route.post("/reset-password", resetPassword)

module.exports = route
