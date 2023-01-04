const express = require("express")
const route = express.Router()
const { getAllUsers, getSingleUser, updateUserPassword, showCurrentUsers, updateUser } = require("../controllers/userController")
const { authenticateUser, authorizePermissions } = require("../middleware/authentication")

// Prima este user route in care accesam toti userii deci trebuie sa avem permis de admin
// 1. Primul middleware (authenticateUser) verifica tokenul atunci cand userul da login
// 2. al 2-lea middleware (authorizePermissions) verifica daca userul are acces de admin
// 3. Controlerul ce face requeste (getAllUsers)
route.get("/", authenticateUser, authorizePermissions("admin", "client"), getAllUsers)

route.get("/showMe", authenticateUser, showCurrentUsers) // conteaza ordinea ca cu asta generam id pentru urmatoarea ruta
route.patch("/updateUser", authenticateUser, updateUser)
route.patch("/updateUserPassword", authenticateUser, updateUserPassword)

route.get("/:id", authenticateUser, getSingleUser)

module.exports = route
