const express = require("express")
const route = express.Router()
const { getAllOrders, getSingleOrder, getCurrentUserOrders, createOrder, updateOrder } = require("../controllers/orderController")
const { authenticateUser, authorizePermissions } = require("../middleware/authentication")

route.get("/", authenticateUser, authorizePermissions("admin"), getAllOrders)
route.get("/showAllMyOrders", authenticateUser, getCurrentUserOrders)
route.get("/:id", authenticateUser, getSingleOrder)
route.post("/", authenticateUser, createOrder)
route.patch("/:id", authenticateUser, updateOrder)

module.exports = route
