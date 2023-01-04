const express = require("express")
const route = express.Router()
const { getAllReviews, getSingleReview, updateReview, createReview, deleteReview } = require("../controllers/reviewController")
const { authenticateUser, authorizePermissions } = require("../middleware/authentication")

route.get("/", getAllReviews)
route.get("/:id", getSingleReview)
route.post("/", authenticateUser, createReview)
route.patch("/:id", authenticateUser, updateReview)
route.delete("/:id", authenticateUser, deleteReview)

module.exports = route
