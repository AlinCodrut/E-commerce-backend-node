const Product = require("../models/Product")
const Review = require("../models/Review")
const { StatusCodes } = require("http-status-codes")
const { BadRequestError, UnauthenticatedError, NotFoundError } = require("../errors")
const { checkPermission } = require("../utilitys")

const getAllReviews = async (req, res) => {
  const reviews = await Review.find({})
    .populate({
      path: "product",
      select: "name producator price"
    })
    .populate({
      path: "user",
      select: "name"
    })
  res.status(StatusCodes.OK).json({ reviews, count: reviews.length })
}

const getSingleReview = async (req, res) => {
  const { id: reviewId } = req.params

  const review = await Review.findOne({ _id: reviewId })

  if (!review) {
    throw new NotFoundError("No review whit this id")
  }
  res.status(StatusCodes.OK).json({ review })
}

const createReview = async (req, res) => {
  const { product: productId } = req.body

  const isValidProduct = await Product.findOne({ _id: productId }) //controlam daca exista produs in req.body
  if (!isValidProduct) {
    throw new NotFoundError(`No product whit the id: ${productId}`)
  }

  const alreadySubmitted = await Review.findOne({ product: productId, userId: req.user.userId })
  if (alreadySubmitted) {
    throw new BadRequestError("Already submitted a review for this product")
  }

  req.body.user = req.user.userId //avem acem middleware in care am facut token pentru user si am setat req.user incat aici il putem accesa

  const review = await Review.create(req.body)
  res.status(StatusCodes.CREATED).json(review)
}

const updateReview = async (req, res) => {
  const { id: reviewId } = req.params
  const { rating, title, comment } = req.body

  const review = await Review.findOne({ _id: reviewId })
  if (!reviewId) {
    throw new NotFoundError(` No such review whit the ${reviewId}`)
  }
  checkPermission(req.user, review.user)

  review.title = title
  review.rating = rating
  review.comment = comment

  await review.save()

  res.status(StatusCodes.OK).json({ review })
}

const deleteReview = async (req, res) => {
  const { id: reviewId } = req.params

  const review = await Review.findOne({ _id: reviewId })
  if (!reviewId) {
    throw new NotFoundError(` No such review whit the ${reviewId}`)
  }
  checkPermission(req.user, review.user)

  await review.remove()
  res.status(StatusCodes.OK).json("Review deleted successfully")
}

const getSingleProductReviews = async (req, res) => {
  const { id: productId } = req.params
  const reviews = await Review.find({ product: productId })
  res.status(StatusCodes.OK).json({ reviews, count: reviews.length })
}

module.exports = {
  getAllReviews,
  getSingleReview,
  updateReview,
  createReview,
  deleteReview,
  getSingleProductReviews
}
