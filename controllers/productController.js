const Product = require("../models/Product")
const { StatusCodes } = require("http-status-codes")
const { BadRequestError, UnauthenticatedError, NotFoundError } = require("../errors")
const path = require("path")

const getAllProducts = async (req, res) => {
  const products = await Product.find({})

  res.status(StatusCodes.OK).json({ products, count: products.length })
}

const getSingleProduct = async (req, res) => {
  const { id: productId } = req.params // este id si nu _id deoarece in router am specificat id simplu fara liniuta

  const product = await Product.findOne({ _id: productId }).populate("reviews")
  res.status(StatusCodes.OK).json({ product })

  if (!product) {
    throw new NotFoundError(`Nici un produs cu id-ul: ${productId}`)
  }
}
const createProduct = async (req, res) => {
  req.body.user = req.user.userId
  const product = await Product.create(req.body)
  res.status(StatusCodes.CREATED).json(product)
}

const updateProduct = async (req, res) => {
  const { id: productId } = req.params // este id si nu _id deoarece in router am specificat id simplu fara liniuta

  const product = await Product.findOneAndUpdate({ _id: productId }, req.body, { new: true, runValidators: true })

  if (!product) {
    throw new NotFoundError(`Nici un produs cu id-ul: ${productId}`)
  }

  res.status(StatusCodes.OK).json({ product })
}

const deleteProduct = async (req, res) => {
  const { id: productId } = req.params // este id si nu _id deoarece in router am specificat id simplu fara liniuta

  const product = await Product.findOne({ _id: productId })
  if (!product) {
    throw new NotFoundError(`Nici un produs cu id-ul: ${productId}`)
  }
  await product.remove()
  res.status(StatusCodes.OK).json({ msg: "Product deleted" })
}

const uploadImage = async (req, res) => {
  if (!req.files) {
    throw new BadRequestError("No file uploaded")
  }

  const productImage = req.files.image
  if (!productImage.mimetype.startsWith("image")) {
    throw new BadRequestError("Please Upload Image")
  }
  const maxSize = 1024 * 1024
  if (productImage.size > maxSize) {
    throw new BadRequestError("Please upload image smaller than 1MB")
  }

  const imagePath = path.join(__dirname, "../public/uploads/" + `${productImage.name}`)
  await productImage.mv(imagePath)
  return res.status(StatusCodes.OK).json({ image: `/uploads/${productImage.name}` })
}

module.exports = {
  getAllProducts,
  getSingleProduct,
  createProduct,
  updateProduct,
  deleteProduct,
  uploadImage
}
