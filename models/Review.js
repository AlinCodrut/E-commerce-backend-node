const mongoose = require("mongoose")

const ReviewSchema = new mongoose.Schema(
  {
    rating: {
      type: Number,
      min: 1,
      max: 5,
      required: [true, "Please provide a rating"]
    },
    title: {
      type: String,
      trim: true,
      required: [true, "Please provide a title"],
      maxlength: 100
    },
    comment: {
      type: String,
      required: [true, "Please provide a review text"]
    },
    user: {
      type: mongoose.Types.ObjectId,
      ref: "User",
      required: true
    },
    product: {
      type: mongoose.Types.ObjectId,
      ref: "Product",
      required: true
    }
  },
  { timestamps: true }
)

ReviewSchema.index({ product: 1, user: 1 }, { unique: true }) //Sa indexam reviewurile si sa le facem unice incat un user sa nu poate las mai mult de un raiting per produs

ReviewSchema.statics.calculateAverageRating = async function (productId) {
  const result = await this.aggregate([
    { $match: { product: productId } },
    {
      $group: {
        _id: null,
        avarageRating: { $avg: "$rating" },
        numOfReviews: { $sum: 1 }
      }
    }
  ])

  try {
    await this.model("Product").findOneAndUpdate(
      { _id: productId },
      {
        avarageRating: Math.ceil(result[0]?.avarageRating || 0),
        numOfReviews: result[0]?.numOfReviews || 0
      }
    )
  } catch (error) {
    console.log(error)
  }
}

ReviewSchema.post("save", async function () {
  await this.constructor.calculateAverageRating(this.product)
})

ReviewSchema.post("remove", async function () {
  await this.constructor.calculateAverageRating(this.product)
})

module.exports = mongoose.model("Review", ReviewSchema)
