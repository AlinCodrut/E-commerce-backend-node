const mongoose = require("mongoose")

const ProductSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please provide a product name"],
      maxLength: [250, "Numele nu poate fi mai mult de 250 de caractere"],
      minLength: 3
    },
    price: {
      type: Number,
      required: [true, "Please provide a price"],
      default: 0
    },
    description: {
      type: String,
      required: [true, "Please provide a description"],
      maxLength: [50000, "Descrierea nu poate fi mai mult de 1000 de caractere"]
    },
    image: {
      type: String,
      default: "/uploads/360.jpeg"
    },
    category: {
      type: String,
      required: [true, "Please provide a category"],
      enum: ["Saboti Medicali Leon Dama", "Saboti Medicali Medi+ Dama", "Saboti Medicali Leon Barbati", "Saboti Medicali Medi+ Barbati", "Incaltaminte de vara Leon", "Incaltaminte de vara Medi+"]
    },
    producator: {
      type: String,
      enum: {
        values: ["Leon", "Medi+"],
        message: "{VALUE} is not supported"
      }
    },
    colors: {
      type: [String],
      require: true,
      default: ["#222"]
    },
    marimi: {
      type: [Number],
      required: true
    },
    featured: {
      type: Boolean,
      default: false
    },
    freeShipping: {
      type: Boolean,
      default: false
    },
    inventory: {
      type: Number,
      required: true,
      default: 0
    },
    avarageRating: {
      type: Number,
      default: 0
    },
    numOfReviews: {
      type: Number,
      default: 0
    },
    user: {
      type: mongoose.Types.ObjectId,
      ref: "User",
      required: true
    }
  },
  { timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } } //sa facem conexiunea cu virtulas intre review si produs(un fel de selctie din databse ce nu exista in memorie)
)

ProductSchema.virtual("reviews", {
  ref: "Review",
  localField: "_id",
  foreignField: "product",
  justOne: false
})

ProductSchema.pre("remove", async function () {
  await this.model("Review").deleteMany({ product: this.id })
})

module.exports = mongoose.model("Product", ProductSchema)
