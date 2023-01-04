const mongoose = require("mongoose")
const validator = require("validator") // asta e un pachet pe care sa-l folisim ca sa putem valida adresa de email sau alte lucruri ce ne trebuie fara sa mai tot scriem regEX si altele
const bcrypt = require("bcryptjs") // Pachet pentru hasihin parola


const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please provide a name"],
    maxLength: 50,
    minLength: 3
  },
  email: {
    type: String,
    unique: true,
    required: [true, "Please provide a email address"],
    validate: {
      validator: validator.isEmail, // aici validam cu acel pachet sa fie email si nu altceva
      message: "Please enter a valid email address"
    }
  },
  password: {
    type: String,
    required: [true, "Please provide a passwprd"],
    minLength: 6
  },
  role: {
    type: String,
    enum: ["admin", "user"],
    default: "user"
  }
})

UserSchema.pre("save", async function () {
  // aici criptam parola
  if (!this.isModified("password")) return

  const salt = await bcrypt.genSalt(10)
  this.password = await bcrypt.hash(this.password, salt)
})

UserSchema.methods.comparePassword = async function (canditatePassword) {
  //ca sa comparam parola sa vedem daca este a usereului atunci cand face login
  const isMatch = await bcrypt.compare(canditatePassword, this.password)
  return isMatch
}

module.exports = mongoose.model("User", UserSchema)
