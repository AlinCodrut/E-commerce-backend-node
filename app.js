require("dotenv").config()
const express = require("express")
const app = express()
require("express-async-errors")
const fileUpload = require("express-fileupload")

//rest of the packages

const morgan = require("morgan") // asta e un pachet ce ne spune de fiecare data in consola ce pagina am vrut sa accesem cu ce status code si tot
const cookieParser = require("cookie-parser") //pachetul ca sa putem accesa datele dintr-un cookie
const rateLimiter = require("express-rate-limit")
const helmet = require("helmet")
const xss = require("xss-clean")
const cors = require("cors")
const mongoSanitize = require("express-mongo-sanitize")

//security packages

app.set("trust proxy", 1)
app.use(rateLimiter({ windowMs: 15 * 60 * 1000, max: 60 }))
app.use(helmet())
app.use(cors())
app.use(xss())
app.use(mongoSanitize())

// Builtin express middleware
app.use(morgan("tiny"))
app.use(express.json())
app.use(cookieParser(process.env.JWT_SECRET))
app.use(express.static("./public"))
app.use(fileUpload())

// Basic Routes

app.get("/", (req, res) => {
  return res.send("Welcome")
})

const authRouter = require("./routes/authRoutes")
const userRoutes = require("./routes/userRoutes")
const productRouter = require("./routes/productRoutes")
const reviewRouter = require("./routes/reviewRoutes")
const orderRoutes = require("./routes/orderRoutes")

app.use("/api/v1/auth", authRouter)
app.use("/api/v1/users", userRoutes)
app.use("/api/v1/products", productRouter)
app.use("/api/v1/reviews", reviewRouter)
app.use("/api/v1/orders", orderRoutes)

// Our middleware
const notFound = require("./middleware/not-found")
const errorHandler = require("./middleware/error-handler")
app.use(errorHandler)
app.use(notFound)

// Database
const connectDB = require("./db/connect")

const port = process.env.PORT || 5000

const start = async () => {
  try {
    await connectDB(process.env.MONGO_URI)
    app.listen(port, console.log(`Server is listening on port ${port}...`))
  } catch (error) {
    console.log(error)
  }
}

start()
