const { UnauthorizedError } = require("../errors")

const checkPermission = (requestUser, resourceUserId) => {
  if (requestUser.role === "admin") return

  if (requestUser.userId !== resourceUserId.toString()) {
    throw new UnauthorizedError("You do not have permission to access this page")
  }
}

module.exports = checkPermission
