const setRateLimit = require("express-rate-limit");
const User = require("../models/user.js");



rateLimiter = async (req, res, next) => {
    const user = await User.findById(req.userId);
    if (user.admin) {
        return adminLimiter(req, res, next);
    } else {
        return userLimiter(req, res, next);
    }
  };


const userLimiter = setRateLimit({
        windowMs: 60 * 1000,
        max: 5,
        message: "You have exceeded your 5 requests per minute limit.",
        headers: true,
})

const adminLimiter = setRateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: "You have exceeded your 10 requests per minute limit.",
    headers: true,
})


module.exports = rateLimiter;