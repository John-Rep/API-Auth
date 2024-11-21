const jwt = require("jsonwebtoken");
const config = require("../config/key.js");
const User = require("../models/user.js");

verifyToken = (req, res, next) => {
  let token = req.headers["x-access-token"];

  if (!token) {
    return res.status(403).send({ message: "No token provided!" });
  }

  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      return res.status(401).send({
        message: "Unauthorized!",
      });
    }
    req.userId = decoded.id;
    next();
  });
};
isExist = async (req, res, next) => {
  const user = await User.findById(req.userId);
  if (!user) {
    res.status(403).send({ message: "User not found" });
    return;
  }
  next();
};
isAdmin = async (req, res, next) => {
  const user = await User.findById(req.userId);
  if (!user.admin) {
    res.status(403).send({ message: "User is not admin" });
    return;
  }
  next();
};

const authJwt = {
  verifyToken,
  isExist,
  isAdmin,
};
module.exports = authJwt;
