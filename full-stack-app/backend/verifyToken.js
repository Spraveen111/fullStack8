import jwt from "jsonwebtoken";

const secret_key = "Please like video";

export const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }
  jwt.verify(token, secret_key, (error, decode) => {
    if (error) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    req.userId = decode.userId;
    next();
  });
};
