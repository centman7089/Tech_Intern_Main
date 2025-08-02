// @ts-nocheck
import jwt from "jsonwebtoken";
import Admin from "../models/adminModel.js";

export const protectAdmin = async (req, res, next) => {
  let token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ msg: "No token, not authorized" });

  try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // ✅ Use the correct key from your JWT payload
      const adminId = decoded.admin; // <-- This matches your token
      if (!adminId) {
        return res.status(401).json({ msg: "Invalid token: admin ID missing" });
      }

      const admin = await Admin.findById(adminId).select("-password");
      if (!admin) {
        return res.status(401).json({ msg: "admin not found" });
      }

      req.admin = admin;
      next();
  } catch (err) {
    res.status(401).json({ msg: "Token failed" });
  }
};

export const authorizeRoles = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.admin.role)) {
      return res.status(403).json({ msg: "Access denied" });
    }
    next();
  };
};
