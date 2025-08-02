// @ts-nocheck
import jwt from "jsonwebtoken";
import Employer from "../models/employerModel.js";

const protectEmployer = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // ✅ Use the correct key from your JWT payload
      const employerId = decoded.employer; // <-- This matches your token
      if (!employerId) {
        return res.status(401).json({ msg: "Invalid token: employer ID missing" });
      }

      const employer = await Employer.findById(employerId).select("-password");
      if (!employer) {
        return res.status(401).json({ msg: "Employer not found" });
      }

      req.employer = employer;
      next();
    } catch (error) {
      return res.status(401).json({ msg: "Invalid or expired token" });
    }
  } else {
    return res.status(401).json({ msg: "No token provided" });
  }
};

export default protectEmployer;
