// @ts-nocheck
import Admin from "../models/adminModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import generateTokenAndSetCookie from "../utils/helpers/generateTokenAndSetCookie.js";
import { v2 as cloudinary } from "cloudinary";
import generateCode from "../utils/generateCode.js";
import sendEmail from "../utils/sendEmails.js";
import mongoose from "mongoose";
import Employer from "../models/employerModel.js";

// In-memory session store (use Redis in production)
const resetSessions = new Map();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Helper to safely format admin response
const formatAdminResponse = (admin) => ({
  _id: admin._id,
  firstName: admin.firstName || "",
  lastName: admin.lastName || "",
  email: admin.email || "",
  phone: admin.phone || "",
  country: admin.country || "",
  role: admin.role || "",
  profilePic: admin.profilePic || "",
  isVerified: admin.isVerified || false,
});

// Auth Controllers
// ========================
export const createAdmin = async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone, country, role } = req.body;

    if (!firstName || !lastName || !email || !password || !phone || !country) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const adminExists = await Admin.findOne({ email });
    if (adminExists) {
      return res.status(400).json({ error: "Admin already exists" });
    }

    const code = generateCode();
    const admin = new Admin({
      firstName,
      lastName,
      email,
      password, // pre-save hook will hash
      phone,
      country,
      role,
      emailCode: code,
      emailCodeExpires: Date.now() + 10 * 60 * 1000, // 10 mins
      passwordHistory: [{ password, changedAt: new Date() }],
      isVerified: false,
    });

    await admin.save();
    await sendEmail(email, "Verify your email", `Your verification code is: ${code}`);

    const token = generateTokenAndSetCookie(admin._id, res, "admin");

    res.status(201).json({
      token,
      ...formatAdminResponse(admin),
      msg: "Admin registered. Verification code sent to email.",
    });
  } catch (err) {
    console.error("Error registering admin:", err.message);
    res.status(500).json({ error: err.message });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin || !(await admin.correctPassword(password))) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    if (!admin.isVerified) {
      const code = generateCode();
      admin.emailCode = code;
      admin.emailCodeExpires = Date.now() + 10 * 60 * 1000;
      await admin.save();
      await sendEmail(email, "Verification Required", `Your new code: ${code}`);
      return res.status(403).json({
        msg: "Account not verified. New verification code sent.",
        isVerified: false,
      });
    }

    const token = generateTokenAndSetCookie(admin._id, res, "admin");
    res.status(200).json({
      token,
      ...formatAdminResponse(admin),
      msg: "Login successful",
      isVerified: true,
    });
  } catch (error) {
    console.error("Error in loginAdmin:", error.message);
    res.status(500).json({ error: error.message });
  }
};

export const logoutUser = (req, res) => {
  try {
    res.cookie("jwt", "", { maxAge: 1 });
    res.status(200).json({ message: "User logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err.message);
    res.status(500).json({ error: err.message });
  }
};

export const getUserProfile = async (req, res) => {
  const { query } = req.params;
  try {
    let user;
    if (mongoose.Types.ObjectId.isValid(query)) {
      user = await Admin.findById(query).select("-password -updatedAt");
    } else {
      user = await Admin.findOne({ username: query }).select("-password -updatedAt");
    }

    if (!user) return res.status(404).json({ error: "User not found" });
    res.status(200).json(user);
  } catch (err) {
    console.error("getUserProfile error:", err.message);
    res.status(500).json({ error: err.message });
  }
};

export const updateUser = async (req, res) => {
  const { firstName, lastName, email, phone, country } = req.body;
  let { logo } = req.body;
  const userId = req.admin._id;

  try {
    let admin = await Admin.findById(adminId);
    if (!admin) return res.status(404).json({ error: "Admin not found" });

    if (req.params.id !== adminId.toString()) {
      return res.status(403).json({ error: "Unauthorized update" });
    }

    if (profilePic && admin.profilePic) {
      await cloudinary.uploader.destroy(user.profilePic.split("/").pop().split(".")[0]);
    }

    const uploadedPic = profilePic
      ? (await cloudinary.uploader.upload(profilePic)).secure_url
      : user.profilePic;

    Object.assign(admin, {
      firstName: firstName || user.firstName,
      lastName: lastName || user.lastName,
      email: email || user.email,
      phone: phone || user.phone,
      country: country || user.country,
      profilePic: uploadedPic,
    });

    await user.save();
    res.status( 200 ).json( {
        _id: admin._id,
  firstName: admin.firstName || "",
  lastName: admin.lastName || "",
  email: admin.email || "",
  phone: admin.phone || "",
  country: admin.country || "",
  role: admin.role || "",
  profilePic: admin.profilePic || "",
  isVerified: admin.isVerified || false,
    });
  } catch (err) {
    console.error("updateUser error:", err.message);
    res.status(500).json({ error: err.message });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { email, code } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin || admin.isVerified)
      return res.status(400).json({ msg: "Invalid request" });

    if (admin.emailCode !== code || Date.now() > admin.emailCodeExpires)
      return res.status( 400 ).json( { msg: "Code expired or incorrect" } );

    admin.isVerified = true;
    admin.emailCode = null;
    admin.emailCodeExpires = null;
    await admin.save();

    res.json({ msg: "Email verified successfully" });
    
    // if (
    //   !admin ||
    //   admin.isVerified ||
    //   admin.emailCode !== code ||
    //   Date.now() > admin.emailCodeExpires
    // ) {
    //   return res.status(400).json({ msg: "Invalid or expired verification code" });
    // }

    
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
};

export const resendCode = async (req, res) => {
  try {
    const { email } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin || admin.isVerified)
      return res.status(400).json({ msg: "admin not found or already verified" });

    const code = generateCode();
    admin.emailCode = code;
    admin.emailCodeExpires = Date.now() + 10 * 60 * 1000;
    await admin.save();

    await sendEmail(email, "New verification code", `Your new code is: ${code}`);
    res.json({ msg: "New verification code sent" });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
};

export const changePassword = async (req, res) => {
  try {
    const adminId = req.admin._id;
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    if (newPassword !== confirmNewPassword) {
      return res.status(400).json({ msg: "Passwords do not match" });
    }

    const admin = await Admin.findById(adminId);
    if (!admin) return res.status(404).json({ msg: "Admin not found" });

    if (!(await admin.correctPassword(currentPassword))) {
      return res.status(400).json({ msg: "Incorrect current password" });
    }

    // Prevent reuse
    const reused = await Promise.any(
      admin.passwordHistory.map(({ password }) => admin.correctPassword(newPassword))
    ).catch(() => false);

    if (reused) return res.status(400).json({ msg: "Password reused from history" });

    admin.password = newPassword; // Let pre-save hook hash
    admin.passwordHistory.push({ password: admin.password, changedAt: new Date() });
    if (admin.passwordHistory.length > 5) admin.passwordHistory.shift();

    await admin.save();
    res.json({ msg: "Password changed successfully" });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.purpose !== "password_reset") {
      return res.status(400).json({ message: "Invalid token" });
    }

    const admin = await Admin.findById(decoded.adminId);
    if (!admin) return res.status(404).json({ message: "User not found" });

    admin.password = newPassword; // Let pre-save hook hash
    admin.emailCode = undefined;
    admin.emailCodeExpires = undefined;
    await admin.save();

    res.json({ success: true, message: "Password updated" });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Token expired" });
    }
    res.status(500).json({ message: "Server error" });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(400).json({ msg: "Email not found" });

    const code = admin.setPasswordResetCode();
    await admin.save({ validateBeforeSave: false });
    await sendEmail(email, "Password Reset Code", `Your reset code is: ${code}`);
    res.json({ msg: "Password reset code sent" });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
};

export const verifyResetCode = async (req, res) => {
  try {
    const { email, code } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin || !admin.validateResetCode(code))
      return res.status(400).json({ message: "Invalid/expired Code" });

    const token = jwt.sign(
      { adminId: admin._id, purpose: "password_reset" },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ success: true, token, message: "Code verified" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};


export const getAdminUser = async (req, res) => {
  try {
    const admin = await Admin.find({ role: "admin" });
    res.status(200).json(admin);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

export const verifyCac = async (req, res) => {
  try {
    const employer = await Employer.findById(req.params.employerId);
    if (!employer) return res.status(404).json({ error: "Employer not found" });

    employer.cacStatus = "approved";
    employer.cacVerified = true;
    employer.cacRejectionReason = "";

    await employer.save();
    res.json({ message: "CAC verified successfully." });
  } catch (err) {
    console.error("verifyCac error:", err);
    res.status(500).json({ error: "Server error" });
  }
};
