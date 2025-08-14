// @ts-nocheck
import Employer from "../models/employerModel.js"
import bcrypt from "bcryptjs";
import generateTokenAndSetCookie from "../utils/helpers/generateTokenAndSetCookie.js";
import { v2 as cloudinary } from "cloudinary";
import mongoose from "mongoose";
import generateCode from "../utils/generateCode.js";
import sendEmail from "../utils/sendEmails.js";
import jwt from "jsonwebtoken"
import crypto from "crypto"
import { v4 as uuidv4 } from "uuid";
import path from "path";
import axios from "axios";
// const fs = require( 'fs' ).promises; // Import the promises version of fs
import fs from 'fs';
import { promises as fsp } from 'fs'; // for promise-based operations
// controllers/hireRequestController.js
import HireRequest from "../models/hireModel.js";
import InternProfile from "../models/InternProfile.js";
import Course from "../models/Course.js";



// In-memory session store (use Redis in production)
const resetSessions = new Map()

// Generate session token
const generateSessionToken = () =>
{
	return crypto.randomBytes( 32 ).toString( "hex" )
}
// or alternatively:
// import fs from 'fs/promises';

cloudinary.config( {
	cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
	api_key: process.env.CLOUDINARY_API_KEY,
	api_secret: process.env.CLOUDINARY_API_SECRET,
} );


const getEmployerProfile = async ( req, res ) =>
{
	// We will fetch user profile either with username or userId
	// query is either username or userId
	const { query } = req.params;

	try
	{
		let user;

		// query is userId
		if ( mongoose.Types.ObjectId.isValid( query ) )
		{
			user = await User.findOne( { _id: query } ).select( "-password" ).select( "-updatedAt" );
		} else
		{
			// query is username
			user = await User.findOne( { username: query } ).select( "-password" ).select( "-updatedAt" );
		}

		if ( !user ) return res.status( 404 ).json( { error: "User not found" } );

		res.status( 200 ).json( user );
	} catch ( err )
	{
		res.status( 500 ).json( { error: err.message } );
		console.log( "Error in getUserProfile: ", err.message );
	}
};

const register = async ( req, res ) =>
{
	try
	{
		const { companyName, email, password, phone, location } = req.body;
		const employerExists = await Employer.findOne( { email } );
		if ( !companyName || !email || !password || !phone || !location )
		{
			return res.status( 404 ).json( { message: "All fields are required" } );
		}


		if ( employerExists )
		{
			return res.status( 400 ).json( { error: "Employer already exists" } );
		}


		const code = generateCode();

		const employer = await Employer.create( {
			companyName,
			email,
			password,
			phone,
			location,
			emailCode: code,
			emailCodeExpires: Date.now() + 10 * 60 * 1000,// 10 mins
			passwordHistory: [ { password, changedAt: new Date() } ],
			isVerified: false
		} );


		await sendEmail( email, "Verify your email", `Your verification code is: ${ code }` );
		const token = generateTokenAndSetCookie( employer._id, res, "employer" );
		await employer.save()

		res.status( 201 ).json( {
			token,
			_id: employer._id,
			email: employer.email,
			companyName: employer.companyName,
			msg: "Employee registered . Verification code sent to email.",
		} );
	} catch ( err )
	{
		console.log( err );

		res.status( 500 ).json( { error: err.message } );
		console.log( "Error in registering Employer: ", err.message );
		res.status( 500 ).json( { msg: err.message } );
	}
}






const logoutUser = ( req, res ) =>
{
	try
	{
		res.cookie( "jwt", "", { maxAge: 1 } );
		res.status( 200 ).json( { message: "User logged out successfully" } );
	} catch ( err )
	{
		res.status( 500 ).json( { error: err.message } );
		console.log( "Error in signupEmployee: ", err.message );
	}
};






// Verify Email
const verifyEmail = async ( req, res ) =>
{
	try
	{
		const { email, code } = req.body;
		const employer = await Employer.findOne( { email } );

	 if (
      !employer ||
      employer.isVerified ||
      employer.emailCode !== code ||
      Date.now() > employer.emailCodeExpires
    ) {
      return res.status(400).json({ msg: "Invalid or expired verification code" });
    }

		employer.isVerified = true;
		employer.emailCode = null;
		employer.emailCodeExpires = null;
		await employer.save();

		res.json( { msg: "Email verified successfully" } );
	} catch ( err )
	{
		console.log(err);
		
		res.status( 500 ).json( { msg: err.message } );
		
	}
};
const verifyPasswordResetCode = async ( req, res ) =>
{
	try
	{
		const { email, code } = req.body;
		const employer = await Employer.findOne( { email } );

	

		if ( employer.resetCode !== code || Date.now() > employer.reseCodeExpires )
			return res.status( 400 ).json( { msg: "Code expired or incorrect" } );

		employer.isVerified = true;
		employer.resetCode = null;
		employer.resetCodeExpires = null;
		await employer.save();

		res.json( { msg: "code verified successfully" } );
	} catch ( err )
	{
		res.status( 500 ).json( { msg: err.msg } );
	}
};

// Resend Verification Code
const resendCode = async ( req, res ) =>
{
	try
	{
		const { email } = req.body;
		const employer = await Employer.findOne( { email } );

		if ( !employer || employer.isVerified ) return res.status( 400 ).json( { msg: "Employer not found or already verified" } );

		const code = generateCode();
		employer.emailCode = code;
		employer.emailCodeExpires = Date.now() + 10 * 60 * 1000;
		await employer.save();

		await sendEmail( email, "New verification code", `Your new code is: ${ code }` );
		res.json( { msg: "New verification code sent" } );
	} catch ( err )
	{
		res.status( 500 ).json( { msg: err.message } );
	}
};

// CHANGE PASSWORD (logged in employer)
const changePassword = async (req, res) => {
  try {
    const employerId = req.employer._id;
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
      return res.status(400).json({ msg: "All fields are required" });
    }

    if (newPassword !== confirmNewPassword) {
      return res.status(400).json({ msg: "Passwords do not match" });
    }

    const employer = await Employer.findById(employerId);
    if (!employer) return res.status(404).json({ msg: "Employer not found" });

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, employer.password);
    if (!isMatch) return res.status(400).json({ msg: "Incorrect current password" });

    // Prevent setting same as current
    if (await bcrypt.compare(newPassword, employer.password)) {
      return res.status(400).json({ msg: "New password cannot be the same as the old password" });
    }

    // Prevent reusing old passwords
    for (const entry of employer.passwordHistory || []) {
      if (await bcrypt.compare(newPassword, entry.password)) {
        return res.status(400).json({ msg: "You have already used this password before" });
      }
    }

    // Store old password in history
    employer.passwordHistory = employer.passwordHistory || [];
    employer.passwordHistory.push({
      password: employer.password,
      changedAt: new Date(),
    });
    if (employer.passwordHistory.length > 5) {
      employer.passwordHistory.shift();
    }

    // Assign new password in plain text — pre-save will hash it
    employer.password = newPassword;
    await employer.save();

    res.json({ msg: "Password changed successfully" });
  } catch (err) {
    console.error("changePassword error:", err);
    res.status(500).json({ msg: "Server error" });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;
    if (!token || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.purpose !== "password_reset") {
      return res.status(400).json({ message: "Invalid token" });
    }

    const employer = await Employer.findById(decoded.employerId);
    if (!employer) return res.status(404).json({ message: "User not found" });

    // Prevent reusing current password
    if (await bcrypt.compare(newPassword, employer.password)) {
      return res.status(400).json({ message: "New password cannot be the same as the old password" });
    }

    // Prevent reusing passwords from history
    for (const entry of employer.passwordHistory || []) {
      if (await bcrypt.compare(newPassword, entry.password)) {
        return res.status(400).json({ message: "You have already used this password before" });
      }
    }

    // Save current hashed password into history
    employer.passwordHistory = employer.passwordHistory || [];
    employer.passwordHistory.push({
      password: employer.password,
      changedAt: new Date(),
    });
    if (employer.passwordHistory.length > 5) {
      employer.passwordHistory.shift();
    }

    // Set new password in plain text — pre-save hook hashes
    employer.password = newPassword;

    // Clear reset tokens
    employer.emailCode = undefined;
    employer.emailCodeExpires = undefined;
    employer.resetCode = undefined;
    employer.resetCodeExpires = undefined;

    await employer.save();

    res.json({ success: true, message: "Password updated" });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Token expired" });
    }
    console.error("resetPassword error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const employer = await Employer.findOne({ email });

    if (!employer) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const isPasswordCorrect = await employer.correctPassword(password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ msg: "Invalid password" });
    }

    // Email verification check
    if (!employer.isVerified) {
      const code = generateCode();
      employer.emailCode = code;
      employer.emailCodeExpires = Date.now() + 10 * 60 * 1000;
      await employer.save();
      await sendEmail(email, "Verification Required", `Your new code: ${code}`);

      return res.status(403).json({
        msg: "Account not verified. New verification code sent.",
        isVerified: false,
      });
    }

    const token = generateTokenAndSetCookie(employer._id, res, "employer");

    return res.status(200).json({
      token,
      _id: employer._id,
      email: employer.email,
      msg: "Login successful",
      isVerified: true,
      cacStatus: employer.cacStatus,
    });
  } catch (error) {
    console.error("Error in loginEmployer:", error.message);
    res.status(500).json({ error: error.message });
  }
};

const updateUser = async (req, res) => {
  const { companyName, email, phone, location, logo, description } = req.body;
  const employerId = req.employer._id;

  try {
    let employer = await Employer.findById(employerId);
    if (!employer) return res.status(404).json({ error: "Employer not found" });

    if (req.params.id !== employerId.toString()) {
      return res.status(403).json({ error: "You cannot update another employer's profile" });
    }

    // Handle logo upload
    if (logo) {
      if (employer.logo) {
        await cloudinary.uploader.destroy(employer.logo.split("/").pop().split(".")[0]);
      }
      const uploadedResponse = await cloudinary.uploader.upload(logo);
      employer.logo = uploadedResponse.secure_url;
    }

    employer.companyName = companyName || employer.companyName;
    employer.email = email || employer.email;
    employer.phone = phone || employer.phone;
    employer.location = location || employer.location;
    employer.description = description || employer.description;

    await employer.save();

    // remove password from response
    employer.password = undefined;

    res.status(200).json(employer);
  } catch (err) {
    console.error("updateUser error:", err);
    res.status(500).json({ error: "Server error" });
  }
};




const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const employer = await Employer.findOne({ email });
    if (!employer) return res.status(400).json({ msg: "Email not found" });

    const code = employer.setPasswordResetCode();
    await employer.save({ validateBeforeSave: false });
    await sendEmail(email, "Password Reset Code", `Your reset code is: ${code}`);
    res.json({ msg: "Password reset code sent" });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
};


const verifyResetCode = async (req, res) => {
  try {
    const { email, code } = req.body;
    const employer = await Employer.findOne({ email });

    if (!employer || !employer.validateResetCode(code))
      return res.status(400).json({ message: "Invalid/expired Code" });

    const token = jwt.sign(
      { employerId: employer._id, purpose: "password_reset" },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ success: true, token, message: "Code verified" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

// Step 3 – change the password with the JWT
// RESET PASSWORD (via reset token produced after verifyResetCode)



const uploadCacDocument = async (req, res) => {
  try {
    const employerId = req.params.employerId; // 👈 Get employerId from the route
    const file = req.file;
    const description = req.body.description;

    // Check if the logged-in employer matches the ID in the route
    if (employerId !== req.employer._id.toString()) {
      return res.status(403).json({ error: "Unauthorized action" });
    }

    // Check for file
    if (!file) {
      return res.status(400).json({ error: "CAC document is required" });
    }

    // Find employer
    const employer = await Employer.findById(employerId);
    if (!employer) {
      return res.status(404).json({ error: "Employer not found" });
    }

    // Update CAC details
    employer.cacDocument = {
      url: file.path,
      public_id: file.filename,
    };
    employer.cacDescription = description;
    employer.cacVerified = false;
    employer.cacStatus = "pending";
    employer.cacRejectionReason = "";

    await employer.save();

    res.status(200).json({
      message: "CAC uploaded successfully. Awaiting admin verification.",
    });
  } catch (err) {
    console.error("Error uploading CAC: ", err);
    res.status(500).json({ error: "Server error" });
  }
};



// Utility: escape regex specials for exact, case-insensitive name match
const escapeRegex = (str = "") => String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const createHireRequestWithMatches = async (req, res) => {
  try {
    const { employerId } = req.params;

    // make sure the route is used by the same logged-in employer
    if (!req.employer || String(req.employer._id) !== String(employerId)) {
      return res.status(403).json({ message: "Unauthorized employer" });
    }

    let {
      selectedCourse, // NAME
      workType,
      location,
      duration,
      paymentType,
      paymentAmount,
      additionalInfo,
    } = req.body;

    if (!selectedCourse || !workType) {
      return res.status(400).json({ message: "selectedCourse and workType are required" });
    }

    // normalize workType to lowercase to match InternProfile.workType enum style
    workType = String(workType).trim().toLowerCase();

    // 1) Find Course by NAME (exact, case-insensitive)
    const course = await Course
      .findOne({ name: { $regex: `^${escapeRegex(selectedCourse)}$`, $options: "i" } })
      .select("_id name");

    if (!course) {
      return res.status(400).json({ message: `Course not found: ${selectedCourse}` });
    }

    // 2) Find all matching interns: selectedCourses contains course._id AND workType matches
    const matchedInterns = await InternProfile.find({
      selectedCourses: course._id,   // array contains this id
      workType: workType,            // exact match
    })
      .populate("user", "firstName lastName email profilePic")
      .populate("selectedCourses", "name")
      .lean();

    // 3) Create hire request (store course id, but we will return the name)
    const hireRequestDoc = await HireRequest.create({
      employerId,
      selectedCourse: course._id,
      workType,
      location,
      duration,
      paymentType,   // left flexible in schema
      paymentAmount,
      additionalInfo,
      interns: matchedInterns.map((p) => p._id),
    });

    // 4) Shape response so selectedCourse is NAME in the payload
    const hireRequest = {
      ...hireRequestDoc.toObject(),
      selectedCourse: course.name,
    };

    return res.status(201).json({
      message: "Hire request created successfully",
      hireRequest,
      matchedInterns,
    });
  } catch (error) {
    console.error("Error creating hire request:", error);
    res.status(500).json({ message: "Server Error", error: error.message });
  }
};









export
{
	register,
	login,
	logoutUser,
	updateUser,
	getEmployerProfile,
	verifyEmail,
	resendCode,
	verifyResetCode,
	forgotPassword,
	resetPassword,
	changePassword,
  uploadCacDocument,
  createHireRequestWithMatches

};
