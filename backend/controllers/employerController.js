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



const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const employer = await Employer.findOne({ email });

    if (!employer) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const isPasswordCorrect = await employer.correctPassword(password); // Use schema method
    if (!isPasswordCorrect) {
      return res.status(400).json({ msg: "Invalid password" });
    }

    // Check email verification
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

    // Check if CAC document is uploaded
    if (!employer.cacDocument?.url || !employer.cacDocument.description) {
      return res.status(403).json({
        msg: "Login blocked. Please upload CAC document and wait for admin verification.",
        requiresCacVerification: true,
      });
    }

    // Check CAC status
    if (employer.cacStatus !== "approved") {
      return res.status(403).json({
        msg:
          employer.cacStatus === "rejected"
            ? "Your CAC was rejected. Please re-upload with valid CAC documents."
            : "Login blocked. Your CAC document is pending verification by admin.",
        requiresCacVerification: true,
        cacStatus: employer.cacStatus,
        rejectionReason: employer.cacRejectionReason || "",
      });
    }

    // Generate token and return success
    const token = generateTokenAndSetCookie(employer._id, res, "employer");

    return res.status(200).json({
      token,
      _id: employer._id,
      email: employer.email,
      msg: "Login successful",
      isVerified: true,
    });

  } catch (error) {
    console.error("Error in loginEmployer: ", error.message);
    res.status(500).json({ error: error.message });
  }
};


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


const updateUser = async ( req, res ) =>
{
	const { companyName, email, phone, location} = req.body;
	let { logo } = req.body;

	const userId = req.employer._id;
	try
	{
		let employer = await Employer.findById( employerId );
		if ( !employer ) return res.status( 400 ).json( { error: "Employer not found" } );

		if ( req.params.id !== employerId.toString() )
			return res.status( 400 ).json( { error: "You cannot update other employer's profile" } );

		if ( password )
		{
			const salt = await bcrypt.genSalt( 10 );
			const hashedPassword = await bcrypt.hash( password, salt );
			employer.password = hashedPassword;
		}

		if ( logo )
		{
			if ( employer.logo )
			{
				await cloudinary.uploader.destroy( employer.logo.split( "/" ).pop().split( "." )[ 0 ] );
			}

			const uploadedResponse = await cloudinary.uploader.upload( logo );
			logo = uploadedResponse.secure_url;
		}

		employer.companyName = companyName || employer.companyName;
		employer.email = email || employer.email;
		employer.description = description || employer.description;
		employer.logo = logo || employer.logo;

		employer = await employer.save();



		// password should be null in response
		employer.password = null;

		res.status( 200 ).json( employer );
	} catch ( err )
	{
		res.status( 500 ).json( { error: err.message } );
		console.log( "Error in update Employer: ", err.message );
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

const changePassword = async (req, res) => {
  try {
    const employerId = req.employer._id;
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    if (newPassword !== confirmNewPassword)
      return res.status(400).json({ msg: "Passwords do not match" });

    const employer = await Employer.findById(employerId);
    if (!employer) return res.status(404).json({ msg: "Employer not found" });

    const isMatch = await bcrypt.compare(currentPassword, employer.password);
    if (!isMatch) return res.status(400).json({ msg: "Incorrect current password" });

    const reused = await Promise.any(
      user.passwordHistory.map(({ password }) => bcrypt.compare(newPassword, password))
    ).catch(() => false);

    if (reused) return res.status(400).json({ msg: "Password reused from history" });

    const hashed = await bcrypt.hash(newPassword, 10);

    employer.password = hashed;
    employer.passwordHistory.push({ password: employer.password, changedAt: new Date() });
    if (employer.passwordHistory.length > 5) employer.passwordHistory.shift();

    await employer.save();
    res.json({ msg: "Password changed successfully" });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
};



const forgotPassword = async ( req, res ) =>
{
	try
	{
		const { email } = req.body;
		const employer = await Employer.findOne( { email } );

		if ( !employer )
		{
			return res.status( 400 ).json( { msg: "Email not found" } );
		}

		const code = employer.setPasswordResetCode();
		await employer.save( { validateBeforeSave: false } )
		await sendEmail( email, "Password Reset Code", `Your reset code is: ${ code }` );
		res.json( { msg: "Password reset code sent" } );
	} catch ( err )
	{
		res.status( 500 ).json( { msg: err.message } );
	}
};


const verifyResetCode = async ( req, res ) =>
{
	try
	{
		const { email, code } = req.body;
		const employer = await Employer.findOne( { email } );

		if ( !employer || !employer.validateResetCode( code ) )
		{
			return res.status( 400 ).json( { message: "Invalid/expired OTP" } );
		}

		// Generate short-lived JWT (15 mins expiry)
		const token = jwt.sign(
			{ employerId: employer._id, purpose: "password_reset" },
			process.env.JWT_SECRET,
			{ expiresIn: "15m" }
		);

		res.json( { success: true, token, message: "OTP verified" } );
	} catch ( error )
	{
		res.status( 500 ).json( { message: "Server error" } );
	}
};
// Step 3 – change the password with the JWT
const resetPassword = async ( req, res ) =>
{
	try
	{
		const { token, newPassword, confirmPassword } = req.body;

		if ( newPassword !== confirmPassword )
		{
			return res.status( 400 ).json( { message: "Passwords do not match" } );
		}

		// Verify JWT
		const decoded = jwt.verify( token, process.env.JWT_SECRET );
		if ( decoded.purpose !== "password_reset" )
		{
			return res.status( 400 ).json( { message: "Invalid token" } );
		}

		const employer = await Employer.findById( decoded.employerId );
		if ( !employer )
		{
			return res.status( 404 ).json( { message: "employer not found" } );
		}

		// Update password & clear OTP
		employer.password = newPassword;
		employer.otp = undefined;
		employer.otpExpires = undefined;
		await employer.save();

		res.json( { success: true, message: "Password updated" } );
	} catch ( error )
	{
		if ( error.name === "TokenExpiredError" )
		{
			return res.status( 400 ).json( { message: "Token expired" } );
		}
		res.status( 500 ).json( { message: "Server error" } );
	}
};

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
	uploadCacDocument

};
