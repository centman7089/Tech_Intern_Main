// @ts-nocheck
import User from "../models/userModel.js";
import Post from "../models/postModel.js";
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
import { profile } from "console";
import InternProfile from "../models/internProfile.js";

// In-memory session store (use Redis in production)
const resetSessions = new Map()

// Generate session token
const generateSessionToken = () => {
  return crypto.randomBytes(32).toString("hex")
}
// or alternatively:
// import fs from 'fs/promises';

cloudinary.config({
	cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
	api_key: process.env.CLOUDINARY_API_KEY,
	api_secret: process.env.CLOUDINARY_API_SECRET,
});


const getUserProfile = async (req, res) => {
	// We will fetch user profile either with username or userId
	// query is either username or userId
	const { query } = req.params;

	try {
		let user;

		// query is userId
		if (mongoose.Types.ObjectId.isValid(query)) {
			user = await User.findOne({ _id: query }).select("-password").select("-updatedAt");
		} else {
			// query is username
			user = await User.findOne({ username: query }).select("-password").select("-updatedAt");
		}

		if (!user) return res.status(404).json({ error: "User not found" });

		res.status(200).json(user);
	} catch (err) {
		res.status(500).json({ error: err.message });
		console.log("Error in getUserProfile: ", err.message);
	}
};

const register = async ( req, res ) =>
{
	try {
		const {firstName,lastName,email,password, phone, country,state,city, address } = req.body;
		const userExists = await User.findOne({ email });
		  if ( !firstName || !lastName || !email || !password || !phone || !country || !state || !city || !address  ) {
			return res.status(404).json({message: "All fields are required"});
		  }
	

		if (userExists) {
			return res.status(400).json({ error: "User already exists" });
		}
		

		const code = generateCode();

		const user = await User.create({
			firstName,
			lastName,
			email,
			password,
			phone,
			country,
			state,
			city,
			address,
			emailCode: code,
			emailCodeExpires: Date.now() + 10 * 60 * 1000 ,// 10 mins
			passwordHistory: [ { password, changedAt: new Date() } ],
			isVerified: false
		} );


		 // Create empty profile for job seeker
		 const profile = new InternProfile({
			user: user._id
		  });
		  await profile.save();
	
		  // Update user with profile reference
		  user.profile = profile._id;
		  await user.save();
		
	    // @ts-ignore
	    await sendEmail(email, "Verify your email", `Your verification code is: ${code}`);
    


		if (user) {
			generateTokenAndSetCookie(user._id, res);

			res.status(201).json({
				_id: user._id,
				firstName: user.firstName,
				lastName: user.lastName,
				email: user.email,
				phone: user.phone,
				country: user.country,
				state: user.state,
				city: user.city,
				address: user.address,
				profile: user.profile,
				profilePic: user.profilePic,
				msg: "User registered. Verification code sent to email."
			})
			
		} else {
			res.status(400).json({ error: "Invalid user data" });
		}
	} catch ( err )
	{
		console.log(err);
		
		res.status(500).json({ error: err.message });
		console.log( "Error in registering User: ", err.message );
		res.status(500).json({ msg: err.message });
	}
}



const login = async (req, res) => {
	try {
	  const { email, password } = req.body;
	  const user = await User?.findOne({ email });
	  
		if ( !user )
		{
			return res.status(400).json({ msg: "Invalid credentials" });
	  }
  
	  const isPasswordCorrect = await user.correctPassword(password); // Use the schema method
        
        if (!isPasswordCorrect) {
            return res.status(400).json({ error: "Invalid password" }); // More specific
        }
  
	  // If user is not verified
	  if (!user.isVerified) {
		// Generate new verification code
		const code = generateCode();
		user.emailCode = code;
		user.emailCodeExpires = Date.now() + 10 * 60 * 1000; // 10 mins
	
  
		// Send verification email
		await sendEmail(
		  email,
		  "New Verification Code",
		  `Your new verification code is: ${code}`
		);
		  
		await user.save();
  
		return res.status(403).json({ 
		  msg: "Account not verified. A new verification code has been sent to your email.",
		  isVerified: false 
		});
	  }
  
	//   if (user.isFrozen) {
	// 	user.isFrozen = false;
	// 	await user.save();
	//   }
  
	  const token = generateTokenAndSetCookie(user._id, res);
  
	  res.status(200).json({
		token,
		_id: user._id,
		email: user.email,
		msg: "Login Successful",
		isVerified: true,
		onboardingCompleted: user.onboardingCompleted
	  });
	} catch ( error )
	{
		console.log(error);
		
	  res.status(500).json({ error: error.message });
	  console.log("Error in loginUser: ", error.message);
	}
};

const logoutUser = (req, res) => {
	try {
		res.cookie("jwt", "", { maxAge: 1 });
		res.status(200).json({ message: "User logged out successfully" });
	} catch (err) {
		res.status(500).json({ error: err.message });
		console.log("Error in signupUser: ", err.message);
	}
};

const followUnFollowUser = async (req, res) => {
	try {
		const { id } = req.params;
		const userToModify = await User.findById(id);
		const currentUser = await User.findById(req.user._id);

		if (id === req.user._id.toString())
			return res.status(400).json({ error: "You cannot follow/unfollow yourself" });

		if (!userToModify || !currentUser) return res.status(400).json({ error: "User not found" });

		const isFollowing = currentUser.following.includes(id);

		if (isFollowing) {
			// Unfollow user
			await User.findByIdAndUpdate(id, { $pull: { followers: req.user._id } });
			await User.findByIdAndUpdate(req.user._id, { $pull: { following: id } });
			res.status(200).json({ message: "User unfollowed successfully" });
		} else {
			// Follow user
			await User.findByIdAndUpdate(id, { $push: { followers: req.user._id } });
			await User.findByIdAndUpdate(req.user._id, { $push: { following: id } });
			res.status(200).json({ message: "User followed successfully" });
		}
	} catch (err) {
		res.status(500).json({ error: err.message });
		console.log("Error in followUnFollowUser: ", err.message);
	}
};

const updateUser = async (req, res) => {
	const { firstName, lastName,email,phone,country, state, city, address } = req.body;
	let { profilePic } = req.body;

	const userId = req.user._id;
	try {
		let user = await User.findById(userId);
		if (!user) return res.status(400).json({ error: "User not found" });

		if (req.params.id !== userId.toString())
			return res.status(400).json({ error: "You cannot update other user's profile" });

		if (password) {
			const salt = await bcrypt.genSalt(10);
			const hashedPassword = await bcrypt.hash(password, salt);
			user.password = hashedPassword;
		}

		if (profilePic) {
			if (user.profilePic) {
				await cloudinary.uploader.destroy(user.profilePic.split("/").pop().split(".")[0]);
			}

			const uploadedResponse = await cloudinary.uploader.upload(profilePic);
			profilePic = uploadedResponse.secure_url;
		}

		user.firstName = firstName || user.firstName;
		user.lastName = lastName || user.lastName;
		user.email = email || user.email;
		user.phone = phone || user.phone;
		user.country = country || user.country;
		user.state = state || user.state;
		user.city = city || user.city;
		user.address = address || user.address;
		user.profilePic = profilePic || user.profilePic;

		user = await user.save();

		// Find all posts that this user replied and update username and userProfilePic fields
		await Post.updateMany(
			{ "replies.userId": userId },
			{
				$set: {
					"replies.$[reply].username": user.username,
					"replies.$[reply].userProfilePic": user.profilePic,
				},
			},
			{ arrayFilters: [{ "reply.userId": userId }] }
		);

		// password should be null in response
		user.password = null;

		res.status(200).json(user);
	} catch (err) {
		res.status(500).json({ error: err.message });
		console.log("Error in updateUser: ", err.message);
	}
};

const getSuggestedUsers = async (req, res) => {
	try {
		// exclude the current user from suggested users array and exclude users that current user is already following
		const userId = req.user._id;

		const usersFollowedByYou = await User.findById(userId).select("following");

		const users = await User.aggregate([
			{
				$match: {
					_id: { $ne: userId },
				},
			},
			{
				$sample: { size: 10 },
			},
		]);
		const filteredUsers = users.filter((user) => !usersFollowedByYou.following.includes(user._id));
		const suggestedUsers = filteredUsers.slice(0, 4);

		suggestedUsers.forEach((user) => (user.password = null));

		res.status(200).json(suggestedUsers);
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

const freezeAccount = async (req, res) => {
	try {
		const user = await User.findById(req.user._id);
		if (!user) {
			return res.status(400).json({ error: "User not found" });
		}

		user.isFrozen = true;
		await user.save();

		res.status(200).json({ success: true });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

// Verify Email
const verifyEmail = async (req, res) => {
	try {
	  const { email, code } = req.body;
	  const user = await User.findOne({ email });
  
	  if (!user || user.isVerified) return res.status(400).json({ msg: "Invalid request" });
  
	  if (user.emailCode !== code || Date.now() > user.emailCodeExpires)
		return res.status(400).json({ msg: "Code expired or incorrect" });
  
	  user.isVerified = true;
	  user.emailCode = null;
	  user.emailCodeExpires = null;
	  await user.save();
  
	  res.json({ msg: "Email verified successfully" });
	} catch (err) {
	  res.status(500).json({ msg: err.message });
	}
};
const verifyPasswordResetCode = async (req, res) => {
	try {
	  const { email, code } = req.body;
	  const user = await User.findOne({ email });
  
	//   if (!user || user.isVerified) return res.status(400).json({ msg: "Invalid request" });
  
	  if (user.resetCode !== code || Date.now() > user.reseCodeExpires)
		return res.status(400).json({ msg: "Code expired or incorrect" });
  
	  user.isVerified = true;
	  user.resetCode = null;
	  user.resetCodeExpires = null;
	  await user.save();
  
	  res.json({ msg: "code verified successfully" });
	} catch (err) {
	  res.status(500).json({ msg: err.msg });
	}
  };
  
  // Resend Verification Code
  const resendCode = async (req, res) => {
	try {
	  const { email } = req.body;
	  const user = await User.findOne({ email });
  
	  if (!user || user.isVerified) return res.status(400).json({ msg: "User not found or already verified" });
  
	  const code = generateCode();
	  user.emailCode = code;
	  user.emailCodeExpires = Date.now() + 10 * 60 * 1000;
	  await user.save();
  
	  await sendEmail(email, "New verification code", `Your new code is: ${code}`);
	  res.json({ msg: "New verification code sent" });
	} catch (err) {
	  res.status(500).json({ msg: err.message });
	}
  };
  // Forgot Password

  
  // Reset Password


  // Forgot Password

  // Change Password (Requires token)
const changePassword = async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    if (newPassword !== confirmNewPassword) {
      return res.status(400).json({ msg: "New passwords do not match" });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ msg: "User not found" });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Current password is incorrect" });
    }

    // Check if same as current
    const isSame = await bcrypt.compare(newPassword, user.password);
    if (isSame) {
      return res.status(400).json({ msg: "New password cannot be the same as the old password" });
    }

    // Check password history
    for (let entry of user.passwordHistory || []) {
      const reused = await bcrypt.compare(newPassword, entry.password);
      if (reused) {
        return res.status(400).json({ msg: "You have already used this password before" });
      }
    }

    // Save old password in history
    const updatedHistory = user.passwordHistory || [];
    updatedHistory.push({ password: user.password, changedAt: new Date() });
    while (updatedHistory.length > 5) {
      updatedHistory.shift();
    }

    // Set new plain password — let pre("save") hash it
    user.password = newPassword;
    user.passwordHistory = updatedHistory;

    await user.save();

    res.json({ msg: "Password changed successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};



  
  const uploadFromUrl = async (req, res) => {
	const { fileUrl } = req.body;
	const userId = req.user?._id; // Get the authenticated user's ID
  
	if (!fileUrl) {
	  return res.status(400).json({ error: "File URL is required" });
	}
  
	// Ensure temp_uploads directory exists
	const tempDir = 'temp_uploads';
	if (!fs.existsSync(tempDir)) {
	  fs.mkdirSync(tempDir, { recursive: true });
	}
  
	const tempPath = path.join(tempDir, uuidv4());
	
	try {
	  // Download the file from URL
	  const response = await axios({
		url: fileUrl,
		method: "GET",
		responseType: "stream",
	  });
  
	  const writer = fs.createWriteStream(tempPath);
	  response.data.pipe(writer);
  
	  await new Promise((resolve, reject) => {
		writer.on('finish', resolve);
		writer.on('error', reject);
	  });
  
	  // Upload to Cloudinary
	  const cloudRes = await cloudinary.uploader.upload(tempPath, {
		resource_type: "auto",
		folder: "resumes", // Optional: organize files in Cloudinary
	  });
  
	  // Delete the temporary file
	  await fsp.unlink(tempPath);
  
	  // Update the user's resume field
	  const updatedUser = await User.findByIdAndUpdate(
		userId,
		{
		  resume: {
			originalUrl: fileUrl,
			cloudinaryUrl: cloudRes.secure_url,
			publicId: cloudRes.public_id, // Store public_id for future management
			fileType: cloudRes.resource_type,
			uploadedAt: new Date(),
		  },
		},
		{ new: true } // Return the updated document
	  );
  
	  res.status(200).json({ 
		message: "Resume uploaded successfully", 
		resume: updatedUser?.resume 
	  });
	} catch (err) {
	  console.error('Upload error:', err);
	  try {
		if (fs.existsSync(tempPath)) {
		  await fsp.unlink(tempPath);
		}
	  } catch (unlinkErr) {
		console.error('Error deleting temp file:', unlinkErr);
	  }
	  res.status(500).json({ 
		error: err.message || "Error processing file upload",
		details: err.response?.data || null
	  });
	}
  };


const uploadFromLocal = async (req, res) => {
	const userId = req.user?._id; // Get the authenticated user's ID
  
	if (!req.file) {
	  return res.status(400).json({ error: "No file uploaded" });
	}
  
	try {
	  // Upload to Cloudinary
	  const cloudRes = await cloudinary.uploader.upload(req.file.path, {
		resource_type: "auto",
		folder: "resumes", // Optional: organize files in Cloudinary
	  });
  
	  // Delete the temporary file
	  if (req.file.path) {
		await fsp.unlink(req.file.path).catch(console.error);
	  }
  
	  // Update the user's resume field
	  const updatedUser = await User.findByIdAndUpdate(
		userId,
		{
		  resume: {
			cloudinaryUrl: cloudRes.secure_url,
			publicId: cloudRes.public_id, // Store public_id for future management
			fileType: cloudRes.resource_type,
			uploadedAt: new Date(),
		  },
		},
		{ new: true } // Return the updated document
	  );
  
	  res.status(200).json({ 
		message: "Resume uploaded successfully", 
		resume: updatedUser.resume 
	  });
	} catch ( err )
	{
		console.log(err);
		
	  console.error('Upload error:', err);
	  // Clean up temp file if it exists
	  if (req.file?.path) {
		await fsp.unlink(req.file.path).catch(console.error);
	  }
	  res.status(500).json({ 
		error: err.message || "Cloudinary upload failed" 
	  });
	}
  };

  // controllers/authController.js
const googleAuthSuccess = async (req, res, next) => {
    try {
      const token = getSignedJwtToken(req.user._id);
      
      // Redirect or send token based on your frontend needs
      res.redirect(`${process.env.FRONTEND_URL}/auth/success?token=${token}`);
      
      // Or send JSON response
      // res.status(200).json({
      //   success: true,
      //   token
      // });
    } catch (err) {
      next(err);
    }
};

const forgotPassword = async (req, res) => {
	try {
	  const { email } = req.body;
	  const user = await User.findOne({ email });
  
		if ( !user )
		{
			return res.status(400).json({ msg: "Email not found" });
	  }
  
		const code = user.setPasswordResetCode();
		await user.save({validateBeforeSave: false})
	  await sendEmail(email, "Password Reset Code", `Your reset code is: ${code}`);
	  res.json({ msg: "Password reset code sent" });
	} catch (err) {
	  res.status(500).json({ msg: err.message });
	}
  };
  

  const verifyResetCode = async (req, res) => {
	try {
	  const { email, code} = req.body;
	  const user = await User.findOne({ email });
  
	  if (!user || !user.validateResetCode(code)) {
		return res.status(400).json({ message: "Invalid/expired OTP" });
	  }
  
	  // Generate short-lived JWT (15 mins expiry)
	  const token = jwt.sign(
		{ userId: user._id, purpose: "password_reset" },
		process.env.JWT_SECRET,
		{ expiresIn: "15m" }
	  );
  
	  res.json({ success: true, token, message: "OTP verified" });
	} catch (error) {
	  res.status(500).json({ message: "Server error" });
	}
  };
// Step 3 – change the password with the JWT
const resetPassword = async (req, res) => {
	try {
	  const { token, newPassword, confirmPassword } = req.body;
  
	  if (newPassword !== confirmPassword) {
		return res.status(400).json({ message: "Passwords do not match" });
	  }
  
	  // Verify JWT
	  const decoded = jwt.verify(token, process.env.JWT_SECRET);
	  if (decoded.purpose !== "password_reset") {
		return res.status(400).json({ message: "Invalid token" });
	  }
  
	  const user = await User.findById(decoded.userId);
	  if (!user) {
		return res.status(404).json({ message: "User not found" });
	  }
  
	  // Update password & clear OTP
	  user.password = newPassword;
	  user.otp = undefined;
	  user.otpExpires = undefined;
	  await user.save();
  
	  res.json({ success: true, message: "Password updated" });
	} catch (error) {
	  if (error.name === "TokenExpiredError") {
		return res.status(400).json({ message: "Token expired" });
	  }
	  res.status(500).json({ message: "Server error" });
	}
};
  

   
export {
	register,
	login,
	logoutUser,
	followUnFollowUser,
	updateUser,
	getUserProfile,
	getSuggestedUsers,
	freezeAccount,
	verifyEmail,
	resendCode,
	verifyResetCode,
	forgotPassword,
	resetPassword,
	changePassword,
	uploadFromUrl,
	uploadFromLocal,
	googleAuthSuccess
	
};
