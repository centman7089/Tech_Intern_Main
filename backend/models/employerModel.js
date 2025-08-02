// @ts-nocheck
// Employer.js

import mongoose from "mongoose";
// import crypto from "crypto"
import bcrypt from "bcryptjs"

const EmployerSchema = new mongoose.Schema( {
	companyName: String,
	email: String,
	password: String,
	phone: String,
	location: String,
	logo: {
		type: String,
		default: ""
	},         // uploaded logo
	description: {
		type: String,
		default: ""
	},
	cacDocument: {
		url: { type: String, default: "" },
		public_id: { type: String, default: "" },
		description: { type: String, default: "" },
		isAproved: { type: Boolean, default: false },
		   isRejected: {
        type: Boolean,
        default: false,
      },
      rejectionReason: {
        type: String,
      },
      uploadedAt: {
        type: Date,
        default: Date.now,
      },
	},
	cacDescription: { type: String, default: "" },
	cacVerified: { type: Boolean, default: false },
	cacStatus: {
		type: String,
		enum: [ "pending", "approved", "rejected" ],
		default: "pending"
	},
		requiresCacVerification: {
		type: Boolean,
		default: false,
	},
	carRejectionReason: {
		type: Boolean,
		default: false,
	},

	createdAt: { type: Date, default: Date.now },

	lastLogin: {
		type: Date,
		default: Date.now,
	},
	isVerified: {
		type: Boolean,
		default: false,
	},

	emailCode: String,
	emailCodeExpires: Date,
	resetCode: String,
	resetCodeExpires: Date,
	passwordHistory: [
		{
			password: String,
			changedAt: Date
		}
	]
} );




// EmployerSchema.methods.setPasswordResetCode = function ()
// {
// 	const code = Math.floor( 1000 + Math.random() * 9000 ).toString();
// 	this.resetCode = crypto.createHash( "sha256" ).update( code ).digest( "hex" )
// 	this.resetCodeExpires = Date.now() + 10 * 60 * 1000; // 10minute
// 	return code; // we will email this
// };

// EmployerSchema.methods.validateResetCode = function ( code )
// {
// 	const hash = crypto.createHash( "sha256" ).update( code ).digest( "hex" );
// 	return (
// 		hash === this.resetCode && this.resetCodeExpires && this.resetCodeExpires > Date.now()
// 	);
// }

// Hash password before saving
EmployerSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
EmployerSchema.methods.correctPassword = async function (inputPassword) {
  return await bcrypt.compare(inputPassword, this.password);
};

const Employer = mongoose.model( "Employer", EmployerSchema )

export default Employer

