// @ts-nocheck
import mongoose from "mongoose";
import crypto from "crypto"
import bcrypt from "bcryptjs"


const adminSchema = new  mongoose.Schema( {
    firstName: {
        type: String,
        required: true,
    },
    lastName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    phone: {
        type: String,
        required: true,
    },
    country: {
        type: String,
        required: true,
    },
    role
        : {
        type: String,
        enum: ['admin', 'superadmin', 'moderator'],
        default: 'admin',
    },
    isVerified: {
        type: Boolean,
        default: false,
      },
    emailCode: String,
    emailCodeExpires: Date,
    resetCode: String,
    resetCodeExpires: Date,
    verificationToken: String,
    passwordHistory: [
      {
        password: String,
        changedAt: Date
      }
    ]
}, { timestamps: true } )

// Hash password before saving
adminSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
adminSchema.methods.correctPassword = async function (inputPassword) {
  return await bcrypt.compare(inputPassword, this.password);
};

adminSchema.methods.setPasswordResetCode = function ()
{
	const code = Math.floor( 1000 + Math.random() * 9000 ).toString();
	this.resetCode = crypto.createHash( "sha256" ).update( code ).digest( "hex" )
	this.resetCodeExpires = Date.now() + 10 * 60 * 1000; // 10minute
	return code; // we will email this
};

adminSchema.methods.validateResetCode = function ( code )
{
	const hash = crypto.createHash( "sha256" ).update( code ).digest( "hex" );
	return (
		hash === this.resetCode && this.resetCodeExpires && this.resetCodeExpires > Date.now()
	);
}

const Admin = mongoose.model( "Admin", adminSchema)

export default Admin