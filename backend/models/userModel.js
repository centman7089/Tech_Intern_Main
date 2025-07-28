// @ts-nocheck
import mongoose from "mongoose";
import crypto from "crypto"
import bcrypt from "bcryptjs"

const userSchema = mongoose.Schema(
	{
		firstName: {
			type: String,
			required: true,
		},
		lastName:
		 {
			type: String,
			required: true,
			
		},
		email: {
			type: String,
			required: true,
			
		},
		password: {
			type: String,
			minLength: 6,
			required: true,
		},
		phone: {
			type: String,
			minLength: 6,
			required: true,
		},
		country: {
			type: String,
			required: true,
			
		},
		state: {
			type: String,
			required: true,
		
		},
		city: {
			type: String,
			required: true,
		},
		  address: {
			type: String,
			required: true,
		},  
		profilePic: {
			type: String,
			default: "https://res.cloudinary.com/dq5puvtne/image/upload/v1740648447/next_crib_avatar_jled2z.jpg"
		  },
		  followers: [{
			type: mongoose.Schema.Types.ObjectId,
			ref: "User"
		  }],
		  following: [{
			type: mongoose.Schema.Types.ObjectId,
			ref: "User"
		  }],
		isFrozen: {
			type: Boolean,
			default: false,
		},
		name: String,
		avatar: String,
		googleId: String,
		facebookId: String,
		githubId: String,
		originalUrl: String,
		cloudinaryUrl: String,
		fileType: String,
		uploadedAt: {
		  type: Date,
		  default: Date.now,
		},
		provider: {
		  type: String,
		  enum: ['local', 'google'],
		  default: 'local',
		},
		// course: [String],
		// skills: [ String ],
		// resume: {
		// 	originalUrl: String,
		// 	cloudinaryUrl: String,
		// 	publicId: String,
		// 	fileType: String,
		// 	uploadedAt: Date
		//   },
		 resumes: [ { type: mongoose.Schema.Types.ObjectId, ref: 'ResumeSchema' } ], // Array of resume references
		 filePath: String,
		 lastLogin: {
			type: Date,
			default: Date.now,
		 },
		  profile: {
			type: mongoose.Schema.Types.ObjectId,
			ref: 'InternProfile'
		  },
		  isVerified: {
			type: Boolean,
			default: false,
		  },
		  emailCode: String,
		  emailCodeExpires: Date,
		  resetCode: String,
		  resetCodeExpires: Date,
		  vverificationToken: String,
		  onboardingCompleted: {
			type: Boolean,
			default: false
		  },
		  passwordHistory: [
			{
			  password: String,
			  changedAt: Date
			}
		],
		createdAt: {
			type: Date,
			default: Date.now
		  }
		  
	},
	
	{
		timestamps: true,
	}
);

userSchema.pre( "save", async function ( next )
{
	if (!this.isModified("password")) {
		return next();
	}
	this.password = await bcrypt.hash( this.password, 12 );
	next();
} )

userSchema.methods.correctPassword = async function ( candPwd )
{
	return bcrypt.compare(candPwd, this.password)
}


userSchema.methods.setPasswordResetCode = function ()
{
	const code = Math.floor( 1000 + Math.random() * 9000 ).toString();
	this.resetCode = crypto.createHash( "sha256" ).update( code ).digest( "hex" )
	this.resetCodeExpires = Date.now() + 10 * 60 * 1000; // 10minute
	return code; // we will email this
};

userSchema.methods.validateResetCode = function ( code )
{
	const hash = crypto.createHash( "sha256" ).update( code ).digest( "hex" );
	return (
		hash === this.resetCode && this.resetCodeExpires && this.resetCodeExpires > Date.now()
	);
}

const User = mongoose.model("User", userSchema);

export default User;
