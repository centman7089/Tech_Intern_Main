// @ts-nocheck
import path from "path";
import express from "express";
import cors from "cors"
import dotenv from "dotenv";
import connectDB from "./db/connectDB.js";
import cookieParser from "cookie-parser";
import userRoutes from "./routes/userRoutes.js";
import postRoutes from "./routes/postRoutes.js";
import messageRoutes from "./routes/messageRoutes.js";
import cloudinaryModule from 'cloudinary';
import { app, server } from "./socket/socket.js";
import job from "./cron/cron.js";
import swaggerUi from "swagger-ui-express"
import swaggerDocument from "./swagger-output.json" with { type: 'json' }
import bodyParser from "body-parser"
import MongoStore from 'connect-mongo';
import passport from "passport";
import session from "express-session"
import authRouter from "./routes/authRoutes.js";
import courseRoute from "./routes/courseRoute.js";
import internProfileRouter from "./routes/internProfileRoute.js";
import EmployerRouter from "./routes/employerRoutes.js";
import uploadRouter from "./routes/upload.js";
import adminRoute from "./routes/adminRoutes.js";
import "./db/passport.js";
import jobRouter from "./routes/jobRoutes.js";
import internRouter from "./routes/internRoute.js";
import onboardRouter from "./routes/onboardRoutes.js";
import errorHandler from "./middlewares/errorHandler.js";


dotenv.config();

connectDB();
job.start();

const PORT = process.env.PORT || 3000;
const __dirname = path.resolve();

const cloudinary = cloudinaryModule.v2;
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Middlewares
app.use(express.json()); // To parse JSON data in the req.body
app.use(express.urlencoded({ extended: true })); // To parse form data in the req.body
app.use( cookieParser() );

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Allow both local dev and deployed frontend
const allowedOrigins = [
	"http://localhost:3000", // React dev server
	"https://page-tech.onrender.com", // your deployed frontend (optional)
	"https://page-tech.onrender.com/", // Swagger UI or others
  ];
  
//   app.use(cors({
// 	origin: (origin, callback) => {
// 	  if (!origin || allowedOrigins.includes(origin)) {
// 		callback(null, true);
// 	  } else {
// 		callback(new Error("CORS Not Allowed"));
// 	  }
// 	},
// 	credentials: true,
//   }));

app.use(cors())



app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: false,
	saveUninitialized: false,
	store: MongoStore.create({
	  mongoUrl: process.env.MONGO_URI,
	  ttl: 14 * 24 * 60 * 60 // = 14 days
	})
  }));
app.use( passport.initialize() );
app.use(passport.session())


// Serve static files
app.use( '/uploads', express.static( path.join( __dirname, 'uploads' ) ) );

// Routes
app.use("/api/auth/users", userRoutes);
app.use("/api/admin", adminRoute);
app.use("/api/posts", postRoutes);
app.use( "/api/messages", messageRoutes );
app.use( "/api/auth", authRouter );
app.use( "/api/employer", EmployerRouter);
app.use("/api/course", courseRoute)
app.use( "/api/intern/profile", internProfileRouter )


app.use('/api/onboarding', onboardRouter);
app.use('/api/profile', internRouter);
app.use('/api/jobs',jobRouter);
// Routes
app.use('/api', uploadRouter);


app.get( '/', ( req, res ) =>
{
	res.send("hello")
} )

app.use( '/uploads', express.static( path.join( __dirname, 'uploads' ) ) );
app.use( "/api-docs", swaggerUi.serve, swaggerUi.setup( swaggerDocument ) );

// Error handling (must be last middleware)
app.use(errorHandler);

http://localhost:5000 => backend,frontend

if (process.env.NODE_ENV === "production") {
	app.use(express.static(path.join(__dirname, "/frontend/dist")));

	// react app
	app.get("*", (req, res) => {
		res.sendFile(path.resolve(__dirname, "frontend", "dist", "index.html"));
	});
}

server.listen(PORT, () => console.log(`Server started at http://localhost:${PORT}`));
