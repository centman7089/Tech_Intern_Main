// @ts-nocheck
import express from "express";

import protectEmployer from "../middlewares/protectEmployer.js";
import auth from "../middlewares/authMiddleware.js";
import { resumeUpload, photoUpload, cacUpload } from "../middlewares/upload.js";
import { logoutUser,updateUser,register,verifyEmail,login,forgotPassword,resetPassword,changePassword,resendCode, getEmployerProfile, uploadCacDocument, verifyResetCode } from "../controllers/employerController.js";

const EmployerRouter = express.Router();


EmployerRouter.post("/logout", logoutUser);

EmployerRouter.post("/register", register);
EmployerRouter.post("/verify", verifyEmail);
EmployerRouter.post("/resend-code", resendCode);
EmployerRouter.post( "/login", login );
EmployerRouter.post("/verify-reset-code", verifyResetCode);
EmployerRouter.post("/forgot-password",protectEmployer, forgotPassword);
EmployerRouter.post("/reset-password", protectEmployer, resetPassword);
EmployerRouter.post( "/change-password", protectEmployer, changePassword );
EmployerRouter.put( "/update/:id", protectEmployer, updateUser );
EmployerRouter.get( "/profile/:query", getEmployerProfile );
EmployerRouter.post(
  "/upload-cac/:employerId",
  protectEmployer,
  cacUpload.single("file"),
  uploadCacDocument
);







export default EmployerRouter;
