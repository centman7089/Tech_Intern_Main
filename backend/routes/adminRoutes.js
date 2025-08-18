// @ts-nocheck
import express from "express";
import { changePassword, createAdmin, forgotPassword, getAdminUser, getUserProfile, login, logoutUser, resendCode, resetPassword, updateUser, verifyCac, verifyEmail, verifyResetCode, rejectCac } from "../controllers/adminController.js";
import { authorizeRoles, protectAdmin } from "../middlewares/adminAuth.js";


const adminRoute = express.Router()

adminRoute.post('/login', login)
adminRoute.post('/create', createAdmin)
adminRoute.post('/logout', logoutUser)
adminRoute.post('/resend-code', resendCode)
adminRoute.post('/change-password',protectAdmin, changePassword)
adminRoute.post('/verify-email', verifyEmail)
adminRoute.post('/forgot-password', forgotPassword)
adminRoute.post( '/verify-reset-code', verifyResetCode )
adminRoute.post( '/reset-password', resetPassword )

adminRoute.get( '/get', protectAdmin,getUserProfile )
adminRoute.get( '/admin-user', protectAdmin,getAdminUser )

adminRoute.patch( "/update/:id", protectAdmin,updateUser );

adminRoute.patch('/verify-cac/:employerId',protectAdmin, authorizeRoles('superadmin'),verifyCac );
// adminRoute.put('/verify-cac/:employerId',protectAdmin, authorizeRoles('admin','superadmin'),verifyCac );
// Reject CAC
adminRoute.patch("/reject-cac/:employerId",protectAdmin, authorizeRoles('superadmin'), rejectCac);



export default adminRoute