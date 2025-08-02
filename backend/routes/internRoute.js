// @ts-nocheck
import express from "express";
import { addEducation, addExperience, getAllInterns, getInternsByCourse, getInternsGroupedByCourse, getProfile, getUserProfile, updateInternProfilePhoto, updateProfile } from "../controllers/InternProfile.js";
import protectRoute from "../middlewares/protectRoute.js";
import { resumeUpload, uploadPhoto } from "../middlewares/upload.js";

// import multer from "multer";


const internRouter = express.Router()

internRouter.get( '/me', protectRoute, getProfile )
internRouter.get('/get-all-interns', getAllInterns)
internRouter.post( '/experience', protectRoute, addExperience)
internRouter.post( '/education', protectRoute,addEducation )

internRouter.get( "/grouped-by-course", protectRoute, getInternsGroupedByCourse );
internRouter.get( '/by-course/:courseId',protectRoute, getInternsByCourse );
internRouter.get( "/:id",protectRoute, getUserProfile );
internRouter.patch( "/photo/:id",protectRoute,uploadPhoto.single('photo'),updateInternProfilePhoto );
internRouter.patch( '/update/:id', protectRoute, updateProfile );

export default internRouter