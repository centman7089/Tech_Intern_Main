import express from "express";
import {
   
} from "../controllers/userController.js";
import protectRoute from "../middlewares/protectRoute.js";
// import { addCourseSkills, getAllCourses, getSkillsByCourse } from "../controllers/courseController.js";
import {  getInternsByCourse } from "../controllers/courseController.js";


const courseRoute = express.Router();




// courseRoute.post( '/', addCourseSkills )
// courseRoute.get( '/courses', getAllCourses );
// courseRoute.get( '/:course', getSkillsByCourse )
// routes/categoryRoutes.js or courseRoutes.js
// to get course ID
courseRoute.get("/by-course/:courseId", getInternsByCourse);



export default courseRoute;
