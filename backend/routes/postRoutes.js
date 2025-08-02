import express from "express";
import {
	createPost,
	deletePost,
	getPost,
	likeUnlikePost,
	replyToPost,
	getFeedPosts,
	getUserPosts
} from "../controllers/postController.js";
import protectRoute from "../middlewares/protectRoute.js";
 import { uploadSingleImage } from "../middlewares/imgUpload.js";

const router = express.Router();

router.get("/feed/:userId",protectRoute, getFeedPosts);
router.post( "/create", protectRoute,uploadSingleImage, createPost );
router.get( "/user/:id", getUserPosts );
router.put("/like/:id", protectRoute, likeUnlikePost);
router.put("/reply/:id", protectRoute, replyToPost);
router.get("/:id",protectRoute, getPost);
router.delete( "/:id", protectRoute, deletePost );
// router.put("/posts/:id", protectRoute, updatePost);


export default router;
