// @ts-nocheck
import fs from "fs/promises";
import Post from "../models/postModel.js";
import User from "../models/userModel.js";
import { v2 as cloudinary } from "cloudinary";
import mongoose from "mongoose";


const createPost = async (req, res) => {
	try {
	  const { text } = req.body;
	  const postedBy = req.user?._id;
  
	  if (!text) return res.status(400).json({ error: "Text field is required" });
	  if (!postedBy || !mongoose.Types.ObjectId.isValid(postedBy)) {
		return res.status(400).json({ error: "Invalid user ID" });
	  }
  
	  let imgUrl = "";
	  if (req.file) {
		try {
		  const uploadRes = await cloudinary.uploader.upload(req.file.path, {
			folder: "posts",
		  });
		  imgUrl = uploadRes.secure_url;
		  await fs.unlink(req.file.path);
		} catch (uploadErr) {
		  console.error("Image upload failed:", uploadErr);
		  return res.status(500).json({ error: "Image upload failed" });
		}
	  }
  
	  const newPost = await Post.create({ postedBy, text, img: imgUrl });
	  res.status(201).json(newPost);
	} catch (err) {
	  console.error(err);
	  res.status(500).json({ error: err.message });
	}
  };

const getPost = async (req, res) => {
	try {
		const post = await Post.findById(req.params.id);

		if (!post) {
			return res.status(404).json({ error: "Post not found" });
		}

		res.status(200).json(post);
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
};

const deletePost = async (req, res) => {
	try {
		const post = await Post.findById(req.params.id);
		if (!post) {
			return res.status(404).json({ error: "Post not found" });
		}

		if (post.postedBy.toString() !== req.user._id.toString()) {
			return res.status(401).json({ error: "Unauthorized to delete post" });
		}

		if (post.img) {
			const imgId = post.img.split("/").pop().split(".")[0];
			await cloudinary.uploader.destroy(imgId);
		}

		await Post.findByIdAndDelete(req.params.id);

		res.status(200).json({ message: "Post deleted successfully" });
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
};

const likeUnlikePost = async (req, res) => {
	try {
		const { id: postId } = req.params;
		const userId = req.user._id;

		const post = await Post.findById(postId);

		if (!post) {
			return res.status(404).json({ error: "Post not found" });
		}

		const userLikedPost = post.likes.includes(userId);

		if (userLikedPost) {
			// Unlike post
			await Post.updateOne({ _id: postId }, { $pull: { likes: userId } });
			res.status(200).json({ message: "Post unliked successfully" });
		} else {
			// Like post
			post.likes.push(userId);
			await post.save();
			res.status(200).json({ message: "Post liked successfully" });
		}
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
};

const replyToPost = async (req, res) => {
	try {
		const { text } = req.body;
		const postId = req.params.id;
		const userId = req.user._id;
		const userProfilePic = req.user.profilePic;
		const username = req.user.username;

		if (!text) {
			return res.status(400).json({ error: "Text field is required" });
		}

		const post = await Post.findById(postId);
		if (!post) {
			return res.status(404).json({ error: "Post not found" });
		}

		const reply = { userId, text, userProfilePic, username };

		post.replies.push(reply);
		await post.save();

		res.status(200).json(reply);
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
};

const getFeedPosts = async (req, res) => {
  try {
    const userId = req.params.userId; // Get the userId from route param

    const user = await User.findById(userId).select("following");
    if (!user) return res.status(404).json({ error: "User not found" });

    // Get users who follow the current user (i.e., followers)
    const followers = await User.find({ following: userId }).select("_id");

    const followerIds = followers.map((f) => f._id.toString());
    const followingIds = user.following.map((id) => id.toString());

    // Get users who are mutuals
    const mutualFollowIds = followingIds.filter((id) => followerIds.includes(id));

    // Include current user
    const visiblePosterIds = [...mutualFollowIds, userId];

    // Fetch posts from mutuals and self
    const feedPosts = await Post.find({ postedBy: { $in: visiblePosterIds } })
      .sort({ createdAt: -1 })
      .populate("postedBy", "name avatar");

    res.status(200).json(feedPosts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


const getUserPosts = async (req, res) => {
	const { username } = req.params;
	try {
		const user = await User.findOne({ username });
		if (!user) {
			return res.status(404).json({ error: "User not found" });
		}

		const posts = await Post.find({ postedBy: user._id }).sort({ createdAt: -1 });

		res.status(200).json(posts);
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

export { createPost, getPost, deletePost, likeUnlikePost, replyToPost, getFeedPosts, getUserPosts };

