// @ts-nocheck
import mongoose from "mongoose";

const HireRequestSchema = new mongoose.Schema(
  {
    employerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Employer",
      required: true,
    },
    // store ObjectId of Course; we will return the name from controller
    selectedCourse: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Course",
      required: true,
    },
    workType: {
      type: String, // keep flexible to avoid enum issues
      trim: true,
      required: true,
      lowercase: true,
    },
    location: { type: String, trim: true },
    duration: { type: String, trim: true },
    paymentType: { type: String, trim: true }, // optional, no enum to avoid “Monthly” errors
    paymentAmount: { type: Number },
    additionalInfo: { type: String, trim: true },
    interns: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "InternProfile",
      },
    ],
  },
  { timestamps: true }
);

export default mongoose.model("HireRequest", HireRequestSchema);
