import mongoose from "mongoose";

const hireRequestSchema = new mongoose.Schema(
  {
    employerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Employer",
      required: true,
    },
    interns: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "InternProfile",
      },
    ],
    selectedCourse: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Course",   // ✅ populate from Course model
      required: true,
    },
    workType: {
      type: String,
      enum: ["remote", "onsite", "hybrid"],
      required: true,
    },
    location: {
      type: String,
      required: true,
    },
    duration: {
      type: String,
      required: true,
    },
    paymentAmount: {
      type: Number,
      required: true,
    },
    additionalInfo: {
      type: String,
    },
  },
  { timestamps: true }
);

export default mongoose.model("HireRequest", hireRequestSchema);
