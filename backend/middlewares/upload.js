// @ts-nocheck
import multer from 'multer';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import cloudinaryModule from 'cloudinary';
import path from 'path';

const cloudinary = cloudinaryModule.v2;
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Supported file types
const allowedResumeTypes = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'image/jpeg',
  'image/png'
];

const allowedImageTypes = [
  'image/jpeg',
  'image/png',
  'image/webp'
];

// Resume Storage Configuration
// Helper function to sanitize filenames
const sanitizeFilename = (filename) => {
  return filename
    .replace(/\.[^/.]+$/, "") // Remove extension
    .replace(/[^\w-]/g, '_')  // Replace special chars with underscore
    .trim()                   // Remove leading/trailing spaces
    .replace(/\s+/g, '_')     // Replace internal spaces with underscore
    .substring(0, 100);       // Limit length
};

// Resume Storage Configuration
const resumeStorage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    const cleanName = sanitizeFilename(file.originalname);
    const timestamp = Date.now();
    
    return {
      folder: 'jobseekers-resumes',
      public_id: `${timestamp}-${cleanName}`,
      resource_type: 'auto',
      allowed_formats: ['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'],
      transformation: [{ quality: 'auto:best' }]
    };
  }
});

// Photo Storage Configuration
const photoStorage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    if (!allowedImageTypes.includes(file.mimetype)) {
      throw new Error('Invalid image type. Only JPEG, PNG, or WebP allowed');
    }

    return {
      folder: 'intern-uploads/profile-photos',
      public_id: `${req.user.id}-${Date.now()}`,
      resource_type: 'image',
      allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
      format: async () => path.extname(file.originalname).substring(1),
      transformation: [
        { width: 500, height: 500, crop: 'limit' },
        { quality: 'auto:best' }
      ]
    };
  }
});

// Configure Multer for both upload types
const resumeUpload = multer({
  storage: resumeStorage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (allowedResumeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

const photoUpload = multer({
  storage: photoStorage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (allowedImageTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid image type'), false);
    }
  }
} );


// ✅ Define file filter for images only
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) cb(null, true);
  else cb(new Error('Only image files are allowed!'), false);
};

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'intern_profile',
    allowed_formats: ['jpg', 'jpeg', 'png'],
    transformation: [{ width: 400, height: 400, crop: 'fill', gravity: 'face' }],
  },
});

const uploadPhoto = multer( { storage, fileFilter } );

const allowedCacTypes = [
  'application/pdf',
  'image/jpeg',
  'image/png'
];

const cacStorage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    return {
      folder: 'employer-cac-documents',
      public_id: `${req.params.employerId}-${Date.now()}`, // ✅ FIXED HERE
      resource_type: 'auto',
      allowed_formats: ['pdf', 'jpg', 'jpeg', 'png'],
      transformation: [{ quality: 'auto:best' }]
    };
  }
});

const cacUpload = multer({
  storage: cacStorage,
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (allowedCacTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Invalid file type. Only PDF or image allowed."), false);
    }
  }
});


export { resumeUpload, photoUpload, uploadPhoto, cacUpload };