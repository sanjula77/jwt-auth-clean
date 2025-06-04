import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    minLength: 5,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    trim: true,
    select: false,
  },
  verified: {
    type: Boolean,
    default: false,
  },
  verificatonCode: {
    type: String,
    select: false, 
  },
  verificatonCodeValidation: {
    type: String,
    select: false, 
  },
  forgotPasswordCode: {
    type: String,
    select: false, 
  },
  forgotPasswordCodeValidation: {
    type: String,
    select: false, 
    },
},{
  timestamps: true,
});

const User = mongoose.model("User", userSchema);

export default User;
