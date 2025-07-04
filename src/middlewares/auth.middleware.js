import jwt from "jsonwebtoken";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";



export const verifyJWT = asyncHandler(async (req, _, next) => {
    const token = req.cookies?.accessToken || req.headers?.authorization?.replace("Bearer ", "")

    if (!token) {
        throw new ApiError(401, "Please login to access this resource");
    }
    try {
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")

        if (!user) {
            throw new ApiError(401, "User not found");
        }
        req.user = user

        next()//trasnfer control to the next middleware or controller

    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid accesss token");
    }

})  