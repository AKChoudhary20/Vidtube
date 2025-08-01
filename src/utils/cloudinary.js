import {v2 as cloudinary} from "cloudinary"
import fs from "fs"
import dotenv from "dotenv"


dotenv.config()

// configuring the cloudinary
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const uploadOnCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) return null
        //upload the file on cloudinary
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })

        // file has been uploaded successfull
        //console.log("file is uploaded on cloudinary ", response.url);

        // ONCE THE FILE IS UPLOADED WE WOULD LIKE TO DELTE IT FROM OUR SERVER
        fs.unlinkSync(localFilePath)
        return response;

    } catch (error) {
        console.log("Error in uploading file on cloudinary ", error);
        fs.unlinkSync(localFilePath) // remove the locally saved temporary file as the upload operation got failed
        return null;
    }
}



const deleteFromCloudinary = async (publicId) => {
    try {
        const result=await cloudinary.uploader.destroy(publicId)
        console.log("Deleted file from cloudinary.PublicId: ",publicId)
        
    } catch (error) {
        console.log("Error in deleting file from cloudinary ", error);
        return null
        
    }
}
export {uploadOnCloudinary,deleteFromCloudinary}