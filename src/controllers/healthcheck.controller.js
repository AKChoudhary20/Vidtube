import { Apiresponse } from "../utils/Apiresponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const healthcheck = asyncHandler(async (req, res) => {
    return res
        .status(200)
        .json(new Apiresponse(200, "ok", "Health check passed"))
})
export{healthcheck}