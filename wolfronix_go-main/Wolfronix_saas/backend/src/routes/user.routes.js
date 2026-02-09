import express from "express";
import { getMe, updateMe, enableMfa, disableMfa } from "../controllers/user.controller.js";
import auth from "../middleware/auth.middleware.js";

const router = express.Router();

router.get("/me", auth, getMe);
router.put("/me", auth, updateMe);
router.post("/mfa/enable", auth, enableMfa);
router.post("/mfa/disable", auth, disableMfa);

export default router;
