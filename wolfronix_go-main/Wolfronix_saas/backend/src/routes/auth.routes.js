import express from "express";
import { register, login, googleCallback, verifyMfa } from "../controllers/auth.controller.js";
import passport from "../config/passport.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/verify-mfa", verifyMfa);

// Google OAuth routes
router.get("/google",
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get("/google/callback",
    passport.authenticate('google', {
        failureRedirect: 'http://localhost:5500/frontend/login.html?error=auth_failed',
        session: false
    }),
    googleCallback
);

export default router;
