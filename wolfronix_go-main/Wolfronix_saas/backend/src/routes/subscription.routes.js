import express from "express";
import { getMySubscription, getBillingHistory } from "../controllers/subscription.controller.js";
import auth from "../middleware/auth.middleware.js";

const router = express.Router();

router.get("/me", auth, getMySubscription);
router.get("/invoices", auth, getBillingHistory);

export default router;
