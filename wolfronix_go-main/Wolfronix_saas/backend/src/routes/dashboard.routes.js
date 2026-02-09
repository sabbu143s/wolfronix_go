import express from "express";
import { getMyDashboardMetrics, forceRefreshMetrics } from "../controllers/dashboard.controller.js";
import auth from "../middleware/auth.middleware.js";

const router = express.Router();

router.get("/metrics", auth, getMyDashboardMetrics);
router.post("/refresh", auth, forceRefreshMetrics);

export default router;
