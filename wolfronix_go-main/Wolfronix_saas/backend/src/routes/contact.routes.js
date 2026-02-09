import express from 'express';
import { sendContactMessage } from '../controllers/contact.controller.js';

const router = express.Router();

// Route to handle contact form submissions
router.post('/contact', sendContactMessage);

export default router;