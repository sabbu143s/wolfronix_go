import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import session from 'express-session';
import passport from './config/passport.js';
import authRoutes from './routes/auth.routes.js';
import userRoutes from './routes/user.routes.js';
import dashboardRoutes from './routes/dashboard.routes.js';
import contactRoutes from './routes/contact.routes.js';
import subscriptionRoutes from './routes/subscription.routes.js';
import wolfronixRoutes from './routes/wolfronix.routes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);

        // Allow any localhost or 127.0.0.1 origin
        if (origin.match(/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/)) {
            return callback(null, true);
        }

        callback(new Error('Not allowed by CORS'));
    },
    credentials: true
}));

// Session middleware for passport
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
    console.error('\u274c FATAL: SESSION_SECRET environment variable is required');
    process.exit(1);
}
if (!process.env.JWT_SECRET) {
    console.error('\u274c FATAL: JWT_SECRET environment variable is required');
    process.exit(1);
}

app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

// Health check endpoint
app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
});

app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api", contactRoutes);
app.use("/api/subscription", subscriptionRoutes);
app.use("/api/wolfronix", wolfronixRoutes);

// 404 handler for undefined routes
app.use((req, res) => {
    res.status(404).json({ message: "Route not found" });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error("Server error:", err);
    res.status(500).json({
        message: "Internal server error",
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

export default app;
