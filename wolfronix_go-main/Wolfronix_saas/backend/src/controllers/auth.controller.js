import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../lib/prisma.js";
import { verifyPhoneToken } from "../utils/phoneEmail.js";

export async function register(req, res) {
    try {
        const { firstName, lastName, email, phoneNumber, password, company } = req.body;

        if (!firstName || !lastName || !email || !phoneNumber || !password) {
            return res.status(400).json({ message: "All required fields must be provided" });
        }

        if (password.length < 8) {
            return res.status(400).json({ message: "Password must be at least 8 characters" });
        }

        const existingUser = await prisma.user.findFirst({
            where: {
                OR: [
                    { email },
                    { phoneNumber }
                ]
            }
        });

        if (existingUser) {
            const field = existingUser.email === email ? "Email" : "Phone number";
            return res.status(409).json({ message: `${field} already registered` });
        }



        const passwordHash = await bcrypt.hash(password, 10);

        // Transaction to create user and metrics
        const user = await prisma.$transaction(async (tx) => {
            const newUser = await tx.user.create({
                data: {
                    firstName,
                    lastName,
                    email,
                    phoneNumber,
                    passwordHash,
                    company: company || "",
                    role: "USER",
                    provider: "local"
                }
            });

            await tx.userMetrics.create({
                data: {
                    userId: newUser.id
                }
            });

            return newUser;
        });

        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.status(201).json({
            message: "User registered successfully",
            token
        });
    } catch (error) {
        console.error("Register error:", error);
    }
}

export async function login(req, res) {
    try {
        const { email, phoneNumber, password, method } = req.body;

        let user;
        if (method === "phone") {
            if (!phoneNumber || !password) return res.status(400).json({ message: "Phone number and password are required" });
            user = await prisma.user.findUnique({ where: { phoneNumber } });
            if (!user) return res.status(401).json({ message: "Phone number not registered" });
        } else {
            if (!email || !password) return res.status(400).json({ message: "Email and password are required" });
            user = await prisma.user.findUnique({ where: { email } });
            if (!user) return res.status(401).json({ message: "Invalid credentials" });
        }

        if (!user.passwordHash) {
            return res.status(401).json({ message: "This account uses social login. Please sign in with Google." });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

        // MFA Check
        if (user.isMfaEnabled) {
            const tempToken = jwt.sign(
                { id: user.id, role: "mfa_pending" },
                process.env.JWT_SECRET,
                { expiresIn: "5m" }
            );
            return res.status(200).json({
                message: "MFA required",
                mfaRequired: true,
                tempToken,
                phoneNumber: user.phoneNumber
            });
        }

        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        return res.status(200).json({ message: "Login successful", token });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Server error" });
    }
}

export async function verifyMfa(req, res) {
    try {
        const { tempToken, phoneToken } = req.body;

        if (!tempToken || !phoneToken) {
            return res.status(400).json({ message: "Token and verification code required" });
        }

        // Verify temp token
        const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
        if (decoded.role !== "mfa_pending") {
            return res.status(401).json({ message: "Invalid token type" });
        }

        // Verify phone token
        const verifiedNumber = await verifyPhoneToken(phoneToken);

        const user = await prisma.user.findUnique({ where: { id: decoded.id } });
        if (!user) return res.status(404).json({ message: "User not found" });

        // Normalize numbers for comparison
        if (user.phoneNumber !== verifiedNumber) {
            if (!verifiedNumber.includes(user.phoneNumber) && !user.phoneNumber.includes(verifiedNumber)) {
                return res.status(401).json({ message: "Phone number verification mismatch" });
            }
        }

        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        console.log("MFA verification successful for user:", user.id, ". Token generated.");
        res.json({ message: "MFA successful", token });

    } catch (error) {
        console.error("MFA Verify error:", error);
        res.status(401).json({ message: "Verification failed" });
    }
}

export async function googleCallback(req, res) {
    try {
        const user = req.user;

        if (!user) {
            return res.redirect('http://localhost:5500/frontend/login.html?error=auth_failed');
        }

        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        // Redirect to frontend with token
        res.redirect(`http://localhost:5500/frontend/auth-callback.html?token=${token}`);
    } catch (error) {
        console.error("Google callback error:", error);
        res.redirect('http://localhost:5500/frontend/login.html?error=server_error');
    }
}
