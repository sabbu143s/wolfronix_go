import prisma from "../lib/prisma.js";
import { verifyPhoneToken } from "../utils/phoneEmail.js";

export async function getMe(req, res) {
    try {
        console.log("getMe called for userId:", req.userId);
        const userId = req.userId;

        const user = await prisma.user.findUnique({
            where: { id: userId }
        });

        if (!user) {
            console.error("getMe: User not found for id:", userId);
            return res.status(404).json({ message: "User not found" });
        }

        // Exclude passwordHash
        const { passwordHash, ...userWithoutPassword } = user;

        res.status(200).json(userWithoutPassword);
    } catch (error) {
        console.error("Get me error:", error);
        res.status(500).json({ message: "Server error" });
    }
}

export const updateMe = async (req, res) => {
    // ... (lines 26-72) ...
    try {
        const userId = req.userId;
        const { firstName, lastName, company, email, phoneNumber } = req.body;

        // Check for conflicts if email or phone is being updated
        if (email || phoneNumber) {
            const existingUser = await prisma.user.findFirst({
                where: {
                    AND: [
                        { NOT: { id: userId } },
                        {
                            OR: [
                                email ? { email } : {},
                                phoneNumber ? { phoneNumber } : {}
                            ]
                        }
                    ]
                }
            });

            if (existingUser) {
                return res.status(409).json({ message: "Email or Phone number is already in use by another account." });
            }
        }

        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: {
                firstName,
                lastName,
                company,
                ...(email && { email }),
                ...(phoneNumber && { phoneNumber })
            }
        });

        const { passwordHash, ...userWithoutPassword } = updatedUser;

        res.json(userWithoutPassword);
    } catch (err) {
        console.error("Update me error:", err);
        // Check for unique constraint violation (Prisma error code P2002) just in case
        if (err.code === 'P2002') {
            return res.status(409).json({ message: "Email or Phone number is already in use." });
        }
        res.status(500).json({ message: "Failed to update profile" });
    }
};

export async function enableMfa(req, res) {
    try {
        const userId = req.userId;

        // 1. Get user
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) return res.status(404).json({ message: "User not found" });

        // 2. Ensure phone number exists
        if (!user.phoneNumber) {
            return res.status(400).json({ message: "Please update your profile with a valid phone number first." });
        }

        // 3. Enable MFA
        await prisma.user.update({
            where: { id: userId },
            data: { isMfaEnabled: true }
        });

        res.json({ message: "MFA enabled successfully" });

    } catch (error) {
        console.error("Enable MFA error:", error);
        res.status(500).json({ message: "Failed to enable MFA" });
    }
}

export async function disableMfa(req, res) {
    try {
        const userId = req.userId;

        await prisma.user.update({
            where: { id: userId },
            data: { isMfaEnabled: false }
        });

        res.json({ message: "MFA disabled" });
    } catch (error) {
        console.error("Disable MFA error:", error);
        res.status(500).json({ message: "Failed to disable MFA" });
    }
}
