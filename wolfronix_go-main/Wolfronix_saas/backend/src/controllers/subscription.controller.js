import prisma from "../lib/prisma.js";

export const getMySubscription = async (req, res) => {
    try {
        const userId = req.userId;

        // Fetch subscription with relations
        let subscription = await prisma.subscription.findUnique({
            where: { userId },
            include: { usage: true }
        });

        // Auto-heal: Create default FREE subscription if none exists
        if (!subscription) {
            const nextYear = new Date();
            nextYear.setFullYear(nextYear.getFullYear() + 1);

            subscription = await prisma.subscription.create({
                data: {
                    userId,
                    plan: "FREE",
                    status: "ACTIVE",
                    startDate: new Date(),
                    nextBillingDate: nextYear,
                    autoRenew: false,
                    usage: {
                        create: {
                            apiCallsUsed: 0,
                            apiCallsLimit: 1000,
                            seatsUsed: 1,
                            seatsLimit: 1
                        }
                    }
                },
                include: { usage: true }
            });
        }

        // Fetch active payment method
        let paymentMethod = await prisma.paymentMethod.findFirst({
            where: { userId, isDefault: true }
        });

        res.json({
            subscription,
            paymentMethod: paymentMethod || null
        });

    } catch (error) {
        console.error("Get subscription error:", error);
        res.status(500).json({ message: "Server error" });
    }
};

export const getBillingHistory = async (req, res) => {
    try {
        const userId = req.userId;

        let invoices = await prisma.invoice.findMany({
            where: { userId },
            orderBy: { date: 'desc' }
        });

        res.json(invoices);

    } catch (error) {
        console.error("Get billing history error:", error);
        res.status(500).json({ message: "Server error" });
    }
};
