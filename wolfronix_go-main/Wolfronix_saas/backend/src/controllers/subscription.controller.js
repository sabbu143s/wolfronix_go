import prisma from "../lib/prisma.js";

export const getMySubscription = async (req, res) => {
    try {
        const userId = req.userId;

        // Fetch subscription with relations
        let subscription = await prisma.subscription.findUnique({
            where: { userId },
            include: { usage: true }
        });

        // Auto-heal: Create default subscription if none exists
        if (!subscription) {
            const nextYear = new Date();
            nextYear.setFullYear(nextYear.getFullYear() + 1);

            subscription = await prisma.subscription.create({
                data: {
                    userId,
                    plan: "PRO",
                    status: "ACTIVE",
                    startDate: new Date(),
                    nextBillingDate: nextYear,
                    autoRenew: true,
                    usage: {
                        create: {
                            apiCallsUsed: 75432,
                            apiCallsLimit: 100000,
                            seatsUsed: 8,
                            seatsLimit: 10
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

        if (!paymentMethod) {
            // Create Mock Payment Method if missing (Simulation for now)
            paymentMethod = await prisma.paymentMethod.create({
                data: {
                    userId,
                    cardBrand: "Visa",
                    last4: "1234",
                    holder: "RAHUL VARMA",
                    expiry: "12/28",
                    isDefault: true
                }
            });
        }

        res.json({
            subscription,
            paymentMethod
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

        // Seed mock invoices if empty
        if (invoices.length === 0) {
            await prisma.invoice.createMany({
                data: [
                    {
                        userId,
                        amount: 249.00,
                        currency: "USD",
                        status: "PAID",
                        date: new Date('2024-12-12'),
                        description: "Pro Plan - Monthly",
                        pdfUrl: "#"
                    },
                    {
                        userId,
                        amount: 249.00,
                        currency: "USD",
                        status: "PAID",
                        date: new Date('2024-11-12'),
                        description: "Pro Plan - Monthly",
                        pdfUrl: "#"
                    }
                ]
            });

            invoices = await prisma.invoice.findMany({
                where: { userId },
                orderBy: { date: 'desc' }
            });
        }

        res.json(invoices);

    } catch (error) {
        console.error("Get billing history error:", error);
        res.status(500).json({ message: "Server error" });
    }
};
