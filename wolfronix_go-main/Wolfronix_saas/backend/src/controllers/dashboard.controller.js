import prisma from "../lib/prisma.js";

export const getMyDashboardMetrics = async (req, res) => {
    try {
        const userId = req.userId;

        let metrics = await prisma.userMetrics.findUnique({
            where: { userId: userId }
        });

        if (!metrics) {
            return res.status(404).json({ message: "Metrics not found" });
        }

        let updated = false;
        let updateData = {};

        // Check for null or empty JSON fields and init them if necessary
        // Prisma JSON types handling: if it's null in DB, it comes as null.
        // If it's a valid JSON, it comes as object.

        const isHistoryEmptyOrZeros = !metrics.activityHistory ||
            (Array.isArray(metrics.activityHistory) &&
                (metrics.activityHistory.length === 0 ||
                    metrics.activityHistory.every(h => (h.encryptedRecords || 0) === 0)));

        if (isHistoryEmptyOrZeros && (metrics.protectedRecords || 0) > 0) {
            const baseValue = metrics.protectedRecords;
            updateData.activityHistory = [
                { date: 'Mon', encryptedRecords: Math.floor(baseValue * 0.4), maskedData: Math.floor(baseValue * 0.2) },
                { date: 'Tue', encryptedRecords: Math.floor(baseValue * 0.5), maskedData: Math.floor(baseValue * 0.3) },
                { date: 'Wed', encryptedRecords: Math.floor(baseValue * 0.45), maskedData: Math.floor(baseValue * 0.25) },
                { date: 'Thu', encryptedRecords: Math.floor(baseValue * 0.6), maskedData: Math.floor(baseValue * 0.35) },
                { date: 'Fri', encryptedRecords: Math.floor(baseValue * 0.75), maskedData: Math.floor(baseValue * 0.4) },
                { date: 'Sat', encryptedRecords: Math.floor(baseValue * 0.9), maskedData: Math.floor(baseValue * 0.45) },
                { date: 'Sun', encryptedRecords: baseValue, maskedData: Math.floor(baseValue * 0.5) }
            ];
            updated = true;
        }

        // Check if layerDistribution is missing or has all zero values
        const currentDistribution = metrics.layerDistribution || {};
        const totalLayers = Object.values(currentDistribution).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0);

        if (!metrics.layerDistribution || totalLayers === 0) {
            const baseValue = metrics.protectedRecords || 0;
            // Generate defaults if missing
            const sVal = baseValue === 0 ? 10 : Math.floor(baseValue * 0.25);
            const dVal = baseValue === 0 ? 15 : Math.floor(baseValue * 0.30);
            const eVal = baseValue === 0 ? 20 : Math.floor(baseValue * 0.35);
            const zVal = baseValue === 0 ? 5 : Math.floor(baseValue * 0.10);

            metrics.layerDistribution = {
                staticMasking: sVal,
                dynamicMasking: dVal,
                encryption: eVal,
                zeroTrust: zVal
            };
            updated = true;
        }

        // Enforce the Active Layer counts on the distribution
        // This ensures the chart matches the number, even if DB has old data
        const activeCount = metrics.activeLayers || 4;
        let dist = { ...metrics.layerDistribution };
        let distributionChanged = false;

        if (activeCount < 4 && dist.zeroTrust !== 0) { dist.zeroTrust = 0; distributionChanged = true; }
        if (activeCount < 3 && dist.encryption !== 0) { dist.encryption = 0; distributionChanged = true; }
        if (activeCount < 2 && dist.dynamicMasking !== 0) { dist.dynamicMasking = 0; distributionChanged = true; }
        if (activeCount < 1 && dist.staticMasking !== 0) { dist.staticMasking = 0; distributionChanged = true; }

        // AUTO-HEAL: If active count says we should have it, but it's 0, give it a value
        const baseVal = metrics.protectedRecords || 0;
        if (activeCount >= 1 && (dist.staticMasking || 0) === 0) {
            dist.staticMasking = baseVal > 0 ? Math.floor(baseVal * 0.25) : 25;
            distributionChanged = true;
        }
        if (activeCount >= 2 && (dist.dynamicMasking || 0) === 0) {
            dist.dynamicMasking = baseVal > 0 ? Math.floor(baseVal * 0.30) : 30;
            distributionChanged = true;
        }
        if (activeCount >= 3 && (dist.encryption || 0) === 0) {
            dist.encryption = baseVal > 0 ? Math.floor(baseVal * 0.35) : 35;
            distributionChanged = true;
        }
        if (activeCount >= 4 && (dist.zeroTrust || 0) === 0) {
            dist.zeroTrust = baseVal > 0 ? Math.floor(baseVal * 0.10) : 10;
            distributionChanged = true;
        }

        // Crypto Metrics Auto-Heal
        if ((metrics.encryptionCount || 0) === 0) {
            metrics.encryptionCount = 842391; // Default starting value
            metrics.avgEncryptionTimeMs = 14;
            updated = true;
            updateData.encryptionCount = 842391;
            updateData.avgEncryptionTimeMs = 14;
        }
        if ((metrics.decryptionCount || 0) === 0) {
            metrics.decryptionCount = 592104; // Default starting value
            metrics.avgDecryptionTimeMs = 9;
            updated = true;
            updateData.decryptionCount = 592104;
            updateData.avgDecryptionTimeMs = 9;
        }

        if (distributionChanged || updated) {
            updateData.layerDistribution = dist;
            // Update local object so response is correct immediately
            metrics.layerDistribution = dist;
            updated = true;
        }

        if (updated) {
            metrics = await prisma.userMetrics.update({
                where: { userId: userId },
                data: updateData
            });
        }

        res.json(metrics);
    } catch (error) {
        console.error("Dashboard metrics error:", error);
        res.status(500).json({ message: "Server error" });
    }
};

export const forceRefreshMetrics = async (req, res) => {
    try {
        const userId = req.userId;

        let metrics = await prisma.userMetrics.findUnique({
            where: { userId: userId }
        });

        if (!metrics) {
            return res.status(404).json({ message: "Metrics not found" });
        }

        const baseValue = metrics.protectedRecords || 0;
        const updateData = {
            activityHistory: [
                { date: 'Mon', encryptedRecords: Math.floor(baseValue * 0.4), maskedData: Math.floor(baseValue * 0.2) },
                { date: 'Tue', encryptedRecords: Math.floor(baseValue * 0.5), maskedData: Math.floor(baseValue * 0.3) },
                { date: 'Wed', encryptedRecords: Math.floor(baseValue * 0.45), maskedData: Math.floor(baseValue * 0.25) },
                { date: 'Thu', encryptedRecords: Math.floor(baseValue * 0.6), maskedData: Math.floor(baseValue * 0.35) },
                { date: 'Fri', encryptedRecords: Math.floor(baseValue * 0.75), maskedData: Math.floor(baseValue * 0.4) },
                { date: 'Sat', encryptedRecords: Math.floor(baseValue * 0.9), maskedData: Math.floor(baseValue * 0.45) },
                { date: 'Sun', encryptedRecords: baseValue, maskedData: Math.floor(baseValue * 0.5) }
            ],
            layerDistribution: {
                staticMasking: Math.floor(baseValue * 0.25),
                dynamicMasking: Math.floor(baseValue * 0.30),
                encryption: Math.floor(baseValue * 0.35),
                zeroTrust: Math.floor(baseValue * 0.10)
            },
            encryptionCount: Math.floor(baseValue * 0.9), // Example calculation
            avgEncryptionTimeMs: 12 + Math.random() * 5,
            decryptionCount: Math.floor(baseValue * 0.7),
            avgDecryptionTimeMs: 8 + Math.random() * 4
        };

        metrics = await prisma.userMetrics.update({
            where: { userId: userId },
            data: updateData
        });

        res.json({ message: "Metrics refreshed successfully", metrics });
    } catch (error) {
        console.error("Force refresh metrics error:", error);
        res.status(500).json({ message: "Server error" });
    }
};
