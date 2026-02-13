/**
 * Wolfronix Controller
 * API endpoints for Wolfronix API key management
 */

import { 
    provisionWolfronixAccess, 
    regenerateApiKey, 
    getUserApiKey,
    syncUsageFromEngine 
} from '../services/wolfronix.service.js';
import prisma from '../lib/prisma.js';

/**
 * GET /api/wolfronix/key
 * Get the current user's API key (masked)
 */
export async function getApiKey(req, res) {
    try {
        const userId = req.userId;
        const reveal = req.query.reveal === 'true';
        
        const keyInfo = await getUserApiKey(userId, reveal);
        
        res.json({
            success: true,
            data: keyInfo
        });
    } catch (error) {
        console.error('Get API key error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
}

/**
 * POST /api/wolfronix/key
 * Generate a new API key (first time) or regenerate existing
 */
export async function generateApiKey(req, res) {
    try {
        const userId = req.userId;
        
        // Get user's subscription
        const user = await prisma.user.findUnique({
            where: { id: userId },
            include: { subscription: true }
        });
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        // Check if user has active subscription
        const plan = user.subscription?.plan || 'STARTER';
        const subscriptionStatus = user.subscription?.status || 'ACTIVE';
        
        if (subscriptionStatus !== 'ACTIVE' && subscriptionStatus !== 'TRIAL') {
            return res.status(403).json({
                success: false,
                message: 'Active subscription required to generate API key'
            });
        }
        
        // Check if key already exists
        if (user.wolfronixApiKey) {
            // Regenerate existing key
            const result = await regenerateApiKey(userId);
            
            // Get masked version for response
            const keyInfo = await getUserApiKey(userId, true);
            
            return res.json({
                success: true,
                message: 'API key regenerated successfully',
                data: {
                    apiKey: keyInfo.apiKey,
                    maskedKey: keyInfo.maskedKey,
                    clientId: keyInfo.clientId,
                    createdAt: keyInfo.createdAt,
                    isNew: false
                }
            });
        }
        
        // Generate new key
        const result = await provisionWolfronixAccess(userId, plan);
        
        // Get masked version for response
        const keyInfo = await getUserApiKey(userId, true);
        
        res.status(201).json({
            success: true,
            message: 'API key generated successfully',
            data: {
                apiKey: keyInfo.apiKey,
                maskedKey: keyInfo.maskedKey,
                clientId: keyInfo.clientId,
                createdAt: keyInfo.createdAt,
                isNew: true
            }
        });
        
    } catch (error) {
        console.error('Generate API key error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
}

/**
 * DELETE /api/wolfronix/key
 * Revoke API key
 */
export async function revokeApiKey(req, res) {
    try {
        const userId = req.userId;
        
        // Get client ID before clearing it
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { wolfronixClientId: true }
        });
        
        // Deactivate on Wolfronix engine first (best-effort)
        if (user?.wolfronixClientId) {
            try {
                const engineUrl = process.env.WOLFRONIX_ENGINE_URL || 'http://localhost:8443';
                const adminKey = process.env.WOLFRONIX_ADMIN_KEY;
                const response = await fetch(
                    `${engineUrl}/api/v1/enterprise/clients/${encodeURIComponent(user.wolfronixClientId)}`,
                    {
                        method: 'DELETE',
                        headers: {
                            'X-Admin-Key': adminKey,
                            'Content-Type': 'application/json'
                        }
                    }
                );
                if (!response.ok) {
                    console.warn(`Engine deactivation returned ${response.status} for client ${user.wolfronixClientId}`);
                }
            } catch (engineErr) {
                console.error('Failed to deactivate on Wolfronix engine:', engineErr.message);
                // Continue with local revocation even if engine call fails
            }
        }
        
        await prisma.user.update({
            where: { id: userId },
            data: {
                wolfronixApiKey: null,
                wolfronixClientId: null,
                apiKeyCreatedAt: null
            }
        });
        
        res.json({
            success: true,
            message: 'API key revoked successfully'
        });
        
    } catch (error) {
        console.error('Revoke API key error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
}

/**
 * GET /api/wolfronix/usage
 * Get current usage statistics from Wolfronix engine
 */
export async function getUsage(req, res) {
    try {
        const userId = req.userId;
        
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { wolfronixClientId: true }
        });
        
        if (!user?.wolfronixClientId) {
            return res.status(404).json({
                success: false,
                message: 'No Wolfronix client registered'
            });
        }
        
        const usage = await syncUsageFromEngine(user.wolfronixClientId);
        
        res.json({
            success: true,
            data: usage
        });
        
    } catch (error) {
        console.error('Get usage error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
}
