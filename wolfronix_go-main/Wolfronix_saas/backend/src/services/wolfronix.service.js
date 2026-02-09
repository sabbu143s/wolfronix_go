/**
 * Wolfronix Service
 * Handles API key generation and communication with Wolfronix encryption engine
 */

import crypto from 'crypto';
import prisma from '../lib/prisma.js';

// Wolfronix Engine Configuration
// In production, set WOLFRONIX_ENGINE_URL in .env (e.g., https://your-server:9443)
const WOLFRONIX_ENGINE_URL = process.env.WOLFRONIX_ENGINE_URL || 'https://localhost:9443';

/**
 * Generate a unique Wolfronix API key with prefix
 * Format: wfx_<32 base64url characters>
 */
export function generateWolfronixKey() {
    const randomBytes = crypto.randomBytes(24).toString('base64url');
    return `wfx_${randomBytes}`;
}

/**
 * Get plan limits based on subscription plan
 */
export function getPlanLimits(plan) {
    const limits = {
        'STARTER': {
            apiCallsLimit: 10000,
            seatsLimit: 3,
            features: ['community_support']
        },
        'PRO': {
            apiCallsLimit: 100000,
            seatsLimit: 10,
            features: ['all_layers', 'priority_support']
        },
        'ENTERPRISE': {
            apiCallsLimit: 999999999, // Unlimited
            seatsLimit: 999999,
            features: ['all_layers', 'priority_support', 'custom_compliance', 'dedicated_support']
        }
    };
    return limits[plan] || limits['STARTER'];
}

/**
 * Provision Wolfronix access for a user
 * Generates API key and registers with Wolfronix engine
 * 
 * @param {number} userId - User ID from SaaS database
 * @param {string} plan - Subscription plan (STARTER, PRO, ENTERPRISE)
 * @returns {Promise<{apiKey: string, clientId: string}>}
 */
export async function provisionWolfronixAccess(userId, plan = 'STARTER') {
    // Get user details
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, firstName: true, lastName: true, email: true, company: true }
    });

    if (!user) {
        throw new Error('User not found');
    }

    // Generate new API key
    const apiKey = generateWolfronixKey();
    const clientId = `saas_${user.id}`;
    const planLimits = getPlanLimits(plan);

    // Register with Wolfronix Go engine
    try {
        const response = await fetch(`${WOLFRONIX_ENGINE_URL}/api/v1/enterprise/register`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Admin-Key': process.env.WOLFRONIX_ADMIN_KEY || ''
            },
            body: JSON.stringify({
                client_id: clientId,
                client_name: user.company || `${user.firstName} ${user.lastName}`,
                wolfronix_key: apiKey,
                api_endpoint: '', // SaaS clients don't have their own storage
                api_key: '', // No external API key needed
                api_calls_limit: planLimits.apiCallsLimit,
                seats_limit: planLimits.seatsLimit,
                plan: plan
            })
        });

        if (!response.ok) {
            console.error('Wolfronix engine registration failed:', await response.text());
            // Continue anyway - we'll store the key and sync later
        }
    } catch (error) {
        console.error('Failed to connect to Wolfronix engine:', error.message);
        // Continue anyway - key generation shouldn't fail due to engine connectivity
    }

    // Save API key to SaaS database
    await prisma.user.update({
        where: { id: userId },
        data: {
            wolfronixApiKey: apiKey,
            wolfronixClientId: clientId,
            apiKeyCreatedAt: new Date()
        }
    });

    console.log(`✅ Wolfronix access provisioned for user ${userId} (${plan})`);
    
    return { apiKey, clientId };
}

/**
 * Regenerate API key for a user
 * Invalidates old key and creates new one
 * 
 * @param {number} userId - User ID
 * @returns {Promise<{apiKey: string}>}
 */
export async function regenerateApiKey(userId) {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        include: { subscription: true }
    });

    if (!user) {
        throw new Error('User not found');
    }

    const plan = user.subscription?.plan || 'STARTER';
    
    // Provision new access (will overwrite old key)
    const result = await provisionWolfronixAccess(userId, plan);
    
    console.log(`🔄 API key regenerated for user ${userId}`);
    
    return { apiKey: result.apiKey };
}

/**
 * Get user's API key (masked for display)
 * 
 * @param {number} userId - User ID
 * @param {boolean} reveal - Whether to reveal full key
 * @returns {Promise<{apiKey: string, maskedKey: string, createdAt: Date}>}
 */
export async function getUserApiKey(userId, reveal = false) {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
            wolfronixApiKey: true,
            wolfronixClientId: true,
            apiKeyCreatedAt: true
        }
    });

    if (!user) {
        throw new Error('User not found');
    }

    // If no API key exists, return null
    if (!user.wolfronixApiKey) {
        return {
            apiKey: null,
            maskedKey: null,
            clientId: null,
            createdAt: null,
            hasKey: false
        };
    }

    // Mask key for display (show first 7 chars: "wfx_xxx")
    const maskedKey = user.wolfronixApiKey.substring(0, 7) + '************************';

    return {
        apiKey: reveal ? user.wolfronixApiKey : null,
        maskedKey,
        clientId: user.wolfronixClientId,
        createdAt: user.apiKeyCreatedAt,
        hasKey: true
    };
}

/**
 * Sync usage from Wolfronix engine to SaaS
 * Called periodically to update usage metrics
 * 
 * @param {string} clientId - Wolfronix client ID
 */
export async function syncUsageFromEngine(clientId) {
    try {
        const response = await fetch(`${WOLFRONIX_ENGINE_URL}/api/v1/metrics/client/${clientId}`, {
            headers: { 
                'X-Admin-Key': process.env.WOLFRONIX_ADMIN_KEY || ''
            }
        });

        if (!response.ok) {
            throw new Error('Failed to fetch metrics');
        }

        const metrics = await response.json();
        
        // Update SaaS usage tracking
        const userId = parseInt(clientId.replace('saas_', ''));
        
        await prisma.subscription.updateMany({
            where: { userId },
            data: {
                // Update usage would go here if we had those fields
            }
        });

        // Update UserMetrics
        await prisma.userMetrics.updateMany({
            where: { userId },
            data: {
                encryptionCount: metrics.records_encrypted || 0,
                decryptionCount: metrics.records_decrypted || 0,
                avgEncryptionTimeMs: metrics.avg_encrypt_time_ms || 0,
                avgDecryptionTimeMs: metrics.avg_decrypt_time_ms || 0
            }
        });

        return metrics;
    } catch (error) {
        console.error('Failed to sync usage:', error.message);
        return null;
    }
}

export default {
    generateWolfronixKey,
    getPlanLimits,
    provisionWolfronixAccess,
    regenerateApiKey,
    getUserApiKey,
    syncUsageFromEngine
};
