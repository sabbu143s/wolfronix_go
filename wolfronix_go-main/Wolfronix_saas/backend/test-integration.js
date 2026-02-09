/**
 * Integration Test Script
 * Tests all API endpoints to verify proper integration
 * 
 * Usage: node test-integration.js
 */

const API_BASE = "http://localhost:5000";

let testToken = null;
const testUser = {
    firstName: "Test",
    lastName: "User",
    email: `test${Date.now()}@example.com`,
    password: "TestPass123!",
    company: "Test Company"
};

// Color codes for console output
const colors = {
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    reset: '\x1b[0m'
};

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

async function testHealthCheck() {
    log("\n📡 Testing Health Check Endpoint...", 'blue');
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        
        if (response.status === 200 && data.status === 'ok') {
            log("✓ Health check passed", 'green');
            return true;
        } else {
            log("✗ Health check failed", 'red');
            return false;
        }
    } catch (error) {
        log(`✗ Health check error: ${error.message}`, 'red');
        return false;
    }
}

async function testRegister() {
    log("\n📝 Testing User Registration...", 'blue');
    try {
        const response = await fetch(`${API_BASE}/api/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(testUser)
        });
        
        const data = await response.json();
        
        if (response.status === 201 && data.token) {
            testToken = data.token;
            log("✓ Registration successful", 'green');
            log(`  Token: ${testToken.substring(0, 20)}...`, 'yellow');
            return true;
        } else {
            log(`✗ Registration failed: ${data.message}`, 'red');
            return false;
        }
    } catch (error) {
        log(`✗ Registration error: ${error.message}`, 'red');
        return false;
    }
}

async function testLogin() {
    log("\n🔐 Testing User Login...", 'blue');
    try {
        const response = await fetch(`${API_BASE}/api/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email: testUser.email,
                password: testUser.password
            })
        });
        
        const data = await response.json();
        
        if (response.status === 200 && data.token) {
            testToken = data.token;
            log("✓ Login successful", 'green');
            return true;
        } else {
            log(`✗ Login failed: ${data.message}`, 'red');
            return false;
        }
    } catch (error) {
        log(`✗ Login error: ${error.message}`, 'red');
        return false;
    }
}

async function testGetUserProfile() {
    log("\n👤 Testing Get User Profile...", 'blue');
    try {
        const response = await fetch(`${API_BASE}/api/user/me`, {
            headers: {
                "Authorization": `Bearer ${testToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.status === 200 && data.email === testUser.email) {
            log("✓ Get profile successful", 'green');
            log(`  User: ${data.firstName} ${data.lastName}`, 'yellow');
            log(`  Email: ${data.email}`, 'yellow');
            return true;
        } else {
            log(`✗ Get profile failed: ${data.message}`, 'red');
            return false;
        }
    } catch (error) {
        log(`✗ Get profile error: ${error.message}`, 'red');
        return false;
    }
}

async function testUpdateUserProfile() {
    log("\n✏️  Testing Update User Profile...", 'blue');
    try {
        const updateData = {
            firstName: "Updated",
            lastName: "User",
            company: "Updated Company"
        };
        
        const response = await fetch(`${API_BASE}/api/user/me`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${testToken}`
            },
            body: JSON.stringify(updateData)
        });
        
        const data = await response.json();
        
        if (response.status === 200 && data.firstName === "Updated") {
            log("✓ Update profile successful", 'green');
            log(`  Updated name: ${data.firstName} ${data.lastName}`, 'yellow');
            return true;
        } else {
            log(`✗ Update profile failed: ${data.message}`, 'red');
            return false;
        }
    } catch (error) {
        log(`✗ Update profile error: ${error.message}`, 'red');
        return false;
    }
}

async function testGetDashboardMetrics() {
    log("\n📊 Testing Get Dashboard Metrics...", 'blue');
    try {
        const response = await fetch(`${API_BASE}/api/dashboard/metrics`, {
            headers: {
                "Authorization": `Bearer ${testToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.status === 200) {
            log("✓ Get dashboard metrics successful", 'green');
            log(`  Protected Records: ${data.protectedRecords}`, 'yellow');
            log(`  Active Layers: ${data.activeLayers}`, 'yellow');
            log(`  Security Alerts: ${data.securityAlerts}`, 'yellow');
            return true;
        } else {
            log(`✗ Get dashboard metrics failed: ${data.message}`, 'red');
            return false;
        }
    } catch (error) {
        log(`✗ Get dashboard metrics error: ${error.message}`, 'red');
        return false;
    }
}

async function testInvalidToken() {
    log("\n🔒 Testing Invalid Token Handling...", 'blue');
    try {
        const response = await fetch(`${API_BASE}/api/user/me`, {
            headers: {
                "Authorization": "Bearer invalid_token_here"
            }
        });
        
        if (response.status === 401) {
            log("✓ Invalid token properly rejected", 'green');
            return true;
        } else {
            log("✗ Invalid token not properly handled", 'red');
            return false;
        }
    } catch (error) {
        log(`✗ Invalid token test error: ${error.message}`, 'red');
        return false;
    }
}

async function runAllTests() {
    log("╔════════════════════════════════════════════════════╗", 'blue');
    log("║     WOLFRONIX INTEGRATION TEST SUITE              ║", 'blue');
    log("╚════════════════════════════════════════════════════╝", 'blue');
    
    const results = [];
    
    // Run tests sequentially
    results.push(await testHealthCheck());
    results.push(await testRegister());
    results.push(await testLogin());
    results.push(await testGetUserProfile());
    results.push(await testUpdateUserProfile());
    results.push(await testGetDashboardMetrics());
    results.push(await testInvalidToken());
    
    // Summary
    const passed = results.filter(r => r).length;
    const total = results.length;
    
    log("\n╔════════════════════════════════════════════════════╗", 'blue');
    log(`║  TEST RESULTS: ${passed}/${total} PASSED`, passed === total ? 'green' : 'red');
    log("╚════════════════════════════════════════════════════╝", 'blue');
    
    if (passed === total) {
        log("\n🎉 All tests passed! Integration is working correctly.", 'green');
        process.exit(0);
    } else {
        log("\n⚠️  Some tests failed. Please check the errors above.", 'red');
        process.exit(1);
    }
}

// Check if server is running
fetch(`${API_BASE}/health`)
    .then(() => {
        runAllTests();
    })
    .catch(() => {
        log("✗ Cannot connect to server. Please start the backend server first:", 'red');
        log("  cd backend && npm start", 'yellow');
        process.exit(1);
    });
