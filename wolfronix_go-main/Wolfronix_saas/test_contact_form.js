
import fetch from 'node-fetch';

async function testContact() {
    try {
        const response = await fetch('http://localhost:5001/api/contact', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: 'Test Script',
                email: 'test@example.com',
                company: 'Test Script Corp',
                message: 'Testing from node script'
            })
        });

        const data = await response.json();
        console.log('Status:', response.status);
        console.log('Response:', data);
    } catch (error) {
        console.error('Error:', error);
    }
}

testContact();