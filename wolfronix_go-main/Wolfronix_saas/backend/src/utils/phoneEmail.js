import https from 'https';

export function verifyPhoneToken(userJsonUrl) {
    return new Promise((resolve, reject) => {
        console.log("verifyPhoneToken called with URL:", userJsonUrl);

        try {
            const urlObj = new URL(userJsonUrl);
            const accessToken = urlObj.searchParams.get('access_token');
            const clientId = urlObj.searchParams.get('client_id');

            if (!accessToken || !clientId) {
                // Fallback to GET if params are missing (legacy or different URL)
                if (userJsonUrl && userJsonUrl.startsWith('https://')) {
                    makeGetRequest(userJsonUrl, resolve, reject);
                    return;
                }
                return reject(new Error('Invalid verification URL or missing parameters'));
            }

            const postData = new URLSearchParams({
                access_token: accessToken,
                client_id: clientId
            }).toString();

            const options = {
                hostname: 'eapi.phone.email',
                path: '/getuser',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': postData.length
                }
            };

            const req = https.request(options, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    console.log("Response status:", res.statusCode);
                    console.log("Raw response data:", data.substring(0, 500));

                    try {
                        const parsedData = JSON.parse(data);

                        // Check for status 200 explicitly in body if present
                        if (parsedData.status !== undefined && parsedData.status !== 200) {
                            console.error("API returned error status:", parsedData.status);
                            // If status is 0, it might be failure.
                        }

                        if (parsedData.phone_no) {
                            const countryCode = parsedData.country_code || "";
                            const phone = parsedData.phone_no;
                            resolve(countryCode + phone);
                        } else if (parsedData.user_phone_number) {
                            // Handle legacy/alternate response format
                            const countryCode = parsedData.user_country_code || "";
                            const phone = parsedData.user_phone_number;
                            resolve(countryCode + phone);
                        } else {
                            reject(new Error('Phone number not found in verification data'));
                        }
                    } catch (e) {
                        console.error("JSON parse error:", e.message);
                        reject(new Error('Failed to parse verification data'));
                    }
                });
            });

            req.on('error', (e) => {
                console.error("Request error:", e);
                reject(new Error('Network error during verification'));
            });

            req.write(postData);
            req.end();

        } catch (err) {
            console.error("Error parsing URL:", err);
            // Fallback to GET
            if (userJsonUrl && userJsonUrl.startsWith('https://')) {
                makeGetRequest(userJsonUrl, resolve, reject);
            } else {
                reject(err);
            }
        }
    });
}

function makeGetRequest(url, resolve, reject) {
    https.get(url, (res) => {
        let data = '';

        res.on('data', (chunk) => {
            data += chunk;
        });

        res.on('end', () => {
            console.log("GET Response status:", res.statusCode);
            console.log("GET Raw response data:", data.substring(0, 500));
            try {
                const parsedData = JSON.parse(data);
                if (parsedData.user_phone_number) {
                    const countryCode = parsedData.user_country_code || "";
                    const phone = parsedData.user_phone_number;
                    resolve(countryCode + phone);
                } else if (parsedData.phone_no) {
                    const countryCode = parsedData.country_code || "";
                    const phone = parsedData.phone_no;
                    resolve(countryCode + phone);
                } else {
                    reject(new Error('Phone number not found in verification data (GET)'));
                }
            } catch (e) {
                console.error("GET JSON parse error:", e.message);
                reject(new Error('Failed to parse verification data'));
            }
        });
    }).on('error', (e) => {
        reject(new Error('Network error during verification'));
    });
}
