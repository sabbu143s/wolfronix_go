
export const razorpayConfig = {
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
};

if (!razorpayConfig.key_id || !razorpayConfig.key_secret) {
    console.warn('\u26a0\ufe0f RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET environment variables are required for payment processing');
}
