import nodemailer from 'nodemailer';

/**
 * Send contact form message to company email
 */
export const sendContactMessage = async (req, res) => {
    try {
        const { name, email, company, message } = req.body;

        // Validate required fields
        if (!name || !email || !message) {
            return res.status(400).json({
                success: false,
                message: 'Name, email, and message are required fields'
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        // Get email configuration from environment variables
        const {
            EMAIL_HOST,
            EMAIL_PORT,
            EMAIL_USER,
            EMAIL_PASS,
            COMPANY_EMAIL
        } = process.env;

        // Check if email configuration exists
        if (!EMAIL_HOST || !EMAIL_PORT || !EMAIL_USER || !EMAIL_PASS || !COMPANY_EMAIL) {
            console.error('Email configuration is missing in environment variables');
            return res.status(500).json({
                success: false,
                message: 'Email service is not configured properly'
            });
        }

        // Create transporter
        const transporter = nodemailer.createTransport({
            host: EMAIL_HOST,
            port: parseInt(EMAIL_PORT),
            secure: parseInt(EMAIL_PORT) === 465, // true for 465, false for other ports
            auth: {
                user: EMAIL_USER,
                pass: EMAIL_PASS
            }
        });

        // Verify transporter configuration
        await transporter.verify();

        // Prepare email content
        const mailOptions = {
            from: `"${name} (via wolfronix)" <${EMAIL_USER}>`,
            replyTo: `"${name}" <${email}>`,
            to: COMPANY_EMAIL,
            subject: `Contact Form Submission from ${name}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #0066FF;">New Contact Form Submission</h2>
                    <div style="background-color: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3>Submission Details:</h3>
                        <p><strong>Name:</strong> ${name}</p>
                        <p><strong>Email:</strong> ${email}</p>
                        <p><strong>Company:</strong> ${company || 'Not provided'}</p>
                        <p><strong>Message:</strong></p>
                        <div style="background-color: white; padding: 15px; border-radius: 4px; border-left: 4px solid #0066FF;">
                            <p>${message.replace(/\n/g, '<br>')}</p>
                        </div>
                    </div>
                    <p style="color: #666; font-size: 14px;">This email was sent from the Wolfronix contact form on ${new Date().toLocaleString()}</p>
                </div>
            `
        };

        // Send email
        const info = await transporter.sendMail(mailOptions);

        console.log('Email sent:', info.messageId);

        res.status(200).json({
            success: true,
            message: 'Your message has been sent successfully!',
            messageId: info.messageId
        });

    } catch (error) {
        console.error('Error sending contact form email:', error);

        // Return generic error to prevent information disclosure
        res.status(500).json({
            success: false,
            message: 'Failed to send message. Please try again later.'
        });
    }
};