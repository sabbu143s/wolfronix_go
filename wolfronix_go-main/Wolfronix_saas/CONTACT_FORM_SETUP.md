# Contact Form Setup Instructions

## Overview
The contact form has been implemented to work in real-time and send details to the company email address.

## Backend Configuration

### Environment Variables
Update the `.env` file in the `backend` directory with your email configuration:

```env
# Email Configuration
EMAIL_HOST="smtp.gmail.com"           # SMTP server host
EMAIL_PORT=587                        # SMTP server port (587 for TLS, 465 for SSL)
EMAIL_USER="your-email@gmail.com"     # Your email address
EMAIL_PASS="your-app-password"        # Your email app password (not regular password!)
COMPANY_EMAIL="akh@akitssconsulting.com"  # Company email to receive messages
```

### For Gmail Users
1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password:
   - Go to Google Account Settings
   - Security → 2-Step Verification → App passwords
   - Generate a password for "Mail"
   - Use this 16-character password in the EMAIL_PASS field

## Frontend Integration

The contact form on the homepage now uses AJAX to submit data to the backend API endpoint `/api/contact`. The form includes:
- Real-time validation
- Loading indicators
- Success/error notifications
- Automatic form reset after successful submission

## API Endpoint

The backend exposes the following endpoint:
- `POST /api/contact` - Handles contact form submissions and sends email

## Styling

The notification toasts have been styled to match the site's cyber/cyberpunk aesthetic with appropriate success/error colors.

## Troubleshooting

### Common Issues:

1. **Email not sending**: Verify all environment variables are correctly set
2. **Connection errors**: Check firewall settings and SMTP server configuration
3. **Gmail blocked sign-in**: Use app password instead of regular password
4. **Port conflicts**: Change PORT variable in .env file

### Testing the Form:
1. Make sure the backend server is running
2. Fill out the contact form on the homepage
3. Submit and check for success notification
4. Verify the email arrives at the company email address