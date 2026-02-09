import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import prisma from '../lib/prisma.js';

if (process.env.GOOGLE_CLIENT_ID) {
    passport.use(
        new GoogleStrategy(
            {
                clientID: process.env.GOOGLE_CLIENT_ID,
                clientSecret: process.env.GOOGLE_CLIENT_SECRET,
                callbackURL: process.env.GOOGLE_CALLBACK_URL,
            },
            async (accessToken, refreshToken, profile, done) => {
                try {
                    const email = profile.emails[0].value;
                    const firstName = profile.name.givenName || '';
                    const lastName = profile.name.familyName || '';
                    const providerId = profile.id;

                    // Check if user already exists
                    let user = await prisma.user.findUnique({
                        where: { email }
                    });

                    if (user) {
                        // Update provider info if user exists but registered with different method
                        if (user.provider === 'local' && !user.providerId) {
                            user = await prisma.user.update({
                                where: { id: user.id },
                                data: {
                                    provider: 'google',
                                    providerId: providerId
                                }
                            });
                        }
                        return done(null, user);
                    }

                    // Create new user with metrics
                    user = await prisma.$transaction(async (tx) => {
                        const newUser = await tx.user.create({
                            data: {
                                firstName,
                                lastName,
                                email,
                                provider: 'google',
                                providerId: providerId,
                                passwordHash: null,
                                role: 'USER'
                            }
                        });

                        await tx.userMetrics.create({
                            data: {
                                userId: newUser.id
                            }
                        });

                        return newUser;
                    });

                    return done(null, user);
                } catch (error) {
                    return done(error, null);
                }
            }
        )
    );
}

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id }
        });
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

export default passport;
