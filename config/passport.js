const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const db = require('./db');

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,         // ⚠️ ASEGÚRATE de que diga clientID (con ID en mayúsculas)
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;
    const nombre = profile.displayName;

    try {
        // Verificar si el usuario de Google ya existe en nuestra base de datos
        const [usuarios] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        
        if (usuarios.length > 0) {
            // Si ya existe, simplemente iniciamos sesión con su registro actual
            return done(null, usuarios[0]);
        } else {
            // Si no existe, lo registramos automáticamente (Omitiendo password tradicional)
            const [resultado] = await db.query(
                'INSERT INTO usuarios (nombre, email, password, mfa_secret) VALUES (?, ?, ?, ?)',
                [nombre, email, 'OAUTH_GOOGLE_USER', 'OAUTH_OMITTED']
            );
            
            const nuevoUsuario = { id: resultado.insertId, nombre, email };
            console.log(`[AUDITORÍA OAUTH] Nuevo usuario registrado vía Google: ${email}`);
            return done(null, nuevoUsuario);
        }
    } catch (error) {
        console.error('[ERROR PASSPORT OAUTH]:', error);
        return done(error, null);
    }
  }
));

// Serialización para mantener al usuario en la sesión de Express
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

module.exports = passport;