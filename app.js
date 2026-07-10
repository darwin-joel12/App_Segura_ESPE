const crypto = require('crypto'); // 👈 ¡AÑADE ESTA LÍNEA AL INICIO DE APP.JS!
const express = require('express');
const session = require('express-session'); // <-- 1. AGREGA ESTA IMPORTACIÓN
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const db = require('./config/db');
const authController = require('./controllers/authController');
const passport = require('./config/passport'); // <-- IMPORTAR CONFIGURACIÓN PASSPORT

// Cargar variables de entorno desde el archivo .env
dotenv.config();

// Inicializar la aplicación Express
const app = express();
const PORT = process.env.PORT || 3000;

// <-- 2. AGREGA ESTE MIDDLEWARE DE SESIONES AQUÍ ABAJO (Debe ir antes de las rutas)
app.use(session({
    secret: process.env.SESSION_SECRET || 'llave_secreta_para_espe_seguro', // Clave para firmar la cookie
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Cambiar a true si usas HTTPS (en producción)
        httpOnly: true, // Mitiga ataques XSS (no accesible desde JS del navegador)
        maxAge: 1000 * 60 * 15 // La sesión expira automáticamente en 15 minutos
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// Middlewares necesarios para capturar y procesar datos de formularios (POST)
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configurar el motor de plantillas EJS para las interfaces de usuario
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware de autenticación (Garantiza Confidencialidad)
const verificarAutenticacion = (req, res, next) => {
    // Si el usuario tiene una sesión activa y completó el login básico
    if (req.session && req.session.usuarioId) {
        return next(); // Puede continuar a la ruta
    }
    // Si no está autenticado, lo rebota al login
    res.redirect('/login');
};

// ==========================================
//      RUTAS DE NAVEGACIÓN (MÉTODO GET)
// ==========================================

// Redirigir la raíz directamente a la pantalla de inicio de sesión
app.get('/', (req, res) => {
    res.redirect('/login'); 
});

// Renderizar la vista de inicio de sesión
app.get('/login', (req, res) => {
    // Si ya tiene sesión definitiva activa, lo mandamos al dashboard
    if (req.session && req.session.usuarioId) {
        return res.redirect('/dashboard');
    }
    // Pasamos error: null por defecto
    res.render('login', { 
        title: 'Iniciar Sesión - ESPE',
        error: null 
    });
});

// Renderizar la vista de registro de usuarios
app.get('/register', (req, res) => {
    res.render('register', { title: 'Registro de Usuario - ESPE' });
});

// Renderizar el panel de control protegido
// Antes: app.get('/dashboard', (req, res) => { ... });
// Ahora cámbialo a esto:
app.get('/dashboard', verificarAutenticacion, (req, res) => {
    res.render('dashboard', { title: 'Panel de Control Seguro' });
});

// Ruta para Cerrar Sesión de forma segura (Destrucción en Servidor)
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('[ERROR LOGOUT]:', err);
            return res.status(500).send('Error al cerrar la sesión.');
        }
        res.clearCookie('connect.sid'); // Borra la cookie del navegador por seguridad
        console.log('[AUDITORÍA] Sesión finalizada correctamente por el usuario.');
        res.redirect('/login'); // Redirige al login vacío
    });
});

app.get('/verificar-mfa', (req, res) => {
    if (!req.session.usuarioIdTemp) {
        return res.redirect('/login');
    }
    // Pasamos error: null para que no muestre nada la primera vez
    res.render('verificar-mfa', { 
        title: 'Verificar Segundo Factor - ESPE',
        error: null 
    });
});

// ==========================================
//    RUTAS DE PROCESAMIENTO (MÉTODO POST)
// ==========================================

// Procesar el envío del formulario de registro de usuarios
app.post('/auth/register', authController.registrarUsuario);

// Procesar el envío del formulario de inicio de sesión
app.post('/auth/login', authController.loginUsuario);

app.post('/auth/verificar-mfa', authController.verificarMfa);


// ==========================================
// 🚀 RUTAS PARA OAUTH 2.0 (GOOGLE)
// ==========================================

// 1. Redirigir al usuario a la página de inicio de sesión de Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// 2. Ruta de retorno a la que Google envía el perfil del usuario
app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        // El login con Google es tan seguro que los tokens de identidad ya fueron verificados.
        // Establecemos la sesión definitiva directamente en Express
        req.session.usuarioId = req.user.id;
        req.session.usuarioNombre = req.user.nombre;
        req.session.usuarioEmail = req.user.email;

        console.log(`[AUDITORÍA] Acceso OAuth 2.0 exitoso para: ${req.user.email}`);
        res.redirect('/dashboard');
    }
);

const { generarTicketKerberos, validarTicketKerberos } = require('./config/kdc');
// Memoria volátil temporal para guardar los Nonces usados y prevenir ataques de repetición (Replay Attacks)
const registrosNoncesUsados = new Set();

// ======================================================================
// 🎟️ ACTIVIDAD 3: ENDPOINTS DE AUTENTICACIÓN CENTRALIZADA (KERBEROS)
// ======================================================================

// 1. Endpoint Real del KDC vinculado a MySQL
app.post('/kdc/solicitar-ticket', async (req, res) => {
    const { email } = req.body; // El cliente solo envía el correo con el que quiere hacer SSO

    if (!email) {
        return res.status(400).json({ success: false, message: 'El correo electrónico es obligatorio.' });
    }

    try {
        // El KDC consulta a la base de datos de XAMPP si el usuario existe
        const [usuarios] = await db.query('SELECT id, nombre, email FROM usuarios WHERE email = ?', [email]);

        if (usuarios.length === 0) {
            console.log(`[AUDITORÍA KDC ALERT]: Solicitud de ticket denegada. El correo ${email} no está registrado.`);
            return res.status(404).json({ success: false, message: 'Usuario no encontrado en el sistema centralizado.' });
        }

        const usuarioReal = usuarios[0];

        // Construimos el Ticket con los datos VERDADEROS de la base de datos
        const ticketPayload = {
            usuarioId: usuarioReal.id,
            nombre: usuarioReal.nombre,
            email: usuarioReal.email,
            timestamp: Date.now(),
            nonce: crypto.randomBytes(8).toString('hex')
        };

        // Ciframos el ticket con la clave maestra compartida
        const ticketCifrado = generarTicketKerberos(ticketPayload);

        console.log(`[AUDITORÍA KDC]: Ticket Kerberos (TGS_REP) emitido con éxito para el usuario real: ${usuarioReal.email}`);
        res.json({ success: true, ticket: ticketCifrado });

    } catch (error) {
        console.error('[ERROR KDC CONTRACT]:', error);
        res.status(500).json({ success: false, message: 'Error interno en el KDC.' });
    }
});

// 2. Endpoint de tu Aplicación que recibe y valida el ticket para dar acceso SSO
app.post('/auth/kerberos-login', (req, res) => {
    const { ticket } = req.body;

    if (!ticket) {
        return res.status(400).json({ success: false, message: 'No se proporcionó ningún ticket de Kerberos.' });
    }

    // El servidor intenta descifrar el ticket usando la clave compartida con el KDC
    const ticketDescifrado = validarTicketKerberos(ticket);

    if (!ticketDescifrado) {
        return res.status(401).json({ success: false, message: 'Ticket inválido o manipulado criptográficamente.' });
    }

    const { usuarioId, nombre, email, timestamp, nonce } = ticketDescifrado;
    const tiempoActual = Date.now();
    const cincoMinutos = 5 * 60 * 1000;

    // 🛑 PROCESO 3: PREVENCIÓN DE ATAQUES DE REPETICIÓN (REPLAY ATTACK)
    // Regla A: Verificar si el ticket ya expiró por tiempo (Margen de 5 minutos reglamentario de Kerberos)
    if (tiempoActual - timestamp > cincoMinutos) {
        console.log(`[AUDITORÍA ALERT]: Intento de acceso con Ticket expirado. Usuario: ${email}`);
        return res.status(401).json({ success: false, message: 'El ticket de Kerberos ha expirado (Superó los 5 minutos).' });
    }

    // Regla B: Verificar si el identificador único (Nonce) ya fue interceptado y reutilizado antes
    if (registrosNoncesUsados.has(nonce)) {
        console.log(`[AUDITORÍA REPLAY ATTACK]: ¡Ataque de repetición detectado! Reutilización del nonce: ${nonce}`);
        return res.status(401).json({ success: false, message: 'Ataque de repetición detectado. Este ticket ya fue usado.' });
    }

    // Si pasa las dos reglas, registramos el nonce para quemar el ticket y que no se vuelva a usar
    registrosNoncesUsados.add(nonce);

    // 🚪 ACCESO SEGURO SIN REENVÍO DE CREDENCIALES: Creamos la sesión definitiva en Express
    req.session.usuarioId = usuarioId;
    req.session.usuarioNombre = nombre;
    req.session.usuarioEmail = email;

    console.log(`[AUDITORÍA SSO]: Acceso concedido vía Kerberos Ticket para: ${email}. Contraseña no requerida.`);
    res.json({ success: true, redirect: '/dashboard' });
});

// ==========================================
//          CONTROL DE ERRORES GLOBAL
// ==========================================
app.use((err, req, res, next) => {
    console.error(`[ERROR LOG] ${new Date().toISOString()} - ${err.message}`);
    res.status(500).send('Error interno en el servidor seguro.');
});

// Levantar el servidor en el puerto especificado
app.listen(PORT, () => {
    console.log(`[INFO] Servidor corriendo en http://localhost:${PORT}`);
});