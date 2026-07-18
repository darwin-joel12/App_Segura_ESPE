const crypto = require('crypto'); // 👈 ¡AÑADE ESTA LÍNEA AL INICIO DE APP.JS!
const express = require('express');
const session = require('express-session'); // <-- 1. AGREGA ESTA IMPORTACIÓN
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const db = require('./config/db');
const authController = require('./controllers/authController');
const passport = require('./config/passport'); // <-- IMPORTAR CONFIGURACIÓN PASSPORT
const logger = require('./config/logger'); // 👈 Importación del motor de logs profesional para el SIEM

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
    const usuarioEmail = req.session.usuarioEmail || 'Desconocido';

    req.session.destroy((err) => {
        if (err) {
            // 🚨 SIEM: Registro de error crítico al intentar destruir sesión
            logger.error({
                evento: 'error_logout',
                modulo: 'autenticacion',
                error: err.message,
                mensaje: 'Fallo crítico al intentar destruir la sesión en el servidor.'
            });
            return res.status(500).send('Error al cerrar la sesión.');
        }
        res.clearCookie('connect.sid'); // Borra la cookie del navegador por seguridad
        
        // 📝 SIEM: Registro de auditoría ordinaria de cierre de sesión
        logger.info({
            evento: 'logout_exitoso',
            modulo: 'autenticacion',
            email: usuarioEmail,
            mensaje: 'Sesión finalizada correctamente por el usuario.'
        });
        
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

        // 📝 SIEM: Registro de éxito de inicio de sesión de tercero (OAuth 2.0)
        logger.info({
            evento: 'login_exitoso_oauth',
            modulo: 'oauth2_google',
            email: req.user.email,
            proveedor: 'Google Cloud Console',
            mensaje: 'Acceso OAuth 2.0 verificado y concedido de forma transparente.'
        });

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
            // 🚨 SIEM: Solicitud de ticket para un usuario inexistente (Alerta potencial de escaneo)
            logger.warn({
                evento: 'ticket_kdc_denegado',
                modulo: 'kerberos_kdc',
                email: email,
                mensaje: 'Solicitud de ticket denegada. El correo electrónico no existe en el sistema centralizado.'
            });
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

        // 📝 SIEM: Registro de emisión de un TGS_REP legítimo
        logger.info({
            evento: 'ticket_kdc_emitido',
            modulo: 'kerberos_kdc',
            email: usuarioReal.email,
            mensaje: 'Ticket Kerberos cifrado simétricamente emitido con éxito.'
        });

        res.json({ success: true, ticket: ticketCifrado });

    } catch (error) {
        // 🚨 SIEM: Error de procesamiento en base de datos interna o criptografía
        logger.error({
            evento: 'error_interno_kdc',
            modulo: 'kerberos_kdc',
            error: error.message,
            mensaje: 'Fallo crítico en el procesamiento del controlador de tickets KDC.'
        });
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
        // 🚨 SIEM: Intento de bypass con un ticket corrupto o alterado
        logger.error({
            evento: 'ticket_kerberos_invalido',
            modulo: 'kerberos_app',
            mensaje: 'Intento de login SSO fallido. El ticket no pudo ser descifrado (Clave incorrecta o alteración).'
        });
        return res.status(401).json({ success: false, message: 'Ticket inválido o manipulado criptográficamente.' });
    }

    const { usuarioId, nombre, email, timestamp, nonce } = ticketDescifrado;
    const tiempoActual = Date.now();
    const cincoMinutos = 5 * 60 * 1000;

    // 🛑 PROCESO 3: PREVENCIÓN DE ATAQUES DE REPETICIÓN (REPLAY ATTACK)
    // Regla A: Verificar si el ticket ya expiró por tiempo (Margen de 5 minutos reglamentario de Kerberos)
    if (tiempoActual - timestamp > cincoMinutos) {
        // 🚨 SIEM: Alerta de ticket obsoleto (Posible reenvío tardío)
        logger.warn({
            evento: 'ticket_kerberos_expirado',
            modulo: 'kerberos_app',
            email: email,
            mensaje: 'Intento de acceso denegado. El ticket de Kerberos superó la ventana de tiempo de 5 minutos.'
        });
        return res.status(401).json({ success: false, message: 'El ticket de Kerberos ha expirado (Superó los 5 minutos).' });
    }

    // Regla B: Verificar si el identificador único (Nonce) ya fue interceptado y reutilizado antes
    if (registrosNoncesUsados.has(nonce)) {
        // 🚨 SIEM [CRÍTICO]: Alerta de Replay Attack detectada en tiempo real. Wazuh disparará una regla de alta severidad aquí.
        logger.error({
            evento: 'ataque_repeticion_detectado',
            modulo: 'kerberos_app',
            email: email,
            nonce: nonce,
            mensaje: '¡ALERTA DE SEGURIDAD!: Se interceptó un intento de reutilización de ticket criptográfico (Replay Attack).'
        });
        return res.status(401).json({ success: false, message: 'Ataque de repetición detectado. Este ticket ya fue usado.' });
    }

    // Si pasa las dos reglas, registramos el nonce para quemar el ticket y que no se vuelva a usar
    registrosNoncesUsados.add(nonce);

    // 🚪 ACCESO SEGURO SIN REENVÍO DE CREDENCIALES: Creamos la sesión definitiva en Express
    req.session.usuarioId = usuarioId;
    req.session.usuarioNombre = nombre;
    req.session.usuarioEmail = email;

    // 📝 SIEM: Acceso concedido vía SSO exitoso
    logger.info({
        evento: 'login_exitoso_sso',
        modulo: 'kerberos_app',
        email: email,
        mensaje: 'Acceso centralizado concedido vía Kerberos Ticket. Credenciales omitidas en red.'
    });

    res.json({ success: true, redirect: '/dashboard' });
});

// ==========================================
//          CONTROL DE ERRORES GLOBAL
// ==========================================
app.use((err, req, res, next) => {
    // 🚨 SIEM: Captura unificada de Information Disclosure (Ocultamiento de trazas técnicas al usuario)
    logger.error({
        evento: 'error_no_controlado',
        modulo: 'servidor_global',
        error: err.message,
        ruta: req.originalUrl,
        metodo: req.method
    });
    res.status(500).send('Error interno en el servidor seguro.');
});

// Levantar el servidor en el puerto especificado
app.listen(PORT, '0.0.0.0', () => {
    // 📝 SIEM: Registro de inicialización de la infraestructura del backend
    logger.info({
        evento: 'inicio_servidor',
        modulo: 'infraestructura',
        mensaje: `Servidor seguro de la aplicación corriendo correctamente en el puerto: ${PORT}`
    });
    // 🚀 CONSOLA: Enlace limpio tradicional para desarrollo rápido (Ctrl + Clic)
     console.log(`[INFO] Servidor corriendo en http://localhost:${PORT}`);
});