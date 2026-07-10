const express = require('express');
const session = require('express-session'); // <-- 1. AGREGA ESTA IMPORTACIÓN
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const db = require('./config/db');
const authController = require('./controllers/authController');

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
    res.render('login', { title: 'Iniciar Sesión - ESPE' });
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