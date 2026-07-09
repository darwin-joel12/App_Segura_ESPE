const express = require('express');
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

// Middlewares necesarios para capturar y procesar datos de formularios (POST)
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configurar el motor de plantillas EJS para las interfaces de usuario
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

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
app.get('/dashboard', (req, res) => {
    res.render('dashboard', { title: 'Panel de Control Seguro' });
});

// ==========================================
//    RUTAS DE PROCESAMIENTO (MÉTODO POST)
// ==========================================

// Procesar el envío del formulario de registro de usuarios
app.post('/auth/register', authController.registrarUsuario);

// Procesar el envío del formulario de inicio de sesión
app.post('/auth/login', authController.loginUsuario);

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