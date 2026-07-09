const db = require('../config/db');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

/**
 * PROCESO 1: Registro de Usuario
 * - Captura los datos del formulario.
 * - Verifica duplicados en la base de datos de XAMPP.
 * - Aplica Hashing Seguro con Bcrypt (Garantiza el principio de Integridad).
 * - Genera un secreto único MFA y lo asocia permanentemente al registro del usuario.
 * - Renderiza el código QR para Google Authenticator.
 */
exports.registrarUsuario = async (req, res) => {
    const { nombre, email, password } = req.body;

    // Validación básica de campos obligatorios
    if (!nombre || !email || !password) {
        return res.status(400).send('Todos los campos son obligatorios.');
    }

    try {
        // 1. Verificar si el correo electrónico ya existe en MySQL
        const [usuariosExistentes] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (usuariosExistentes.length > 0) {
            return res.status(400).send('El correo electrónico ya está registrado.');
        }

        // 2. Cifrar la contraseña usando un factor de costo seguro (saltRounds = 10)
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // 3. Generar la clave secreta única para la Autenticación Multifactor (MFA)
        const mfaSecret = speakeasy.generateSecret({
            name: `ESPE Control de Accesos (${email})`
        });

        // 4. Almacenar el nuevo registro en la base de datos con el hash y el secreto MFA
        await db.query(
            'INSERT INTO usuarios (nombre, email, password, mfa_secret) VALUES (?, ?, ?, ?)',
            [nombre, email, hashedPassword, mfaSecret.base32]
        );

        console.log(`[AUDITORÍA] Nuevo usuario registrado con éxito: ${email} - Secreto MFA asociado.`);

        // 5. Transformar la URL de autenticación del secreto en un código QR visible
        qrcode.toDataURL(mfaSecret.otpauth_url, (err, data_url) => {
            if (err) {
                console.error('[ERROR GENERACIÓN QR]:', err);
                return res.status(500).send('Error al generar el QR de seguridad.');
            }
            
            // Renderizar la vista de configuración del MFA enviándole el QR y el código secreto manual
            res.render('mfa-setup', {
                title: 'Configurar Segundo Factor - ESPE',
                qrCodeUrl: data_url,
                secret: mfaSecret.base32
            });
        });

    } catch (error) {
        console.error('[ERROR CRÍTICO EN REGISTRO]:', error);
        res.status(500).send('Error interno al procesar el registro del usuario.');
    }
};

/**
 * PROCESO 2: Inicio de Sesión Seguro (Fase 1: Validación de Credenciales Básicas)
 * - Busca el usuario por su correo electrónico.
 * - Valida la coincidencia de la contraseña provista usando la comparación segura de hashes.
 */
exports.loginUsuario = async (req, res) => {
    const { email, password } = req.body;

    // Validación básica de campos obligatorios
    if (!email || !password) {
        return res.status(400).send('Todos los campos son obligatorios.');
    }

    try {
        // 1. Buscar al usuario dentro de la tabla en base a su correo electrónico
        const [usuarios] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        
        // Control de mitigación contra enumeración de usuarios: mensaje genérico por seguridad
        if (usuarios.length === 0) {
            return res.status(400).send('El correo electrónico o la contraseña son incorrectos.');
        }

        const usuario = usuarios[0];

        // 2. Comparar de forma segura la contraseña ingresada con el Hash almacenado
        const coinciden = await bcrypt.compare(password, usuario.password);

        if (!coinciden) {
            return res.status(400).send('El correo electrónico o la contraseña son incorrectos.');
        }

        console.log(`[AUDITORÍA] Credenciales básicas válidas para: ${email}. Redirigiendo a verificación.`);
        
        // 3. Por ahora, redirige temporalmente directo al Dashboard
        res.redirect('/dashboard');

    } catch (error) {
        console.error('[ERROR CRÍTICO EN LOGIN]:', error);
        res.status(500).send('Error interno al intentar iniciar sesión.');
    }
};