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

    if (!email || !password) {
        return res.status(400).send('Todos los campos son obligatorios.');
    }

    try {
        const [usuarios] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);

        if (usuarios.length === 0) {
            return res.status(400).send('El correo electrónico o la contraseña son incorrectos.');
        }

        const usuario = usuarios[0];
        const coinciden = await bcrypt.compare(password, usuario.password);

        if (!coinciden) {
            return res.status(400).send('El correo electrónico o la contraseña son incorrectos.');
        }

        // En lugar de iniciar sesión definitiva, guardamos los datos de forma TEMPORAL
        req.session.usuarioIdTemp = usuario.id;
        req.session.usuarioEmailTemp = usuario.email;
        req.session.usuarioNombreTemp = usuario.nombre;

        console.log(`[AUDITORÍA] Credenciales correctas para: ${email}. Pasando a verificación MFA.`);

        // Redirigir a la pantalla del código de 6 dígitos
        res.redirect('/verificar-mfa');

    } catch (error) {
        console.error('[ERROR LOGIN]:', error);
        res.status(500).send('Error interno al intentar iniciar sesión.');
    }
};

// Nueva función para verificar el código de 6 dígitos enviado por el usuario
exports.verificarMfa = async (req, res) => {
    const { codigoMfa } = req.body;
    const usuarioId = req.session.usuarioIdTemp;

    if (!usuarioId) {
        return res.redirect('/login');
    }

    try {
        const [usuarios] = await db.query('SELECT mfa_secret FROM usuarios WHERE id = ?', [usuarioId]);
        const usuario = usuarios[0];

        const verificado = speakeasy.totp.verify({
            secret: usuario.mfa_secret,
            encoding: 'base32',
            token: codigoMfa,
            window: 1 
        });

        if (verificado) {
            req.session.usuarioId = req.session.usuarioIdTemp;
            req.session.usuarioNombre = req.session.usuarioNombreTemp;
            req.session.usuarioEmail = req.session.usuarioEmailTemp;

            delete req.session.usuarioIdTemp;

            console.log(`[AUDITORÍA] Verificación MFA exitosa para usuario ID: ${usuarioId}.`);
            res.redirect('/dashboard');
        } else {
            console.log(`[AUDITORÍA ALERT] Intento de verificación MFA fallido para usuario ID: ${usuarioId}.`);
            
            // 🔄 EN LUGAR DE ENVIAR TEXTO PLANO, RENDERIZAMOS LA VISTA CON EL ERROR
            return res.render('verificar-mfa', {
                title: 'Verificar Segundo Factor - ESPE',
                error: 'El código introducido es incorrecto o ha expirado. Inténtalo de nuevo.'
            });
        }

    } catch (error) {
        console.error('[ERROR VERIFICACIÓN MFA]:', error);
        res.render('verificar-mfa', {
            title: 'Verificar Segundo Factor - ESPE',
            error: 'Ocurrió un error interno al validar el código.'
        });
    }
};