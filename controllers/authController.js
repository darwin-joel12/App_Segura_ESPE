const db = require('../config/db');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const logger = require('../config/logger');

exports.registrarUsuario = async (req, res) => {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) return res.status(400).send('Todos los campos son obligatorios.');

    try {
        const [usuariosExistentes] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (usuariosExistentes.length > 0) return res.status(400).send('El correo electrónico ya está registrado.');

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const mfaSecret = speakeasy.generateSecret({ name: `ESPE Control de Accesos (${email})` });

        await db.query(
            'INSERT INTO usuarios (nombre, email, password, mfa_secret) VALUES (?, ?, ?, ?)',
            [nombre, email, hashedPassword, mfaSecret.base32]
        );

        logger.info({
            evento: 'registro_usuario_exitoso',
            modulo: 'autenticacion',
            email: email,
            mensaje: 'Nuevo usuario registrado con éxito.'
        });

        qrcode.toDataURL(mfaSecret.otpauth_url, (err, data_url) => {
            if (err) {
                logger.error({
                    evento: 'error_generacion_qr',
                    modulo: 'autenticacion',
                    error: err.message,
                    mensaje: 'Error al generar el QR de seguridad.'
                });
                return res.status(500).send('Error al generar el QR de seguridad.');
            }
            res.render('mfa-setup', { title: 'Configurar Segundo Factor - ESPE', qrCodeUrl: data_url, secret: mfaSecret.base32 });
        });
    } catch (error) {
        logger.error({
            evento: 'error_no_controlado',
            modulo: 'autenticacion',
            error: error.message,
            mensaje: 'Error crítico en registro de usuario.'
        });
        res.status(500).send('Error interno al procesar el registro del usuario.');
    }
};

exports.loginUsuario = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.render('login', { title: 'Iniciar Sesión - ESPE', error: 'Todos los campos son obligatorios.' });

    try {
        const [usuarios] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (usuarios.length === 0 || !(await bcrypt.compare(password, usuarios[0].password))) {
            return res.render('login', { title: 'Iniciar Sesión - ESPE', error: 'El correo electrónico o la contraseña son incorrectos.' });
        }

        const usuario = usuarios[0];
        req.session.usuarioIdTemp = usuario.id;
        req.session.usuarioEmailTemp = usuario.email;
        req.session.usuarioNombreTemp = usuario.nombre;

        logger.info({
            evento: 'login_password_ok',
            modulo: 'autenticacion',
            email: email,
            mensaje: 'Credenciales correctas, pendiente verificación MFA.'
        });
        res.redirect('/verificar-mfa');
    } catch (error) {
        logger.error({
            evento: 'error_no_controlado',
            modulo: 'autenticacion',
            error: error.message,
            mensaje: 'Error interno al intentar iniciar sesión.'
        });
        res.render('login', { title: 'Iniciar Sesión - ESPE', error: 'Error interno al intentar iniciar sesión.' });
    }
};

exports.verificarMfa = async (req, res) => {
    const { codigoMfa } = req.body;
    const usuarioId = req.session.usuarioIdTemp;
    if (!usuarioId) return res.redirect('/login');

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

            logger.info({
                evento: 'mfa_verificado_exitoso',
                modulo: 'autenticacion',
                usuarioId: usuarioId,
                mensaje: 'Verificación MFA exitosa.'
            });
            res.redirect('/dashboard');
        } else {
            logger.error({
                evento: 'mfa_fallido',
                modulo: 'autenticacion',
                usuarioId: usuarioId,
                mensaje: 'Código MFA incorrecto o expirado.'
            });
            return res.render('verificar-mfa', { title: 'Verificar Segundo Factor - ESPE', error: 'El código introducido es incorrecto o ha expirado.' });
        }
    } catch (error) {
        logger.error({
            evento: 'error_no_controlado',
            modulo: 'autenticacion',
            error: error.message,
            mensaje: 'Error interno al validar el código MFA.'
        });
        res.render('verificar-mfa', { title: 'Verificar Segundo Factor - ESPE', error: 'Ocurrió un error interno al validar el código.' });
    }
};