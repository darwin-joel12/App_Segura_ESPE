const crypto = require('crypto');

// Clave secreta maestra simulada que comparten ÚNICAMENTE el KDC y nuestro Servidor Express
const KDC_SERVER_SECRET = 'ClaveUltraSecretaCompartidaKDCYApp'; 
// Ajustamos la clave para que cumpla con los 32 bytes requeridos por AES-256
const SECRET_KEY = crypto.createHash('sha256').update(KDC_SERVER_SECRET).digest();
const IV_LENGTH = 16;

/**
 * Función para cifrar un Ticket (Emulación de emisión TGS)
 */
function generarTicketKerberos(data) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    // Retornamos el IV junto al texto cifrado para poder desencriptarlo después
    return iv.toString('hex') + ':' + encrypted;
}

/**
 * Función para descifrar y validar un Ticket (Emulación de validación en el Servidor)
 */
function validarTicketKerberos(ticketCifrado) {
    try {
        const textParts = ticketCifrado.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', SECRET_KEY, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (error) {
        console.error('[AUDITORÍA KERBEROS ERROR]: Fallo al descifrar el ticket (Ticket alterado/inválido).');
        return null;
    }
}

module.exports = {
    generarTicketKerberos,
    validarTicketKerberos
};