const crypto = require('crypto');
const logger = require('./logger'); // 👈 Importación del logger profesional

const KDC_SERVER_SECRET = 'ClaveUltraSecretaCompartidaKDCYApp'; 
const SECRET_KEY = crypto.createHash('sha256').update(KDC_SERVER_SECRET).digest();
const IV_LENGTH = 16;

function generarTicketKerberos(data) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

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
        // 📝 Guarda la anomalía en el archivo físico para Wazuh
        logger.error('ticket_kerberos_expirado - Fallo critico al descifrar el ticket (Ticket alterado o corrupto).');
        return null;
    }
}

module.exports = { generarTicketKerberos, validarTicketKerberos };