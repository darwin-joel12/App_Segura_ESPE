const mysql = require('mysql2');
const dotenv = require('dotenv');

dotenv.config();

// Configuración del pool de conexiones para XAMPP
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const promisePool = pool.promise();

// Validar conexión inicial
pool.getConnection((err, connection) => {
    if (err) {
        console.error('[ERROR] Error al conectar a MySQL en XAMPP:', err.message);
    } else {
        console.log('[OK] Conectado exitosamente al MySQL de XAMPP.');
        connection.release();
    }
});

module.exports = promisePool;