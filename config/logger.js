const winston = require('winston');
const path = require('path');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(({ message }) => {
            // 💡 Si el mensaje es un objeto, lo convierte a texto para que no salga [object Object]
            if (typeof message === 'object') {
                return JSON.stringify(message);
            }
            return `${message}`;
        })
    ),
    transports: [
        new winston.transports.File({ 
            filename: path.join(__dirname, '../logs/app-segura.log') 
        }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

module.exports = logger;