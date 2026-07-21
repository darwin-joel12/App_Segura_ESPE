const winston = require('winston');
require('winston-syslog');
const path = require('path');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(({ message }) => {
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
        }),
        new winston.transports.Syslog({
            host: process.env.WAZUH_MANAGER_IP || '127.0.0.1',
            port: process.env.WAZUH_SYSLOG_PORT || 514,
            protocol: 'udp4',
            app_name: 'app-segura',
            eol: '\n'
        })
    ]
});

module.exports = logger;