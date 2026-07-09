# Sistema de Control de Accesos Seguro - ESPE 

Este proyecto constituye la entrega del **Proyecto Final** para la asignatura de **Ingeniería de la Seguridad del Software** en la Universidad de las Fuerzas Armadas ESPE (Período Académico: Abril - Agosto 2026).

El sistema consiste en una aplicación web segura orientada al control de accesos, diseñada bajo los principios fundamentales de **Confidencialidad, Integridad y Disponibilidad (C.I.A.)**, alineándose con los marcos normativos de **NIST 2.0** y **MITRE ATT&CK**.

## Características Implementadas (Fase 1)

* **Registro de Usuarios Seguro:** Captura y procesamiento estructurado de credenciales de usuario.
* **Mecanismo de Integridad (Criptografía):** Almacenamiento de contraseñas protegidas mediante funciones de hashing irreversible con **Bcrypt** (factor de costo de 10 saltos).
* **Asociación Multifactor (MFA):** Generación e inyección dinámica de secretos únicos basados en tiempo (TOTP) vinculados directamente al registro del usuario en la base de datos, desplegando un código QR compatible con **Google Authenticator**.
* **Arquitectura Limpia (MVC Estricto):** Separación rigurosa de responsabilidades entre las vistas dinámicas (`.ejs`), la lógica del negocio (`controllers`) y la gestión de datos (`config`).

## Stack Tecnológico

* **Backend:** Node.js v24+ con Express.
* **Base de Datos:** MySQL / MariaDB (Gestionado localmente mediante XAMPP).
* **Motor de Plantillas:** EJS (Embedded JavaScript).
* **Diseño Interfaz:** Tailwind CSS & FontAwesome (vía CDN).
* **Librerías Criptográficas/Seguridad:** `bcrypt`, `speakeasy`, `qrcode`.

## 📦 Estructura del Proyecto

```text
📁 app-segura-espe/
├── 📁 config/          # Conexión y Pool de datos a MySQL
├── 📁 controllers/     # Lógica criptográfica y controladores de autenticación
├── 📁 views/           # Interfaces de usuario dinámicas (.ejs)
├── 📄 .env             # Variables de entorno y llaves del sistema (Excluido en producción)
├── 📄 app.js           # Punto de entrada y servidor principal
├── 📄 package.json     # Definición de dependencias
└── 📄 README.md        # Documentación técnica del repositorio

## Guía de Instalación y Despliegue Local (Para Colaboradores)

### 1. Clonar el Proyecto e Instalar Dependencias
Abre tu terminal o consola de comandos, ubícate en la carpeta donde deseas guardar el proyecto y ejecuta los siguientes comandos:

```bash
# Clonar el repositorio remoto
git clone <ENLACE_DE_TU_REPOSITORIO_AQUÍ>

# Entrar a la carpeta del proyecto
cd App-Segura

# Instalar todas las dependencias del package.json de forma automática
npm install
