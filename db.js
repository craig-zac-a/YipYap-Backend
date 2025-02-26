require("dotenv").config();
const mysql = require("mysql2");

// Database Connection Parameters
const db = mysql.createPool(
{
    connectionLimit: 10,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

// Checks for database errors
db.on("error", (err) =>
{
    console.error("Database error:", err);
});

module.exports = db;