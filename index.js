require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT;

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

// Test Database Connection
db.query("SELECT 1", (err, results) =>
{
    if (err)
    {
        console.error("Database connection failed: " + err.stack);
        return;
    }
    console.log("Database connected");
});

// Checks for database errors
db.on("error", (err) =>
{
    console.error("Database error:", err);
});

module.exports = db;

// Fetch Posts API
app.get("/posts/fetch", (req, res) => {
    const {latitude, longitude, radius} = req.query;

    // Make sure all required fields are provided
    if (!latitude || !longitude || !radius)
    {
        return res.status(400).json({ error: "Missing parameters" });
    }

    // Fetch Posts Query
    const sqlQuery = `
        SELECT * FROM Post
        WHERE ST_Distance_Sphere(POINT(longitude, latitude), POINT(?, ?)) <= ?
    `;

    // Execute the query
    db.query(sqlQuery, [longitude, latitude, radius], (err, results) => {
        if (err)
        {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

// Add New Post API
app.post("/posts", (req, res) => {
    const {message, accountid, latitude, longitude} = req.body;
  
    // Make sure all required fields are provided
    if(!latitude || !longitude || !message || !accountid)
    {
        return res.status(400).json({ error: "Missing required fields" });
    }

    // Insert Post Query
    const sqlQuery = "INSERT INTO Post (latitude, longitude, message, accountid) VALUES (?, ?, ?, ?)";

    // Execute the query
    db.query(sqlQuery, [latitude, longitude, message, accountid], (err, results) => {
        if (err)
        {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ message: "Post created", postid: results.insertId });
    });
});

// Create Account API
app.post("/account/register", async (req, res) => {
    const {email, password} = req.body;

    // Make sure email and password are provided
    if(!email || !password)
    {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try
    {
        // Hash the password using 12 rounds of salt
        const hashedPassword = await bcrypt.hash(password, 12);

        // Insert Account Query
        const sqlQuery = "INSERT INTO Account (email, password_hash) VALUES (?, ?)";

        // Execute the query
        db.query(sqlQuery, [email, hashedPassword], (err, results) => {
            if (err)
            {
                return res.status(500).json({ error: err.message });
            }

            res.status(201).json(
            {
                message: "Account created successfully",
                accountid: results.insertId,
            });
        });
    }
    catch (err)
    {
        return res.status(500).json({ error: "Error hashing password" });
    }
});

// Login API
app.post("/account/login", (req, res) => {
    const {email, password} = req.body;

    // Make sure email and password are provided
    if (!email || !password)
    {
        return res.status(400).json({ error: "Missing email or password" });
    }

    // Login Query
    const sqlQuery = "SELECT * FROM Account WHERE email = ?";
    db.query(sqlQuery, [email], (err, results) => {
        if (err)
        {
            return res.status(500).json({ error: err.message });
        }

        // If no results are returned, the email is not in the database
        if (results.length === 0)
        {
            // Do not give away if the email is in the database as this can be used to find valid emails
            return res.status(401).json({ error: "Invalid email or password" });
        }

        // Gets the first result from the query, which should have only returned one result if there is an account with that email
        const user = results[0];

        // Compares the password with the stored hash
        bcrypt.compare(password, user.password_hash, (err, isMatch) => {
            if (err)
            {
                return res.status(500).json({ error: err.message });
            }

            if (isMatch)
            {
                // If the password matches, we return a success message
                return res.json({ message: "Login successful", user: { email: user.email } });
            }
            else
            {
                // If the password does not match we return an error
                return res.status(401).json({ error: "Invalid email or password" });
            }
        });
    });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
