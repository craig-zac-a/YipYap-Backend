require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db");

const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;

// Test Database Connection
db.query("SELECT 1", (err, results) =>
{
    if(err)
    {
        console.error("Database connection failed: " + err.stack);
        return;
    }
    console.log("Database connected");
});


/* LOGS */

// Logs all requests to the console
app.use((req, res, next) => {
    req.requestStartTime = Date.now();
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    // Logs the date and time, request method, URL, and completion time
    res.on("finish", () => {
        // Put date into CDT timezone
        date = new Date();
        date.setHours(date.getHours() - 5);
        console.log(`[${date.toISOString()}] ${req.method} ${req.originalUrl} - Completed in ${Date.now() - req.requestStartTime}ms`);
    });

    next();
});




/* AUTHENTICATION */

// Verify Authentication Token
const verifyToken = (req, res, next) =>
{
    const token = req.headers["authorization"];
    if(!token) return res.status(403).json({ error: "No token provided" });

    jwt.verify(token, JWT_SECRET, (err, decoded) =>
    {
        if(err) return res.status(401).json({ error: "Invalid token" });

        req.accountid = decoded.accountid;
        req.email = decoded.email;
        next();
    });
}




/* POST ENDPOINTS */

// Fetch Posts API
app.get("/posts", verifyToken, (req, res) =>
{
    // Set the default radius to 8047 meters, which is approx 5 miles
    const {latitude, longitude, radius = 8047 } = req.query;

    // Make sure all required fields are provided
    if(!latitude || !longitude) return res.status(400).json({ error: "Missing location parameters" });

    // Fetch Posts Query
    const sqlQuery = `
        SELECT * FROM Post
        WHERE ST_Distance_Sphere(POINT(longitude, latitude), POINT(?, ?)) <= ? AND is_deleted = 0
        ORDER BY timestamp DESC
    `;

    // Execute the query
    db.query(sqlQuery, [longitude, latitude, radius], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        if(results.length === 0) return res.status(204).json({ message: "No posts found" });

        res.status(200).json(results);
    });
});

// Fetch Single Post API
app.get("/posts/:postid", verifyToken, (req, res) =>
{
    const {postid} = req.params;

    if(!postid) return res.status(400).json({ error: "Missing postid" });

    // Fetch Single Post Query
    const sqlQuery = "SELECT * FROM Post WHERE postid = ?";

    // Execute the query
    db.query(sqlQuery, [postid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        if(results.length === 0) return res.status(404).json({ error: "Post not found" });

        res.status(200).json(results[0]);
    });
});

// Add Post API
app.post("/posts", verifyToken, (req, res) =>
{
    const {message, latitude, longitude} = req.body;
    
    // Make sure all required fields are provided
    if(!latitude || !longitude || !message) return res.status(416).json({ error: "Missing location or message" });
    // Insert Post Query
    const sqlQuery = "INSERT INTO Post (latitude, longitude, message, accountid) VALUES (?, ?, ?, ?)";

    // Execute the query
    db.query(sqlQuery, [latitude, longitude, message, req.accountid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        res.status(201).json({ message: "Post created", postid: results.insertId });
    });
});

// Delete Post API
app.delete("/posts/:postid", verifyToken, (req, res) =>
{
    const {postid} = req.params;

    if(!postid) return res.status(400).json({ error: "Missing postid" });

    // Delete Post Query
    const sqlQuery = "UPDATE Post SET is_deleted = 1 WHERE postid = ? AND accountid = ?";

    // Execute the query
    db.query(sqlQuery, [postid, req.accountid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        res.status(200).json({ message: "Post deleted" });
    });
});

// Post Reaction API
app.post("/posts/:postid/reactions", verifyToken, (req, res) =>
{
    const {postid} = req.params;
    const {reaction} = req.body;

    if(postid === undefined || reaction === undefined) return res.status(400).json({ error: "Missing postid or reaction" });

    // Check if user has already reacted to the post
    const checkReactionQuery = "SELECT * FROM PostReaction WHERE postid = ? AND accountid = ?";
    db.query(checkReactionQuery, [postid, req.accountid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        // If the user has already reacted to the post, update the reaction
        if(results.length > 0)
        {
            const isDeleting = reaction === 0;

            console.log("Are we deleting?: ", isDeleting);

            const deleteReactionQuery = "DELETE FROM PostReaction WHERE reaction != ? AND postid = ? AND accountid = ?";
            const updateReactionQuery = "UPDATE PostReaction SET reaction = ? WHERE postid = ? AND accountid = ?";

            db.query(isDeleting? deleteReactionQuery : updateReactionQuery, [reaction, postid, req.accountid], (err, results) =>
            {
                if(err) return res.status(500).json({ error: err.message });

                res.status(200).json({ message: "Reaction updated" });
            });
        }
        else
        {
            const insertReactionQuery = "INSERT INTO PostReaction (postid, accountid, reaction) VALUES (?, ?, ?)";
            db.query(insertReactionQuery, [postid, req.accountid, reaction], (err, results) =>
            {
                if(err) return res.status(500).json({ error: err.message });

                res.status(201).json({ message: "Reaction added" });
            });
        }
    });
});

// Get Post Reactions API
app.get("/posts/:postid/reactions", verifyToken, (req, res) =>
{
    const {postid} = req.params;

    if(!postid) return res.status(400).json({ error: "Missing postid" });

    // Get Post Reactions Query
    const likeCount = "SELECT COUNT(*) AS count FROM PostReaction WHERE postid = ? AND reaction = 1";
    const dislikeCount = "SELECT COUNT(*) AS count FROM PostReaction WHERE postid = ? AND reaction = -1";
    const commentCount = "SELECT COUNT(*) AS count FROM Comment WHERE postid = ?";

    // Execute the query
    db.query(likeCount, [postid], (err, likeResults) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        db.query(dislikeCount, [postid], (err, dislikeResults) =>
        {
            if(err) return res.status(500).json({ error: err.message });

            db.query(commentCount, [postid], (err, commentResults) =>
            {
                if(err) return res.status(500).json({ error: err.message });

                res.status(200).json({ likes: likeResults[0].count, dislikes: dislikeResults[0].count, comments: commentResults[0].count });
            });
        });
    });

});




/* COMMENT ENDPOINTS */

// Fetch Comments API
app.get("/posts/:postid/comments", verifyToken, (req, res) =>
{
    const {postid} = req.params;

    if(!postid) return res.status(400).json({ error: "Missing postid" });

    // Fetch Comments Query
    const sqlQuery = `
    SELECT * FROM Comment WHERE postid = ? AND is_deleted = 0
    ORDER BY timestamp DESC
    `;

    // Execute the query
    db.query(sqlQuery, [postid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        if(results.length === 0) return res.status(204).json({ message: "No comments found" });

        res.status(200).json(results);
    });
});

// Add Comment API
app.post("/posts/:postid/comments", verifyToken, (req, res) =>
{
	const {postid} = req.params;
    const {message} = req.body;

    // Make sure all required fields are provided
    if(!postid || !message) return res.status(400).json({ error: "Missing required fields" });

    // Insert Comment Query
    const sqlQuery = "INSERT INTO Comment (postid, accountid, message) VALUES (?, ?, ?)";

    // Execute the query
    db.query(sqlQuery, [postid, req.accountid, message], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        res.status(201).json({ message: "Comment added", commentid: results.insertId });
    });
});

// Delete Comment API
app.delete("/posts/:postid/comments/:commentid", verifyToken, (req, res) =>
{
    const {commentid} = req.params;
    
    if(!commentid) return res.status(400).json({ error: "Missing commentid" });

    // Delete Comment Query
    const sqlQuery = "UPDATE Comment SET is_deleted = 1 WHERE commentid = ? AND accountid = ?";

    // Execute the query
    db.query(sqlQuery, [commentid, req.accountid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        res.status(200).json({ message: "Comment deleted" });
    });
});

// Comment Reaction API
app.post("/posts/:postid/comments/:commentid/reactions", verifyToken, (req, res) =>
{
    const {commentid} = req.params;
    const {reaction} = req.body;

    if(commentid === undefined || reaction === undefined) return res.status(400).json({ error: "Missing commentid or reaction" });

    // Check if user has already reacted to the comment
    const checkReactionQuery = "SELECT * FROM CommentReaction WHERE commentid = ? AND accountid = ?";

    db.query(checkReactionQuery, [commentid, req.accountid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        // If the user has already reacted to the comment, update the reaction
        if(results.length > 0)
        {
            const isDeleting = reaction === "0";

            const deleteReactionQuery = "DELETE FROM CommentReaction WHERE reaction != ? AND commentid = ? AND accountid = ?";
            const updateReactionQuery = "UPDATE CommentReaction SET reaction = ? WHERE commentid = ? AND accountid = ?";

            db.query(isDeleting? deleteReactionQuery : updateReactionQuery, [reaction, commentid, req.accountid], (err, results) =>
            {
                if(err) return res.status(500).json({ error: err.message });

                res.status(200).json({ message: "Reaction updated" });
            });
        }
        else
        {
            const insertReactionQuery = "INSERT INTO CommentReaction (commentid, accountid, reaction) VALUES (?, ?, ?)";
            db.query(insertReactionQuery, [commentid, req.accountid, reaction], (err, results) =>
            {
                if(err) return res.status(500).json({ error: err.message });

                res.status(201).json({ message: "Reaction added" });
            });
        }
    });
});

// Get Comment Reactions API
app.get("/posts/:postid/comments/:commentid/reactions", verifyToken, (req, res) =>
{
    const {commentid} = req.params;

    if(!commentid) return res.status(400).json({ error: "Missing commentid" });

    // Get Post Reactions Query
    const likeCount = "SELECT COUNT(*) AS count FROM CommentReaction WHERE commentid = ? AND reaction = 1";
    const dislikeCount = "SELECT COUNT(*) AS count FROM CommentReaction WHERE commentid = ? AND reaction = -1";

    // Execute the query
    db.query(likeCount, [commentid], (err, likeResults) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        db.query(dislikeCount, [commentid], (err, dislikeResults) =>
        {
            if(err) return res.status(500).json({ error: err.message });
            res.status(200).json({ likes: likeResults[0].count, dislikes: dislikeResults[0].count });
        });
    });
});




/* ACCOUNT ENDPOINTS */

// Create Account API
app.post("/users/register", async (req, res) =>
    {
        const {email, password} = req.body;
    
        // Make sure email and password are provided
        if(!email || !password) return res.status(400).json({ error: "Email and password are required" });
    
        try
        {
            // Hash the password using 12 rounds of salt
            const hashedPassword = await bcrypt.hash(password, 12);
    
            // Insert Account Query
            const sqlQuery = "INSERT INTO Account (email, password_hash) VALUES (?, ?)";
    
            // Execute the query
            db.query(sqlQuery, [email, hashedPassword], (err, results) => {
                if(err)
                {   
                    // Catches if the error thrown is a duplicate entry error
                    if(err.code === "ER_DUP_ENTRY")
                    {
                        return res.status(409).json({ error: "Email is already in use" });
                    }
    
                    // Other generic error
                    return res.status(500).json({ error: err.message });
                }
    
                res.status(201).json(
                {
                    message: "Account created successfully",
                    accountid: results.insertId,
                });
            });
        }
        catch(err)
        {
            return res.status(500).json({ error: "Error hashing password" });
        }
    });

// Login API
app.post("/users/login", (req, res) =>
{
    const {email, password} = req.body;

    // Make sure email and password are provided
    if(!email || !password) return res.status(400).json({ error: "Missing email or password" });

    try
    {
        // Login Query
        const sqlQuery = "SELECT * FROM Account WHERE email = ?";
        db.query(sqlQuery, [email], async (err, results) =>
        {
            if(err) return res.status(500).json({ error: err.message });

            // If no results are returned, the email is not in the database
            // Do not give away if the email is in the database as this can be used to find valid emails
            if(results.length === 0) return res.status(401).json({ error: "Invalid email or password" });

            // Gets the first result from the query, which should have only returned one result if there is an account with that email
            const user = results[0];

            // Compares the password with the stored hash
            const isMatch = await bcrypt.compare(password, user.password_hash);

            // If the password matches, we return a success message
            if(isMatch)
            {
                const token = jwt.sign({ accountid: user.accountid, email: user.email }, JWT_SECRET, { expiresIn: "24h" });
                return res.json({ message: "Login successful", authToken: token });
            }
            // If the password does not match we return an error
            else return res.status(401).json({ error: "Invalid email or password" });
        });
    }
    catch(err)
    {
        return res.status(500).json({ error: "Error logging in" });
    }
});

// Get User's Post Reactions API
app.get("/users/me/posts/reactions", verifyToken, (req, res) =>
{
    // Get User Reactions Query
    const sqlQuery = "SELECT * FROM PostReaction WHERE accountid = ?";

    // Execute the query
    db.query(sqlQuery, [req.accountid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        res.status(200).json(results);
    });
});

// Get User's Comment Reactions API
app.get("/users/me/comments/reactions", verifyToken, (req, res) =>
{
    // Get User Reactions Query
    const sqlQuery = "SELECT * FROM CommentReaction WHERE accountid = ?";

    // Execute the query
    db.query(sqlQuery, [req.accountid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        res.status(200).json(results);
    });
});

// Get User's Account Information API
app.get("/users/me", verifyToken, (req, res) =>
{
    const sqlQuery = "SELECT * FROM Account WHERE accountid = ?";

    db.query(sqlQuery, [req.accountid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        res.status(200).json(results[0]);
    });
});

// Token Verification for Auto Login
app.get("/users/verify", verifyToken, (req, res) =>
{
    res.json({ message: "Token is valid", accountid: req.accountid, email: req.email });
});

// Update User's Email API
app.put("/users/me/email", verifyToken, (req, res) =>
{
    const {email} = req.body;

    // Make sure email is provided
    if(!email) return res.status(400).json({ error: "Missing email" });

    // Update Email Query
    const sqlQuery = "UPDATE Account SET email = ? WHERE accountid = ?";

    // Execute the query
    db.query(sqlQuery, [email, req.accountid], (err, results) =>
    {
        if(err) return res.status(500).json({ error: err.message });

        res.status(200).json({ message: "Email updated" });
    });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
