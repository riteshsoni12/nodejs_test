const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

const JWT_SECRET = "OsCkXG75VhqWo";

// --------------------------------------------
// MySQL Connection (Hostinger DB via Render)
// --------------------------------------------
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

// Test DB connection
db.getConnection()
    .then(() => console.log("MySQL connected successfully"))
    .catch(err => console.error("DB connection failed:", err.message));


// ------------------------------------------------
// Generate JWT Token
// ------------------------------------------------
app.post("/generate-token", (req, res) => {
    try {
        const { user_id } = req.body;

        if (!user_id) {
            return res.status(400).json({
                status: "failed",
                message: "user_id is required"
            });
        }

        const token = jwt.sign(
            { user_id },
            JWT_SECRET,
            { expiresIn: "2h" }
        );

        return res.json({
            status: "success",
            message: "Token generated successfully",
            token
        });

    } catch (err) {
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: err.message
        });
    }
});


// ------------------------------------------------
// Middleware: Validate Token
// ------------------------------------------------
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            status: "failed",
            message: "Token is missing"
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({
            status: "failed",
            message: "Invalid or expired token"
        });
    }
}

// ------------------------------------------------
// GET USERS FROM HOSTINGER DATABASE (Protected)
// ------------------------------------------------
app.get("/api/users", verifyToken, async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM users");

        return res.json({
            status: "success",
            count: rows.length,
            users: rows
        });

    } catch (err) {
        return res.status(500).json({
            status: "error",
            message: "Database error",
            error: err.message
        });
    }
});


// ------------------------------------------------
// SIGNUP API
// ------------------------------------------------
app.post("/api/signup", async (req, res) => {
    try {
        const {
            name,
            email,
            dob,
            user_type,
            password,
            profile_pic,
            location,
            preferred_music
        } = req.body;

        // 1. Validate
        if (!name || !email || !password) {
            return res.status(400).json({
                status: "failed",
                message: "name, email and password are required"
            });
        }

        // 2. Check if email already exists
        const [existingUser] = await db.query(
            "SELECT id FROM users WHERE email = ?",
            [email]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({
                status: "failed",
                message: "Email already registered"
            });
        }

        // 3. Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 4. Insert into users table
        const [insertUser] = await db.query(
            `INSERT INTO users 
            (name, email, dob, user_type, password, profile_pic, location, preferred_music, status, created_at, updated_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
            [
                name,
                email,
                dob,
                user_type,
                hashedPassword,
                profile_pic,
                location,
                preferred_music,
                "online"
            ]
        );

        const user_id = insertUser.insertId; // newly created user id

        // 5. Create default profile (music_lover)
        const [insertProfile] = await db.query(
            `INSERT INTO profile (user_id, account_type, email, created_at, updated_at) 
             VALUES (?, ?, ?, NOW(), NOW())`,
            [user_id, "music_lover", email]
        );

        const profile_id = insertProfile.insertId;

        // 6. Update users table with default profile info
        await db.query(
            `UPDATE users SET 
            default_profile_type = ?, 
            default_profile_id = ?, 
            status = ?,
            updated_at = NOW()
            WHERE id = ?`,
            ["music_lover", profile_id, "online", user_id]
        );

        // 7. Return success response
        return res.json({
            status: "success",
            message: "Signup successful",
            data: {
                user_id,
                default_profile_id: profile_id,
                default_profile_type: "music_lover"
            }
        });

    } catch (err) {
        console.log("Signup Error:", err);
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: err.message
        });
    }
});


// ------------------------------------------------
// LOGIN API (MINIMAL RESPONSE)
// ------------------------------------------------
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Validation
        if (!email || !password) {
            return res.status(400).json({
                status: "failed",
                message: "email and password are required"
            });
        }

        // 2. Check if user exists
        const [users] = await db.query(
            "SELECT * FROM users WHERE email = ? LIMIT 1",
            [email]
        );

        if (users.length === 0) {
            return res.status(400).json({
                status: "failed",
                message: "Invalid email or password"
            });
        }

        const user = users[0];

        // 3. Check password
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(400).json({
                status: "failed",
                message: "Invalid email or password"
            });
        }

        // 4. Generate JWT token
        const token = jwt.sign(
            { user_id: user.id },
            JWT_SECRET,
            { expiresIn: "2h" }
        );

        // ✔ 5. Minimal response
        return res.json({
            status: "success",
            message: "Login successful",
            token
        });

    } catch (err) {
        console.log("Login Error:", err);
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: err.message
        });
    }
});


// -------------------------------
// SAVE or UPDATE EPK
// -------------------------------
app.post("/api/epk", verifyToken, async (req, res) => {
    const conn = await db.getConnection();
    try {
        const {
            user_id,
            logo,
            banner,
            images,
            videos,
            bio,
            website_url,
            instagram_url,
            facebook_url,
            youtube_url,
            spotify_url,
            epk_url,
            other_url
        } = req.body;

        // -------- VALIDATIONS ---------
        if (!user_id) {
            return res.status(400).json({
                status: "failed",
                message: "user_id is required"
            });
        }

        if (typeof bio !== "string") {
            return res.status(400).json({
                status: "failed",
                message: "bio must be a string"
            });
        }

        // Ensure user updates their own EPK
        if (req.user.user_id !== user_id) {
            return res.status(403).json({
                status: "failed",
                message: "Unauthorized: You can update only your own EPK"
            });
        }

        const imageList = images ? images.split(",") : [];
        const videoList = videos ? videos.split(",") : [];

        await conn.beginTransaction();

        // Check if EPK exists
        const [existing] = await conn.execute(
            "SELECT id FROM epk WHERE user_id = ? LIMIT 1",
            [user_id]
        );

        let epkId;

        if (existing.length > 0) {
            // ----------- UPDATE MAIN EPK TABLE -----------
            epkId = existing[0].id;

            await conn.execute(
                `UPDATE epk SET 
                    logo = ?, banner = ?, bio = ?, 
                    website_url = ?, instagram_url = ?, facebook_url = ?, 
                    youtube_url = ?, spotify_url = ?, epk_url = ?, other_url = ?, 
                    updated_at = NOW()
                WHERE user_id = ?`,
                [
                    logo, banner, bio,
                    website_url, instagram_url, facebook_url,
                    youtube_url, spotify_url, epk_url, other_url,
                    user_id
                ]
            );

        } else {
            // ----------- INSERT MAIN EPK TABLE -----------
            const [result] = await conn.execute(
                `INSERT INTO epk 
                (user_id, logo, banner, bio, website_url, instagram_url, facebook_url, 
                 youtube_url, spotify_url, epk_url, other_url, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    user_id, logo, banner, bio,
                    website_url, instagram_url, facebook_url,
                    youtube_url, spotify_url, epk_url, other_url
                ]
            );

            epkId = result.insertId;
        }

        // ----------- IMAGES -----------
        await conn.execute("DELETE FROM epk_images WHERE epk_id = ?", [epkId]);
        for (const url of imageList) {
            await conn.execute(
                "INSERT INTO epk_images (epk_id, url, created_at) VALUES (?, ?, NOW())",
                [epkId, url]
            );
        }

        // ----------- VIDEOS -----------
        await conn.execute("DELETE FROM epk_videos WHERE epk_id = ?", [epkId]);
        for (const url of videoList) {
            await conn.execute(
                "INSERT INTO epk_videos (epk_id, url, created_at) VALUES (?, ?, NOW())",
                [epkId, url]
            );
        }

        await conn.commit();

        return res.status(200).json({
            success: true,
            message: existing.length > 0 ? "EPK updated successfully" : "EPK saved successfully",
            epk_id: epkId
        });

    } catch (error) {
        await conn.rollback();
        console.error("EPK Save Error:", error);
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});

// -------------------------------------------
// GET EPK by user_id (Protected by verifyToken)
// -------------------------------------------
app.get("/api/epk/:user_id", verifyToken, async (req, res) => {
    try {
        const user_id = req.params.user_id;

        // ------------------------
        // 1. Validate user_id
        // ------------------------
        if (!user_id || isNaN(user_id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid or missing user_id"
            });
        }

        // ------------------------
        // 2. Fetch EPK from database
        // ------------------------
        const [rows] = await db.query(
            "SELECT * FROM epk WHERE user_id = ?",
            [user_id]
        );

        // No EPK found for user
        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "No EPK found for this user_id"
            });
        }

        // ------------------------
        // 3. Success
        // ------------------------
        return res.status(200).json({
            success: true,
            message: "EPK fetched successfully",
            data: rows[0]
        });

    } catch (error) {
        console.error("EPK fetch error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
            error : error.message
        });
    }
});


// -------------------------------------------
// GET profiles of user (Protected by verifyToken)
// -------------------------------------------
app.get("/api/profiles/:user_id", verifyToken, async (req, res) => {
    try {
        const { user_id } = req.params;

        if (!user_id) {
            return res.status(400).json({
                status: "failed",
                message: "user_id is required"
            });
        }

        // Fetch all profiles except music_lover
        const [rows] = await db.query(
            "SELECT * FROM profile WHERE user_id = ? AND account_type != 'music_lover'",
            [user_id]
        );

        return res.json({
            status: "success",
            count: rows.length,
            profiles: rows
        });

    } catch (err) {
        return res.status(500).json({
            status: "error",
            message: "Database error",
            error: err.message
        });
    }
});

// ------------------------------------------------
app.listen(3000, () => console.log("API running on http://localhost:3000"));