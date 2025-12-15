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

        // 1. Validate required fields
        if (!name || !email || !password) {
            return res.status(400).json({
                status: "failed",
                message: "name, email and password are required"
            });
        }

        // 2. Check for existing email
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

        // 4. Insert user (NO profile creation, NO default profile update)
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

        const user_id = insertUser.insertId;

        // 5. Success response
        return res.status(200).json({
            status: "success",
            message: "Signup successful",
            data: {
                user_id: user_id
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


// -----------------------------------------------------
// SAVE or UPDATE EPK
// -----------------------------------------------------
app.post("/api/epk", verifyToken, async (req, res) => {
    const conn = await db.getConnection();
    try {
        const {
            user_id,
            logo,
            banner,
            bio,
            website_url,
            instagram_url,
            facebook_url,
            youtube_url,
            spotify_url,
            epk_url,
            other_url,
            images, // now expected as ARRAY
            videos  // now expected as ARRAY
        } = req.body;

        // ------------ VALIDATION ---------------
        if (!user_id) {
            return res.status(400).json({
                status: "failed",
                message: "user_id is required"
            });
        }

        if (req.user.user_id !== user_id) {
            return res.status(403).json({
                status: "failed",
                message: "Unauthorized: You can update only your own EPK"
            });
        }

        if (bio && typeof bio !== "string") {
            return res.status(400).json({
                status: "failed",
                message: "bio must be a string"
            });
        }

        const imageList = Array.isArray(images) ? images : [];
        const videoList = Array.isArray(videos) ? videos : [];

        await conn.beginTransaction();

        // Check if EPK exists
        const [existing] = await conn.execute(
            "SELECT id FROM epk WHERE user_id = ? LIMIT 1",
            [user_id]
        );

        let epkId;

        if (existing.length > 0) {
            // -------- UPDATE MAIN EPK --------
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
            // -------- INSERT MAIN EPK --------
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

        // -------- IMAGES --------
        await conn.execute("DELETE FROM epk_images WHERE epk_id = ?", [epkId]);
        for (const url of imageList) {
            await conn.execute(
                "INSERT INTO epk_images (epk_id, url, created_at) VALUES (?, ?, NOW())",
                [epkId, url]
            );
        }

        // -------- VIDEOS --------
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
            message: existing.length > 0 ? "EPK updated successfully" : "EPK created successfully",
            epk_id: epkId
        });

    } catch (error) {
        await conn.rollback();
        console.error("EPK Error:", error);
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
        // 2. Fetch EPK main data
        // ------------------------
        const [epkRows] = await db.query(
            "SELECT * FROM epk WHERE user_id = ?",
            [user_id]
        );

        // No EPK created yet
        if (epkRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "No EPK found for this user_id"
            });
        }

        const epk = epkRows[0];
        const epkId = epk.id;

        // ------------------------
        // 3. Fetch images
        // ------------------------
        const [imageRows] = await db.query(
            "SELECT url FROM epk_images WHERE epk_id = ?",
            [epkId]
        );

        const images = imageRows.map(row => row.url);

        // ------------------------
        // 4. Fetch videos
        // ------------------------
        const [videoRows] = await db.query(
            "SELECT url FROM epk_videos WHERE epk_id = ?",
            [epkId]
        );

        const videos = videoRows.map(row => row.url);

        // ------------------------
        // 5. Success Response
        // ------------------------
        return res.status(200).json({
            success: true,
            message: "EPK fetched successfully",
            epk: epk,
            images: images,
            videos: videos
        });

    } catch (error) {
        console.error("EPK fetch error:", error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
            error: error.message
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
            "SELECT * FROM profile WHERE user_id = ?",
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


// ------------------------------------------------------
// UPDATE USER PROFILE (Protected by verifyToken)
// ------------------------------------------------------
app.put("/api/update-user", verifyToken, async (req, res) => {
    try {
        const user_id = req.user.user_id;  // from token

        const {
            name,
            email,
            dob,
            location,
            profile_pic,
            preferred_music
        } = req.body;

        // Validate
        if (!name || !email) {
            return res.status(400).json({
                success: false,
                message: "name and email are required"
            });
        }

        // Check if email is already taken by another user
        const [existingEmail] = await db.query(
            "SELECT id FROM users WHERE email = ? AND id != ?",
            [email, user_id]
        );

        if (existingEmail.length > 0) {
            return res.status(400).json({
                success: false,
                message: "Email already exists for another user"
            });
        }

        // Build update query dynamically (only update provided fields)
        const fields = [];
        const values = [];

        if (name) { fields.push("name = ?"); values.push(name); }
        if (email) { fields.push("email = ?"); values.push(email); }
        if (dob) { fields.push("dob = ?"); values.push(dob); }
        if (location) { fields.push("location = ?"); values.push(location); }
        if (profile_pic) { fields.push("profile_pic = ?"); values.push(profile_pic); }
        if (preferred_music) { fields.push("preferred_music = ?"); values.push(preferred_music); }

        fields.push("updated_at = NOW()");

        const sql = `UPDATE users SET ${fields.join(", ")} WHERE id = ?`;
        values.push(user_id);

        // Execute update
        await db.query(sql, values);

        // Fetch updated user
        const [updatedUser] = await db.query(
            "SELECT id, name, email, dob, location, profile_pic, preferred_music FROM users WHERE id = ?",
            [user_id]
        );

        return res.status(200).json({
            success: true,
            message: "Profile updated successfully",
            data: updatedUser[0]
        });

    } catch (error) {
        console.error("Update Profile Error:", error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
            error: error.message
        });
    }
});


// ----------------------------------------------------------
// SAVE or UPDATE PROFILE (artist, promoter, venue)
// ----------------------------------------------------------
app.post("/api/profile", verifyToken, async (req, res) => {
    try {
        const {
            user_id,
            account_type, // artist | promoter | venue

            // COMMON FIELDS
            location,
            stage_name,
            fee_range,
            bio,
            profile_pic,
            banner_pic,
            willing_to_travel,
            genre,
            preferred_event_type,
            email,
            phone,

            // CONTACT FIELDS
            artist_contact_person,
            promoter_contact_person,
            venue_contact_person,
            manager_email,
            manager_phone,

            // PROMOTER FIELDS
            company_name,

            // VENUE FIELDS
            venue_name,
            venue_capacity,
            opening_hours,
            type_of_venue,
            venue_email,
            venue_address,
            venue_phone
        } = req.body;

        // ---------------------------
        // 1. Validate required fields
        // ---------------------------
        if (!user_id || !account_type) {
            return res.status(400).json({
                success: false,
                message: "user_id and account_type are required"
            });
        }

        // User can update only their own profile
        if (req.user.user_id !== user_id) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized: You can update only your own profile"
            });
        }

        // Validate account_type
        const validTypes = ["artist", "promoter", "venue"];
        if (!validTypes.includes(account_type)) {
            return res.status(400).json({
                success: false,
                message: "Invalid account_type"
            });
        }

        // ---------------------------
        // 2. Check if profile exists
        // ---------------------------
        const [existing] = await db.query(
            `SELECT id FROM profile WHERE user_id = ? AND account_type = ? LIMIT 1`,
            [user_id, account_type]
        );

        // ---------------------------
        // 3. Build UPDATE field list
        // ---------------------------
        const updateFields = [];
        const updateValues = [];

        const addUpdate = (column, value) => {
            if (typeof value !== "undefined") {
                updateFields.push(`${column} = ?`);
                updateValues.push(value);
            }
        };

        addUpdate("location", location);
        addUpdate("stage_name", stage_name);
        addUpdate("fee_range", fee_range);
        addUpdate("bio", bio);
        addUpdate("profile_pic", profile_pic);
        addUpdate("banner_pic", banner_pic);
        addUpdate("willing_to_travel", willing_to_travel);
        addUpdate("genre", genre);
        addUpdate("preferred_event_type", preferred_event_type);
        addUpdate("email", email);
        addUpdate("phone", phone);

        addUpdate("artist_contact_person", artist_contact_person);
        addUpdate("promoter_contact_person", promoter_contact_person);
        addUpdate("venue_contact_person", venue_contact_person);
        addUpdate("manager_email", manager_email);
        addUpdate("manager_phone", manager_phone);

        addUpdate("company_name", company_name);

        addUpdate("venue_name", venue_name);
        addUpdate("venue_capacity", venue_capacity);
        addUpdate("opening_hours", opening_hours);
        addUpdate("type_of_venue", type_of_venue);
        addUpdate("venue_email", venue_email);
        addUpdate("venue_address", venue_address);
        addUpdate("venue_phone", venue_phone);

        // ---------------------------
        // 4. UPDATE if exists
        // ---------------------------
        if (existing.length > 0) {
            const profileId = existing[0].id;

            if (updateFields.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "No fields provided to update"
                });
            }

            const sql = `
                UPDATE profile SET ${updateFields.join(", ")}, updated_at = NOW()
                WHERE id = ?
            `;

            await db.query(sql, [...updateValues, profileId]);

            return res.status(200).json({
                success: true,
                message: `${account_type} profile updated successfully`,
                profile_id: profileId
            });
        }

        // ---------------------------
        // 5. INSERT new profile (FIXED)
        // ---------------------------
        const insertCols = ["user_id", "account_type"];
        const insertVals = [user_id, account_type];

        const maybeAdd = (column, value) => {
            if (typeof value !== "undefined") {
                insertCols.push(column);
                insertVals.push(value);
            }
        };

        maybeAdd("location", location);
        maybeAdd("stage_name", stage_name);
        maybeAdd("fee_range", fee_range);
        maybeAdd("bio", bio);
        maybeAdd("profile_pic", profile_pic);
        maybeAdd("banner_pic", banner_pic);
        maybeAdd("willing_to_travel", willing_to_travel);
        maybeAdd("genre", genre);
        maybeAdd("preferred_event_type", preferred_event_type);
        maybeAdd("email", email);
        maybeAdd("phone", phone);

        maybeAdd("artist_contact_person", artist_contact_person);
        maybeAdd("promoter_contact_person", promoter_contact_person);
        maybeAdd("venue_contact_person", venue_contact_person);
        maybeAdd("manager_email", manager_email);
        maybeAdd("manager_phone", manager_phone);

        maybeAdd("company_name", company_name);

        maybeAdd("venue_name", venue_name);
        maybeAdd("venue_capacity", venue_capacity);
        maybeAdd("opening_hours", opening_hours);
        maybeAdd("type_of_venue", type_of_venue);
        maybeAdd("venue_email", venue_email);
        maybeAdd("venue_address", venue_address);
        maybeAdd("venue_phone", venue_phone);

        const placeholders = insertCols.map(() => "?").join(", ");

        const sqlInsert = `
            INSERT INTO profile (${insertCols.join(", ")}, created_at, updated_at)
            VALUES (${placeholders}, NOW(), NOW())
        `;

        const [result] = await db.query(sqlInsert, insertVals);

        return res.status(200).json({
            success: true,
            message: `${account_type} profile created successfully`,
            profile_id: result.insertId
        });

    } catch (error) {
        console.error("Profile Save Error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error",
            error: error.message
        });
    }
});


// ------------------------------------------------
// GET SINGLE PROFILE BY ID (Protected)
// ------------------------------------------------
app.get("/api/profile/:profile_id", verifyToken, async (req, res) => {
    try {
        const { profile_id } = req.params;

        // Validate profile_id
        if (!profile_id || isNaN(profile_id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid or missing profile_id"
            });
        }

        /* -------------------------------
           1. Fetch profile + ownership
        -------------------------------- */
        const [profileRows] = await db.query(
            "SELECT * FROM profile WHERE id = ? LIMIT 1",
            [profile_id]
        );

        if (profileRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Profile not found"
            });
        }

        const profile = profileRows[0];

        // Ownership check
        if (profile.user_id !== req.user.user_id) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized: You can access only your own profile"
            });
        }

        /* -------------------------------
           2. Fetch profile media
        -------------------------------- */
        const [mediaRows] = await db.query(
            `SELECT id, media_type, media_url, created_at
             FROM profile_media
             WHERE profile_id = ?
             ORDER BY id DESC`,
            [profile_id]
        );

        /* -------------------------------
           3. Fetch social links
        -------------------------------- */
        const [socialRows] = await db.query(
            `SELECT 
                id, website_url, instagram_url, facebook_url, youtube_url,
                spotify_url, tiktok_url, twitter_url, other_url,
                created_at, updated_at
             FROM profile_social_links
             WHERE profile_id = ?
             LIMIT 1`,
            [profile_id]
        );

        /* -------------------------------
           4. Response
        -------------------------------- */
        return res.status(200).json({
            success: true,
            message: "Profile data fetched successfully",
            data: {
                profile,
                media: mediaRows || [],
                social_links: socialRows.length ? socialRows[0] : {}
            }
        });

    } catch (error) {
        console.error("Full Profile Fetch Error:", error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
            error: error.message
        });
    }
});


// --------------------------------------------------------------
// ADD PROFILE MEDIA (images/videos)
// --------------------------------------------------------------
app.post("/api/profile/media", verifyToken, async (req, res) => {
    try {
        const { profile_id, user_id, media } = req.body;

        /*
            media = [
                { media_type: "image", media_url: "img1.jpg" },
                { media_type: "video", media_url: "video1.mp4" }
            ]
        */

        // -----------------------------
        // 1. Validate Required Fields
        // -----------------------------
        if (!profile_id || !user_id || !Array.isArray(media)) {
            return res.status(400).json({
                success: false,
                message: "profile_id, user_id and media array are required"
            });
        }

        if (media.length === 0) {
            return res.status(400).json({
                success: false,
                message: "media array cannot be empty"
            });
        }

        // -----------------------------
        // 2. Check user ownership
        // -----------------------------
        const [profile] = await db.query(
            "SELECT user_id FROM profile WHERE id = ? LIMIT 1",
            [profile_id]
        );

        if (profile.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Profile not found"
            });
        }

        if (profile[0].user_id !== user_id) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized: You can add media only to your own profile"
            });
        }

        // -----------------------------
        // 3. Insert media entries
        // -----------------------------
        const insertValues = [];
        const placeholders = [];

        for (const item of media) {
            if (!item.media_type || !item.media_url) continue;

            if (!["image", "video"].includes(item.media_type)) {
                return res.status(400).json({
                    success: false,
                    message: "media_type must be image or video"
                });
            }

            placeholders.push("(?, ?, ?, NOW())");
            insertValues.push(profile_id, item.media_type, item.media_url);
        }

        if (placeholders.length === 0) {
            return res.status(400).json({
                success: false,
                message: "No valid media items provided"
            });
        }

        const sql = `
            INSERT INTO profile_media (profile_id, media_type, media_url, created_at)
            VALUES ${placeholders.join(", ")}
        `;

        await db.query(sql, insertValues);

        // -----------------------------
        // 4. Fetch updated media list
        // -----------------------------
        const [updatedMedia] = await db.query(
            "SELECT * FROM profile_media WHERE profile_id = ? ORDER BY id DESC",
            [profile_id]
        );

        return res.status(200).json({
            success: true,
            message: "Media uploaded successfully",
            media: updatedMedia
        });

    } catch (error) {
        console.error("Profile Media Save Error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error",
            error: error.message
        });
    }
});


// -----------------------------------------------
// SAVE / UPDATE SOCIAL LINKS
// -----------------------------------------------
app.post("/api/profile/social-links", verifyToken, async (req, res) => {
    try {
        const {
            profile_id,
            website_url,
            instagram_url,
            facebook_url,
            youtube_url,
            spotify_url,
            tiktok_url,
            twitter_url,
            other_url
        } = req.body;

        // -----------------------------------
        // 1. Validate input
        // -----------------------------------
        if (!profile_id) {
            return res.status(400).json({
                success: false,
                message: "profile_id is required"
            });
        }

        // -----------------------------------
        // 2. Check profile ownership
        // -----------------------------------
        const [profile] = await db.query(
            `SELECT user_id FROM profile WHERE id = ? LIMIT 1`,
            [profile_id]
        );

        if (profile.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Profile not found"
            });
        }

        // Only owner can update
        if (profile[0].user_id !== req.user.user_id) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized: You can update only your own social links"
            });
        }

        // -----------------------------------
        // 3. Check if existing social links exist
        // -----------------------------------
        const [existing] = await db.query(
            `SELECT id FROM profile_social_links WHERE profile_id = ? LIMIT 1`,
            [profile_id]
        );

        // -----------------------------------
        // Prepare values for insert/update
        // -----------------------------------
        const values = [
            website_url || null,
            instagram_url || null,
            facebook_url || null,
            youtube_url || null,
            spotify_url || null,
            tiktok_url || null,
            twitter_url || null,
            other_url || null
        ];

        // -----------------------------------
        // 4. UPDATE
        // -----------------------------------
        if (existing.length > 0) {
            await db.query(
                `UPDATE profile_social_links 
                 SET website_url=?, instagram_url=?, facebook_url=?, youtube_url=?, 
                     spotify_url=?, tiktok_url=?, twitter_url=?, other_url=?, updated_at = NOW()
                 WHERE profile_id = ?`,
                [...values, profile_id]
            );

            return res.status(200).json({
                success: true,
                message: "Profile social links updated successfully"
            });
        }

        // -----------------------------------
        // 5. INSERT
        // -----------------------------------
        await db.query(
            `INSERT INTO profile_social_links 
                (profile_id, website_url, instagram_url, facebook_url, youtube_url, 
                 spotify_url, tiktok_url, twitter_url, other_url, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
            [profile_id, ...values]
        );

        return res.status(200).json({
            success: true,
            message: "Profile social links created successfully"
        });

    } catch (error) {
        console.error("Social Links Save Error:", error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
            error: error.message
        });
    }
});


// ---------------------------------------------------------
// CREATE EVENT
// ---------------------------------------------------------
app.post("/api/create-event", verifyToken, async (req, res) => {
    const conn = await db.getConnection();

    try {
        const {
            creator_user_id,
            event_title,
            where_to_host,
            preferred_day,
            start_date_and_time,
            end_date_and_time,
            type_of_event,
            type_of_artist,
            reason_for_event,
            equipment_for_event,
            open_artist_public_request,
            event_manager_name,
            event_manager_phone,
            event_manager_email
        } = req.body;

        // ---------------------- VALIDATIONS ----------------------

        if (!creator_user_id) {
            return res.status(400).json({
                status: "failed",
                message: "creator_user_id is required"
            });
        }

        // user can create only their own event
        if (req.user.user_id !== creator_user_id) {
            return res.status(403).json({
                status: "failed",
                message: "Unauthorized: You can create only your own event"
            });
        }

        if (!event_title || event_title.trim() === "") {
            return res.status(400).json({
                status: "failed",
                message: "event_title is required"
            });
        }

        if (!where_to_host) {
            return res.status(400).json({
                status: "failed",
                message: "where_to_host is required"
            });
        }

        if (!preferred_day) {
            return res.status(400).json({
                status: "failed",
                message: "preferred_day is required"
            });
        }

        // Date validation
        if (!start_date_and_time) {
            return res.status(400).json({
                status: "failed",
                message: "start_date_and_time is required"
            });
        }

        await conn.beginTransaction();

        // ---------------------- INSERT EVENT ----------------------
        const [result] = await conn.execute(
            `INSERT INTO events (
                creator_user_id, event_title, where_to_host, preferred_day,
                start_date_and_time, end_date_and_time, type_of_event,
                type_of_artist, reason_for_event, equipment_for_event,
                open_artist_public_request, event_manager_name,
                event_manager_phone, event_manager_email, created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW()
            )`,
            [
                creator_user_id,
                event_title,
                where_to_host,
                preferred_day,
                start_date_and_time,
                end_date_and_time,
                type_of_event,
                type_of_artist,
                reason_for_event,
                equipment_for_event,
                open_artist_public_request ?? 0,
                event_manager_name,
                event_manager_phone,
                event_manager_email
            ]
        );

        await conn.commit();

        return res.status(200).json({
            success: true,
            message: "Event created successfully",
            event_id: result.insertId
        });

    } catch (error) {
        await conn.rollback();
        console.error("Create Event Error:", error);
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});


// ---------------------------------------------
// CREATE OR UPDATE EVENT INVITE
// ---------------------------------------------
app.post("/api/event-invites", verifyToken, async (req, res) => {
    const conn = await db.getConnection();
    try {
        const {
            invite_id,
            event_id,
            profile_id,
            profile_type,
            draft_set_times,
            stage_name,
            status,
            confirmation,
            notes_for_artist,
            notes_for_venues
        } = req.body;

        // ---------------- VALIDATION ----------------
        if (!event_id || !profile_id || !profile_type) {
            return res.status(400).json({
                status: "failed",
                message: "event_id, profile_id and profile_type are required"
            });
        }

        if (!["artist", "venue"].includes(profile_type)) {
            return res.status(400).json({
                status: "failed",
                message: "profile_type must be 'artist' or 'venue'"
            });
        }

        // Verify user owns the event
        const [event] = await conn.execute(
            "SELECT creator_user_id FROM events WHERE id = ? LIMIT 1",
            [event_id]
        );

        if (event.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "Event not found"
            });
        }

        if (event[0].creator_user_id !== req.user.user_id) {
            return res.status(403).json({
                status: "failed",
                message: "Unauthorized: Only event creator can invite"
            });
        }

        await conn.beginTransaction();

        // If invite_id is passed → UPDATE
        if (invite_id) {
            await conn.execute(
                `UPDATE event_invites SET
                    profile_id = ?, 
                    profile_type = ?, 
                    draft_set_times = ?, 
                    stage_name = ?, 
                    status = ?, 
                    confirmation = ?, 
                    notes_for_artist = ?, 
                    notes_for_venues = ?, 
                    updated_at = NOW()
                WHERE id = ? AND event_id = ?`,
                [
                    profile_id,
                    profile_type,
                    draft_set_times,
                    stage_name,
                    status,
                    confirmation,
                    notes_for_artist,
                    notes_for_venues,
                    invite_id,
                    event_id
                ]
            );

            await conn.commit();

            return res.status(200).json({
                status: "success",
                message: "Invite updated successfully",
                invite_id
            });
        }

        // Otherwise → CREATE NEW invite
        const [result] = await conn.execute(
            `INSERT INTO event_invites
            (event_id, profile_id, profile_type, draft_set_times, stage_name, status, confirmation,
             notes_for_artist, notes_for_venues, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
            [
                event_id,
                profile_id,
                profile_type,
                draft_set_times,
                stage_name,
                status || null,
                confirmation || null,
                notes_for_artist,
                notes_for_venues
            ]
        );

        await conn.commit();

        return res.status(201).json({
            status: "success",
            message: "Invite created successfully",
            invite_id: result.insertId
        });

    } catch (error) {
        await conn.rollback();
        console.error("Event Invite Error:", error);
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});



// ---------------------------------------------
// SAVE EVENT MEDIA
// ---------------------------------------------
app.post("/api/event-media", verifyToken, async (req, res) => {
    const conn = await db.getConnection();

    try {
        const { event_id, images, videos, banner_image } = req.body;

        // -----------------------------
        // REQUIRED FIELD CHECK
        // -----------------------------
        if (!event_id) {
            return res.status(400).json({
                status: "error",
                message: "event_id is required"
            });
        }

        // -----------------------------
        // CHECK EVENT EXISTS
        // -----------------------------
        const [eventCheck] = await conn.execute(
            "SELECT id FROM events WHERE id = ? LIMIT 1",
            [event_id]
        );

        if (eventCheck.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Event not found"
            });
        }

        // No media sent → success but do nothing
        if (!images && !videos && !banner_image) {
            return res.status(200).json({
                status: "success",
                message: "No media sent. Nothing to update."
            });
        }

        const imageList = images ? images.split(",") : [];
        const videoList = videos ? videos.split(",") : [];
        const bannerList = banner_image ? [banner_image] : [];

        await conn.beginTransaction();

        // -----------------------------
        // SAVE IMAGES
        // -----------------------------
        for (let url of imageList) {
            if (!url || !url.trim()) continue;

            await conn.execute(
                `INSERT INTO event_media (event_id, media_type, media_url, created_at) 
                 VALUES (?, 'image', ?, NOW())`,
                [event_id, url.trim()]
            );
        }

        // -----------------------------
        // SAVE VIDEOS
        // -----------------------------
        for (let url of videoList) {
            if (!url || !url.trim()) continue;

            await conn.execute(
                `INSERT INTO event_media (event_id, media_type, media_url, created_at) 
                 VALUES (?, 'video', ?, NOW())`,
                [event_id, url.trim()]
            );
        }

        // -----------------------------
        // SAVE BANNER IMAGE (ONLY ONE)
        // -----------------------------
        if (bannerList.length > 0) {

            // Delete old banner image
            await conn.execute(
                `DELETE FROM event_media 
                 WHERE event_id = ? AND media_type = 'banner_image'`,
                [event_id]
            );

            // Insert new one
            await conn.execute(
                `INSERT INTO event_media (event_id, media_type, media_url, created_at)
                 VALUES (?, 'banner_image', ?, NOW())`,
                [event_id, bannerList[0].trim()]
            );
        }

        await conn.commit();

        return res.status(200).json({
            status: "success",
            message: "Event media saved successfully"
        });

    } catch (error) {
        await conn.rollback();
        console.error("Media Save Error:", error);

        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});



// ---------------------------------------------
// SAVE EVENT Tickets
// ---------------------------------------------
app.post("/api/event-tickets", verifyToken, async (req, res) => {
    const conn = await db.getConnection();

    try {
        const { event_id, tickets } = req.body;

        // -----------------------------
        // VALIDATION
        // -----------------------------
        if (!event_id) {
            return res.status(400).json({
                status: "error",
                message: "event_id is required"
            });
        }

        if (!tickets || !Array.isArray(tickets) || tickets.length === 0) {
            return res.status(400).json({
                status: "error",
                message: "tickets array is required"
            });
        }

        // -----------------------------
        // CHECK EVENT EXISTS
        // -----------------------------
        const [eventCheck] = await conn.execute(
            "SELECT id FROM events WHERE id = ? LIMIT 1",
            [event_id]
        );

        if (eventCheck.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Event not found"
            });
        }

        await conn.beginTransaction();

        // -----------------------------
        // INSERT TICKETS
        // -----------------------------
        for (let t of tickets) {
            const { ticket_date, ticket_type, ticket_price, visibility, location } = t;

            await conn.execute(
                `INSERT INTO event_tickets 
                (event_id, ticket_date, ticket_type, ticket_price, visibility, location, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, NOW())`,
                [
                    event_id,
                    ticket_date || null,
                    ticket_type || null,
                    ticket_price || 0,
                    visibility || 0,
                    location || null
                ]
            );
        }

        await conn.commit();

        return res.status(200).json({
            status: "success",
            message: "Event tickets saved successfully"
        });

    } catch (error) {
        await conn.rollback();
        console.error("Ticket Save Error:", error);

        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});


// ---------------------------------------------
// GET EVENT Details
// ---------------------------------------------
app.get("/api/events/:event_id", verifyToken, async (req, res) => {
    const conn = await db.getConnection();

    try {
        const event_id = req.params.event_id;

        if (!event_id) {
            return res.status(400).json({
                status: "error",
                message: "event_id is required"
            });
        }

        // -----------------------------
        // FETCH EVENT DETAILS
        // -----------------------------
        const [eventRows] = await conn.execute(
            "SELECT * FROM events WHERE id = ? LIMIT 1",
            [event_id]
        );

        if (eventRows.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Event not found"
            });
        }

        return res.status(200).json({
            status: "success",
            event: eventRows[0]
        });

    } catch (error) {
        console.error("Get Event Error:", error);
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});


// ---------------------------------------------
// GET EVENT Media
// ---------------------------------------------
app.get("/api/event-media/:event_id", verifyToken, async (req, res) => {
    const conn = await db.getConnection();

    try {
        const event_id = req.params.event_id;

        if (!event_id) {
            return res.status(400).json({
                status: "error",
                message: "event_id is required"
            });
        }

        // -----------------------------------------------------
        // CHECK IF EVENT EXISTS
        // -----------------------------------------------------
        const [eventRows] = await conn.execute(
            "SELECT id FROM events WHERE id = ? LIMIT 1",
            [event_id]
        );

        if (eventRows.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Event not found"
            });
        }

        // -----------------------------------------------------
        // GET ALL MEDIA FOR EVENT
        // -----------------------------------------------------
        const [mediaRows] = await conn.execute(
            "SELECT id, media_type, media_url, created_at FROM event_media WHERE event_id = ? ORDER BY id DESC",
            [event_id]
        );

        // Group media by type
        const banner_image = mediaRows.find(m => m.media_type === "banner_image") || null;
        const images = mediaRows.filter(m => m.media_type === "image");
        const videos = mediaRows.filter(m => m.media_type === "video");

        return res.status(200).json({
            status: "success",
            event_id,
            banner_image,
            images,
            videos
        });

    } catch (error) {
        console.error("Get Event Media Error:", error);
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});



// ---------------------------------------------
// GET EVENT tickets
// ---------------------------------------------
app.get("/api/event-tickets/:event_id", verifyToken, async (req, res) => {
    const conn = await db.getConnection();

    try {
        const event_id = req.params.event_id;

        if (!event_id) {
            return res.status(400).json({
                status: "error",
                message: "event_id is required"
            });
        }

        // --------------------------------------------
        // CHECK EVENT EXISTS
        // --------------------------------------------
        const [eventRows] = await conn.execute(
            "SELECT id FROM events WHERE id = ? LIMIT 1",
            [event_id]
        );

        if (eventRows.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Event not found"
            });
        }

        // --------------------------------------------
        // GET ALL TICKETS FOR EVENT
        // --------------------------------------------
        const [ticketRows] = await conn.execute(
            `SELECT id, event_id, ticket_date, ticket_type, ticket_price, visibility, location, created_at, updated_at
             FROM event_tickets 
             WHERE event_id = ?
             ORDER BY ticket_date ASC, id DESC`,
            [event_id]
        );

        return res.status(200).json({
            status: "success",
            event_id,
            tickets: ticketRows
        });

    } catch (error) {
        console.error("Get Event Tickets Error:", error);
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});


// ---------------------------------------------
// GET EVENT invites
// ---------------------------------------------
app.get("/api/event-invites/:event_id", verifyToken, async (req, res) => {
    const conn = await db.getConnection();

    try {
        const event_id = req.params.event_id;

        if (!event_id) {
            return res.status(400).json({
                status: "error",
                message: "event_id is required"
            });
        }

        // --------------------------------------------
        // CHECK IF EVENT EXISTS
        // --------------------------------------------
        const [eventRows] = await conn.execute(
            "SELECT id FROM events WHERE id = ? LIMIT 1",
            [event_id]
        );

        if (eventRows.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Event not found"
            });
        }

        // --------------------------------------------
        // GET EVENT INVITES
        // --------------------------------------------
        const [inviteRows] = await conn.execute(
            `SELECT id, event_id, profile_id, profile_type, draft_set_times, stage_name, status, confirmation, 
                    notes_for_artist, notes_for_venues, created_at, updated_at
             FROM event_invites
             WHERE event_id = ?
             ORDER BY id DESC`,
            [event_id]
        );

        return res.status(200).json({
            status: "success",
            event_id,
            invites: inviteRows
        });

    } catch (error) {
        console.error("Get Event Invites Error:", error);
        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});



// ---------------------------------------------
// Save collab request
// ---------------------------------------------
app.post("/api/collab-requests", verifyToken, async (req, res) => {
    const conn = await db.getConnection();

    try {
        const { sender_user_id, receiver_user_id, message } = req.body;

        // -------------------------------
        // VALIDATION
        // -------------------------------
        if (!sender_user_id || !receiver_user_id) {
            return res.status(400).json({
                status: "error",
                message: "sender_user_id and receiver_user_id are required"
            });
        }

        // Ensure user is sending request from their own account
        if (req.user.user_id !== sender_user_id) {
            return res.status(403).json({
                status: "error",
                message: "Unauthorized: You can send requests only from your own account"
            });
        }

        // Cannot send a request to yourself
        if (sender_user_id === receiver_user_id) {
            return res.status(400).json({
                status: "error",
                message: "You cannot send a request to yourself"
            });
        }

        // -------------------------------
        // INSERT INTO DATABASE
        // -------------------------------
        const [result] = await conn.execute(
            `INSERT INTO collab_requests 
                (sender_user_id, receiver_user_id, message, status, created_at, updated_at)
             VALUES (?, ?, ?, 'pending', NOW(), NOW())`,
            [sender_user_id, receiver_user_id, message || null]
        );

        const insertedId = result.insertId;

        return res.status(200).json({
            status: "success",
            message: "Collaboration request sent successfully",
            request_id: insertedId
        });

    } catch (error) {
        console.error("Collab Request Error:", error);

        return res.status(500).json({
            status: "error",
            message: "Server error",
            error: error.message
        });
    } finally {
        conn.release();
    }
});


// ------------------------------------------------
// GET PROFILES WITH FILTERS + PAGINATION (Protected)
// ------------------------------------------------
app.get("/api/profiles", verifyToken, async (req, res) => {
    const {
        stage_name,
        genre,
        location,
        account_type,
        page = 1
    } = req.query;

    const limit = 16;
    const offset = (parseInt(page) - 1) * limit;

    try {
        let whereSql = " WHERE 1=1 ";
        const params = [];

        // ---------- Filters ----------
        if (stage_name) {
            whereSql += " AND stage_name LIKE ?";
            params.push(`%${stage_name}%`);
        }

        if (genre) {
            whereSql += " AND genre LIKE ?";
            params.push(`%${genre}%`);
        }

        if (location) {
            whereSql += " AND `location` LIKE ?";
            params.push(`%${location}%`);
        }

        if (account_type) {
            whereSql += " AND account_type LIKE ?";
            params.push(`%${account_type}%`);
        }

        // ---------- Total count ----------
        const countSql = `SELECT COUNT(*) AS total FROM profile ${whereSql}`;
        const [[{ total }]] = await db.query(countSql, params);

        // ---------- Paginated data ----------
        const dataSql = `
            SELECT *
            FROM profile
            ${whereSql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        `;

        const dataParams = [...params, limit, offset];
        const [rows] = await db.query(dataSql, dataParams);

        return res.json({
            status: "success",
            page: parseInt(page),
            per_page: limit,
            total,
            total_pages: Math.ceil(total / limit),
            count: rows.length,
            profiles: rows
        });

    } catch (err) {
        console.error("Error fetching profiles:", err.message);
        return res.status(500).json({
            status: "error",
            message: "Database error",
            error: err.message
        });
    }
});


// ------------------------------------------------
// GET EVENTS WITH SEARCH / FILTERS / PAGINATION
// ------------------------------------------------
app.get("/api/events", verifyToken, async (req, res) => {
    const {
        search,                   // global text search
        event_title,              // specific title search
        type_of_event,
        type_of_artist,
        preferred_day,
        where_to_host,
        open_artist_public_request, // 0 or 1
        from_date,                // YYYY-MM-DD
        to_date,                  // YYYY-MM-DD
        page = 1                  // pagination
    } = req.query;

    const limit = 16;
    const offset = (parseInt(page) - 1) * limit;

    try {
        let whereSql = " WHERE 1=1 ";
        const params = [];

        // ---------- Global text search ----------
        if (search) {
            whereSql += `
                AND (
                    event_title LIKE ?
                    OR where_to_host LIKE ?
                    OR preferred_day LIKE ?
                    OR type_of_event LIKE ?
                    OR type_of_artist LIKE ?
                    OR reason_for_event LIKE ?
                    OR equipment_for_event LIKE ?
                    OR event_manager_name LIKE ?
                    OR event_manager_phone LIKE ?
                    OR event_manager_email LIKE ?
                )
            `;
            const s = `%${search}%`;
            params.push(s, s, s, s, s, s, s, s, s, s);
        }

        // ---------- Event title filter ----------
        if (event_title) {
            whereSql += " AND event_title LIKE ?";
            params.push(`%${event_title}%`);
        }

        // ---------- Extra filters ----------
        if (type_of_event) {
            whereSql += " AND type_of_event LIKE ?";
            params.push(`%${type_of_event}%`);
        }

        if (type_of_artist) {
            whereSql += " AND type_of_artist LIKE ?";
            params.push(`%${type_of_artist}%`);
        }

        if (preferred_day) {
            whereSql += " AND preferred_day LIKE ?";
            params.push(`%${preferred_day}%`);
        }

        if (where_to_host) {
            whereSql += " AND where_to_host LIKE ?";
            params.push(`%${where_to_host}%`);
        }

        if (open_artist_public_request !== undefined) {
            whereSql += " AND open_artist_public_request = ?";
            params.push(open_artist_public_request);
        }

        // ---------- Date range filter ----------
        if (from_date) {
            whereSql += " AND start_date_and_time >= ?";
            params.push(`${from_date} 00:00:00`);
        }

        if (to_date) {
            whereSql += " AND start_date_and_time <= ?";
            params.push(`${to_date} 23:59:59`);
        }

        // ---------- Total count ----------
        const countSql = `SELECT COUNT(*) as total FROM events ${whereSql}`;
        const [[{ total }]] = await db.query(countSql, params);

        // ---------- Paginated data ----------
        const dataSql = `
            SELECT *
            FROM events
            ${whereSql}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        `;

        const dataParams = [...params, limit, offset];
        const [rows] = await db.query(dataSql, dataParams);

        return res.json({
            status: "success",
            page: parseInt(page),
            per_page: limit,
            total,
            total_pages: Math.ceil(total / limit),
            count: rows.length,
            events: rows
        });

    } catch (err) {
        console.error("Error fetching events:", err.message);
        return res.status(500).json({
            status: "error",
            message: "Database error",
            error: err.message
        });
    }
});


// ------------------------------------------------
// DELETE PROFILE MEDIA BY media_id (Protected)
// ------------------------------------------------
app.delete("/api/profile/media/:media_id", verifyToken, async (req, res) => {
    try {
        const { media_id } = req.params;

        if (!media_id) {
            return res.status(400).json({
                status: "failed",
                message: "media_id is required"
            });
        }

        // Check if media exists
        const [rows] = await db.query(
            "SELECT * FROM profile_media WHERE id = ?",
            [media_id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "Media not found"
            });
        }

        // Delete media
        await db.query("DELETE FROM profile_media WHERE id = ?", [media_id]);

        return res.json({
            status: "success",
            message: "Media deleted successfully"
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