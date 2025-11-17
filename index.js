const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");

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
// 1️ Generate JWT Token
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
// 2️ User Profile (Protected)
// ------------------------------------------------
app.get("/user-profile", verifyToken, (req, res) => {
    return res.json({
        status: "success",
        message: "User profile data",
        data: {
            user_id: req.user.user_id,
            name: "John Doe",
            email: "john@example.com"
        }
    });
});

// ------------------------------------------------
// 3️ Products (Protected)
// ------------------------------------------------
app.get("/products", verifyToken, (req, res) => {
    return res.json({
        status: "success",
        products: [
            { id: 1, name: "Product One", price: 100 },
            { id: 2, name: "Product Two", price: 200 }
        ]
    });
});

// ------------------------------------------------
// 4️ GET USERS FROM HOSTINGER DATABASE (Protected)
// ------------------------------------------------
app.get("/users", verifyToken, async (req, res) => {
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
app.listen(3000, () => console.log("API running on http://localhost:3000"));