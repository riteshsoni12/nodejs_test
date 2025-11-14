const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const JWT_SECRET = "OsCkXG75VhqWo"; // change this

// ------------------------------------------------
// 1️ API: Generate Token (NO LOGIN REQUIRED)
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
        req.user = decoded; // store decoded data
        next();
    } catch (error) {
        return res.status(403).json({
            status: "failed",
            message: "Invalid or expired token"
        });
    }
}

// ------------------------------------------------
// 2️ API: Get User Profile (Requires Token)
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
// 3️ API: Get Products (Requires Token)
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
app.listen(3000, () => console.log("API running on http://localhost:3000"));