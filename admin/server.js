
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const bcrypt = require("bcrypt");
const session = require("express-session");

const db = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;

const production = process.env.NODE_ENV === "production";

if (production && !process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET is required.");
}

app.set("trust proxy", 1);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
    name: "tourguide.sid",
    secret: process.env.SESSION_SECRET ||
        "local-development-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: production,
        sameSite: "lax",
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// DATABASE: USERS TABLE

db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`, (err) => {
    if (err) {
        console.error("Users table error:", err.message);
    } else {
        console.log("Users table ready");
    }
});

// UPLOAD CONFIGURATION

const uploadFolder = process.env.UPLOADS_DIR ||
    path.join(__dirname, "uploads");

fs.mkdirSync(uploadFolder, { recursive: true });

const allowedTypes = [
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "video/mp4",
    "video/webm",
    "video/ogg"
];

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadFolder);
    },

    filename: (req, file, cb) => {
        const uniqueName =
            Date.now() + "-" +
            Math.round(Math.random() * 1e9) +
            path.extname(file.originalname).toLowerCase();

        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,

    limits: {
        fileSize: 100 * 1024 * 1024
    },

    fileFilter: (req, file, cb) => {
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error("Only images and videos are allowed."));
        }
    }
});

// AUTHENTICATION HELPERS

function requireAdmin(req, res, next) {
    if (!req.session.admin) {
        return res.redirect("/admin-login.html");
    }
    next();
}

function requireSuperAdmin(req, res, next) {
    if (
        !req.session.admin ||
        req.session.admin.role !== "superadmin"
    ) {
        return res.status(403).json({
            success: false,
            message: "Super Admin access required."
        });
    }
    next();
}

function regenerateSession(req) {
    return new Promise((resolve, reject) => {
        req.session.regenerate(err => {
            if (err) reject(err);
            else resolve();
        });
    });
}

// =====================================================
// USER REGISTRATION
// =====================================================

app.post("/register", (req, res) => {

    const {
        fullname,
        email,
        password,
        confirmPassword
    } = req.body;

    if (!fullname || !email || !password || !confirmPassword) {
        return res.status(400).send("All fields are required.");
    }

    if (password !== confirmPassword) {
        return res.status(400).send("Passwords do not match.");
    }

    if (password.length < 6) {
        return res.status(400).send(
            "Password must be at least 6 characters."
        );
    }

    const normalizedEmail = email.trim().toLowerCase();

    db.get(
        "SELECT id FROM users WHERE email = ?",
        [normalizedEmail],
        async (err, user) => {

            if (err) {
                console.error(err);
                return res.status(500).send("Registration failed.");
            }

            if (user) {
                return res.status(409).send(
                    'Email already registered. <a href="/login.html">Login</a>'
                );
            }

            try {
                const hashedPassword = await bcrypt.hash(password, 10);

                db.run(
                    `INSERT INTO users (fullname, email, password)
                     VALUES (?, ?, ?)`,
                    [fullname.trim(), normalizedEmail, hashedPassword],
                    function(insertErr) {

                        if (insertErr) {
                            console.error(insertErr);
                            return res.status(500).send(
                                "Registration failed."
                            );
                        }

                        res.redirect("/login.html");
                    }
                );

            } catch (error) {
                console.error(error);
                res.status(500).send("Registration failed.");
            }
        }
    );
});

// =====================================================
// USER LOGIN
// =====================================================

app.post("/login", (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send(
            "Email and password are required."
        );
    }

    db.get(
        "SELECT * FROM users WHERE email = ?",
        [email.trim().toLowerCase()],
        async (err, user) => {

            if (err) {
                console.error(err);
                return res.status(500).send("Login failed.");
            }

            if (!user) {
                return res.status(401).send(
                    "Invalid email or password."
                );
            }

            try {
                const passwordMatch = await bcrypt.compare(
                    password,
                    user.password
                );

                if (!passwordMatch) {
                    return res.status(401).send(
                        "Invalid email or password."
                    );
                }

                await regenerateSession(req);

                req.session.user = {
                    id: user.id,
                    fullname: user.fullname,
                    email: user.email
                };

                res.redirect("/booking.html");

            } catch (error) {
                console.error(error);
                res.status(500).send("Login failed.");
            }
        }
    );
});

// =====================================================
// USER LOGOUT
// =====================================================

app.get("/logout", (req, res) => {

    req.session.destroy(err => {

        if (err) {
            return res.status(500).send("Logout failed.");
        }

        res.clearCookie("tourguide.sid");
        res.redirect("/");

    });
});

// =====================================================
// ADMIN LOGIN
// =====================================================

app.post("/admin-login", async (req, res) => {

    const { username, password } = req.body;

    let role = null;

    if (
        username === process.env.ADMIN_USERNAME &&
        password === process.env.ADMIN_PASSWORD
    ) {
        role = "admin";

    } else if (
        username === process.env.SUPERADMIN_USERNAME &&
        password === process.env.SUPERADMIN_PASSWORD
    ) {
        role = "superadmin";
    }

    if (!role) {
        return res.status(401).send(
            'Wrong username or password. <a href="/admin-login.html">Try again</a>'
        );
    }

    try {
        await regenerateSession(req);

        req.session.admin = {
            username,
            role
        };

        res.redirect("/dashboard.html");

    } catch (error) {
        console.error(error);
        res.status(500).send("Admin login failed.");
    }
});

// =====================================================
// ADMIN LOGOUT
// =====================================================

app.get("/admin-logout", (req, res) => {

    req.session.destroy(err => {

        if (err) {
            return res.status(500).send("Logout failed.");
        }

        res.clearCookie("tourguide.sid");
        res.redirect("/admin-login.html");

    });
});

// =====================================================
// ADMIN DASHBOARD PROTECTION
// =====================================================

app.get("/dashboard.html", requireAdmin, (req, res) => {

    res.sendFile(path.join(__dirname, "dashboard.html"));

});

app.get("/admin/dashboard.html", requireAdmin, (req, res) => {

    res.redirect("/dashboard.html");

});

// =====================================================
// CURRENT ADMIN
// =====================================================

app.get("/current-admin", (req, res) => {

    if (!req.session.admin) {
        return res.status(401).json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,
        username: req.session.admin.username,
        role: req.session.admin.role
    });

});

// =====================================================
// BOOKINGS - ADMIN ONLY
// =====================================================

app.post("/book", (req, res) => {

    const {
        fullname,
        email,
        phone,
        destination,
        travelDate,
        guests,
        message
    } = req.body;

    if (
        !fullname ||
        !email ||
        !phone ||
        !destination ||
        !travelDate ||
        !guests
    ) {
        return res.status(400).send(
            "Please complete all required fields."
        );
    }

    db.run(
        `INSERT INTO bookings
        (fullname, email, phone, destination, travelDate, guests, message)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,

        [
            fullname,
            email,
            phone,
            destination,
            travelDate,
            guests,
            message || ""
        ],

        function(err) {

            if (err) {
                console.error(err);
                return res.status(500).send("Booking failed.");
            }

            res.send(`
                <h1>Booking Successful!</h1>
                <h2>Booking Number: DDT-${this.lastID}</h2>
                <p>Thank you ${escapeHtml(fullname)}.</p>
                <a href="/">Return Home</a>
            `);
        }
    );
});

// =====================================================
// GET BOOKINGS
// =====================================================

app.get("/bookings", requireAdmin, (req, res) => {

    db.all(
        "SELECT * FROM bookings ORDER BY id DESC",
        [],
        (err, rows) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: "Could not retrieve bookings."
                });
            }

            res.json(rows);
        }
    );
});

// =====================================================
// GET ALL ADVERTISEMENTS
// =====================================================

app.get("/advertisements", (req, res) => {

    db.all(
        "SELECT * FROM advertisements ORDER BY id DESC",
        [],
        (err, rows) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: "Could not retrieve advertisements."
                });
            }

            res.json(rows);
        }
    );
});

// =====================================================
// GET ACTIVE ADVERTISEMENTS
// =====================================================

app.get("/advertisements/active", (req, res) => {

    db.all(
        `SELECT * FROM advertisements
         WHERE status = 'published'
         AND (
             advertisement_type = 'permanent'
             OR (
                 advertisement_type = 'duration'
                 AND start_datetime <= datetime('now')
                 AND end_datetime >= datetime('now')
             )
         )
         ORDER BY id DESC`,
        [],
        (err, rows) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: "Could not retrieve advertisements."
                });
            }

            res.json(rows);
        }
    );
});

// =====================================================
// CREATE ADVERTISEMENT - SUPERADMIN ONLY
// =====================================================

app.post(
    "/advertisements",
    requireSuperAdmin,
    upload.single("media"),
    (req, res) => {

        const {
            title,
            description,
            price,
            advertisement_type,
            start_datetime,
            end_datetime
        } = req.body;

        if (!title || !description || !req.file) {

            if (req.file) {
                fs.unlink(req.file.path, () => {});
            }

            return res.status(400).json({
                success: false,
                message: "Title, description and media are required."
            });
        }

        if (!["permanent", "duration"].includes(advertisement_type)) {

            fs.unlink(req.file.path, () => {});

            return res.status(400).json({
                success: false,
                message: "Invalid advertisement type."
            });
        }

        if (
            advertisement_type === "duration" &&
            (!start_datetime || !end_datetime)
        ) {

            fs.unlink(req.file.path, () => {});

            return res.status(400).json({
                success: false,
                message: "Start and end dates are required."
            });
        }

        const mediaPath = "/uploads/" + req.file.filename;

        db.run(
            `INSERT INTO advertisements
            (
                title,
                description,
                price,
                media,
                media_type,
                advertisement_type,
                start_datetime,
                end_datetime,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,

            [
                title,
                description,
                price || "",
                mediaPath,
                req.file.mimetype,
                advertisement_type,
                advertisement_type === "permanent"
                    ? null
                    : start_datetime,
                advertisement_type === "permanent"
                    ? null
                    : end_datetime,
                "published"
            ],

            function(err) {

                if (err) {
                    console.error(err);
                    fs.unlink(req.file.path, () => {});

                    return res.status(500).json({
                        success: false,
                        message: "Failed to save advertisement."
                    });
                }

                res.json({
                    success: true,
                    message: "Advertisement published successfully.",
                    id: this.lastID
                });
            }
        );
    }
);

// =====================================================
// DELETE ADVERTISEMENT - SUPERADMIN ONLY
// =====================================================

app.delete(
    "/advertisements/:id",
    requireSuperAdmin,
    (req, res) => {

        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid advertisement ID."
            });
        }

        db.get(
            "SELECT media FROM advertisements WHERE id = ?",
            [id],
            (err, ad) => {

                if (err) {
                    console.error(err);
                    return res.status(500).json({
                        success: false,
                        message: "Database error."
                    });
                }

                if (!ad) {
                    return res.status(404).json({
                        success: false,
                        message: "Advertisement not found."
                    });
                }

                db.run(
                    "DELETE FROM advertisements WHERE id = ?",
                    [id],
                    function(deleteErr) {

                        if (deleteErr) {
                            console.error(deleteErr);
                            return res.status(500).json({
                                success: false,
                                message: "Could not delete advertisement."
                            });
                        }

                        if (ad.media) {
                            const filename = path.basename(ad.media);
                            const filePath = path.join(
                                uploadFolder,
                                filename
                            );

                            fs.unlink(filePath, fileErr => {
                                if (
                                    fileErr &&
                                    fileErr.code !== "ENOENT"
                                ) {
                                    console.error(fileErr);
                                }
                            });
                        }

                        res.json({
                            success: true,
                            message: "Advertisement deleted."
                        });
                    }
                );
            }
        );
    }
);

// =====================================================
// SERVE UPLOADED MEDIA
// =====================================================

app.use("/uploads", express.static(uploadFolder));

// =====================================================
// PROTECT PRIVATE FILES
// =====================================================

app.use((req, res, next) => {

    const blocked = [
        /^\/server\.js$/i,
        /^\/database\.js$/i,
        /^\/package(?:-lock)?\.json$/i,
        /^\/\.env/i
    ];

    if (blocked.some(pattern => pattern.test(req.path))) {
        return res.sendStatus(404);
    }

    next();
});

// =====================================================
// SERVE WEBSITE FILES
// =====================================================

app.use(express.static(__dirname, {
    index: false,
    dotfiles: "deny"
}));

// =====================================================
// HOMEPAGE
// =====================================================

app.get("/", (req, res) => {

    res.sendFile(path.join(__dirname, "index.html"));

});

// =====================================================
// ERROR HANDLING
// =====================================================

app.use((err, req, res, next) => {

    console.error("Server error:", err);

    if (
        err instanceof multer.MulterError ||
        err.message === "Only images and videos are allowed."
    ) {
        return res.status(400).json({
            success: false,
            message: err.message
        });
    }

    res.status(500).send(
        "An unexpected server error occurred."
    );
});

// =====================================================
// START SERVER FOR RENDER
// =====================================================

app.listen(PORT, "0.0.0.0", () => {

    console.log(
        `Tour Guide server running on port ${PORT}`
    );

});

// =====================================================
// BOOKINGS - ADMIN ONLY
// =====================================================

app.post("/book", (req, res) => {

    const {
        fullname,
        email,
        phone,
        destination,
        travelDate,
        guests,
        message
    } = req.body;

    if (
        !fullname ||
        !email ||
        !phone ||
        !destination ||
        !travelDate ||
        !guests
    ) {
        return res.status(400).send(
            "Please complete all required fields."
        );
    }

    db.run(
        `INSERT INTO bookings
        (fullname, email, phone, destination, travelDate, guests, message)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,

        [
            fullname,
            email,
            phone,
            destination,
            travelDate,
            guests,
            message || ""
        ],

        function(err) {

            if (err) {
                console.error(err);
                return res.status(500).send("Booking failed.");
            }

            res.send(`
                <h1>Booking Successful!</h1>
                <h2>Booking Number: DDT-${this.lastID}</h2>
                <p>Thank you ${escapeHtml(fullname)}.</p>
                <a href="/">Return Home</a>
            `);
        }
    );
});

// =====================================================
// GET BOOKINGS
// =====================================================

app.get("/bookings", requireAdmin, (req, res) => {

    db.all(
        "SELECT * FROM bookings ORDER BY id DESC",
        [],
        (err, rows) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: "Could not retrieve bookings."
                });
            }

            res.json(rows);
        }
    );
});

// =====================================================
// GET ALL ADVERTISEMENTS
// =====================================================

app.get("/advertisements", (req, res) => {

    db.all(
        "SELECT * FROM advertisements ORDER BY id DESC",
        [],
        (err, rows) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: "Could not retrieve advertisements."
                });
            }

            res.json(rows);
        }
    );
});

// =====================================================
// GET ACTIVE ADVERTISEMENTS
// =====================================================

app.get("/advertisements/active", (req, res) => {

    db.all(
        `SELECT * FROM advertisements
         WHERE status = 'published'
         AND (
             advertisement_type = 'permanent'
             OR (
                 advertisement_type = 'duration'
                 AND start_datetime <= datetime('now')
                 AND end_datetime >= datetime('now')
             )
         )
         ORDER BY id DESC`,
        [],
        (err, rows) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: "Could not retrieve advertisements."
                });
            }

            res.json(rows);
        }
    );
});

// =====================================================
// CREATE ADVERTISEMENT - SUPERADMIN ONLY
// =====================================================

app.post(
    "/advertisements",
    requireSuperAdmin,
    upload.single("media"),
    (req, res) => {

        const {
            title,
            description,
            price,
            advertisement_type,
            start_datetime,
            end_datetime
        } = req.body;

        if (!title || !description || !req.file) {

            if (req.file) {
                fs.unlink(req.file.path, () => {});
            }

            return res.status(400).json({
                success: false,
                message: "Title, description and media are required."
            });
        }

        if (!["permanent", "duration"].includes(advertisement_type)) {

            fs.unlink(req.file.path, () => {});

            return res.status(400).json({
                success: false,
                message: "Invalid advertisement type."
            });
        }

        if (
            advertisement_type === "duration" &&
            (!start_datetime || !end_datetime)
        ) {

            fs.unlink(req.file.path, () => {});

            return res.status(400).json({
                success: false,
                message: "Start and end dates are required."
            });
        }

        const mediaPath = "/uploads/" + req.file.filename;

        db.run(
            `INSERT INTO advertisements
            (
                title,
                description,
                price,
                media,
                media_type,
                advertisement_type,
                start_datetime,
                end_datetime,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,

            [
                title,
                description,
                price || "",
                mediaPath,
                req.file.mimetype,
                advertisement_type,
                advertisement_type === "permanent"
                    ? null
                    : start_datetime,
                advertisement_type === "permanent"
                    ? null
                    : end_datetime,
                "published"
            ],

            function(err) {

                if (err) {
                    console.error(err);
                    fs.unlink(req.file.path, () => {});

                    return res.status(500).json({
                        success: false,
                        message: "Failed to save advertisement."
                    });
                }

                res.json({
                    success: true,
                    message: "Advertisement published successfully.",
                    id: this.lastID
                });
            }
        );
    }
);

// =====================================================
// DELETE ADVERTISEMENT - SUPERADMIN ONLY
// =====================================================

app.delete(
    "/advertisements/:id",
    requireSuperAdmin,
    (req, res) => {

        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid advertisement ID."
            });
        }

        db.get(
            "SELECT media FROM advertisements WHERE id = ?",
            [id],
            (err, ad) => {

                if (err) {
                    console.error(err);
                    return res.status(500).json({
                        success: false,
                        message: "Database error."
                    });
                }

                if (!ad) {
                    return res.status(404).json({
                        success: false,
                        message: "Advertisement not found."
                    });
                }

                db.run(
                    "DELETE FROM advertisements WHERE id = ?",
                    [id],
                    function(deleteErr) {

                        if (deleteErr) {
                            console.error(deleteErr);
                            return res.status(500).json({
                                success: false,
                                message: "Could not delete advertisement."
                            });
                        }

                        if (ad.media) {
                            const filename = path.basename(ad.media);
                            const filePath = path.join(
                                uploadFolder,
                                filename
                            );

                            fs.unlink(filePath, fileErr => {
                                if (
                                    fileErr &&
                                    fileErr.code !== "ENOENT"
                                ) {
                                    console.error(fileErr);
                                }
                            });
                        }

                        res.json({
                            success: true,
                            message: "Advertisement deleted."
                        });
                    }
                );
            }
        );
    }
);

// =====================================================
// SERVE UPLOADED MEDIA
// =====================================================

app.use("/uploads", express.static(uploadFolder));

// =====================================================
// PROTECT PRIVATE FILES
// =====================================================

app.use((req, res, next) => {

    const blocked = [
        /^\/server\.js$/i,
        /^\/database\.js$/i,
        /^\/package(?:-lock)?\.json$/i,
        /^\/\.env/i
    ];

    if (blocked.some(pattern => pattern.test(req.path))) {
        return res.sendStatus(404);
    }

    next();
});

// =====================================================
// SERVE WEBSITE FILES
// =====================================================

app.use(express.static(__dirname, {
    index: false,
    dotfiles: "deny"
}));

// =====================================================
// HOMEPAGE
// =====================================================

app.get("/", (req, res) => {

    res.sendFile(path.join(__dirname, "index.html"));

});

// =====================================================
// ERROR HANDLING
// =====================================================

app.use((err, req, res, next) => {

    console.error("Server error:", err);

    if (
        err instanceof multer.MulterError ||
        err.message === "Only images and videos are allowed."
    ) {
        return res.status(400).json({
            success: false,
            message: err.message
        });
    }

    res.status(500).send(
        "An unexpected server error occurred."
    );
});

// =====================================================
// START SERVER FOR RENDER
// =====================================================

app.listen(PORT, "0.0.0.0", () => {

    console.log(
        `Tour Guide server running on port ${PORT}`
    );

});
