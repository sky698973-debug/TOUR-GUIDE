const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const bcrypt = require("bcrypt");
const session = require("express-session");

const db = require("./database");

const app = express();
const PORT = 3000;

// =====================================================
// SESSION CONFIGURATION
// =====================================================

app.use(
    session({
        secret: "darius-deedea-tour-secret-key",
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 1000 * 60 * 60 * 24
        }
    })
);

// =====================================================
// ADVERTISEMENT UPLOAD CONFIGURATION
// =====================================================

const uploadFolder = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadFolder)) {
    fs.mkdirSync(uploadFolder);
}

const storage = multer.diskStorage({

    destination: function(req, file, cb) {

        cb(null, uploadFolder);

    },

    filename: function(req, file, cb) {

        const uniqueName =
            Date.now() + "-" +
            Math.round(Math.random() * 1E9) +
            path.extname(file.originalname);

        cb(null, uniqueName);

    }

});

const upload = multer({

    storage: storage,

    limits: {
        fileSize: 100 * 1024 * 1024
    },

    fileFilter: function(req, file, cb) {

        const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif",
            "video/mp4",
            "video/webm",
            "video/ogg"
        ];

        if (allowedTypes.includes(file.mimetype)) {

            cb(null, true);

        } else {

            cb(
                new Error(
                    "Only images and videos are allowed."
                )
            );

        }

    }

});

// Read form data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// =====================================================
// USERS TABLE
// =====================================================

db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`, (err) => {

    if (err) {
        console.log("Users table error:", err.message);
    } else {
        console.log("Users table ready");
    }

});
// =====================================================
// USER REGISTRATION
// =====================================================

app.post("/register", async (req, res) => {

    const {
        fullname,
        email,
        password,
        confirmPassword
    } = req.body;

    // Check all fields
    if (!fullname || !email || !password || !confirmPassword) {

        return res.send(`
            <h2>All fields are required.</h2>

            <a href="/register.html">
                Go Back
            </a>
        `);

    }

    // Check passwords
    if (password !== confirmPassword) {

        return res.send(`
            <h2>Passwords do not match.</h2>

            <a href="/register.html">
                Go Back
            </a>
        `);

    }

    // Check password length
    if (password.length < 6) {

        return res.send(`
            <h2>Password must be at least 6 characters.</h2>

            <a href="/register.html">
                Go Back
            </a>
        `);

    }

    // Check if email already exists
    db.get(
        `SELECT id FROM users WHERE email = ?`,
        [email],
        async (err, user) => {

            if (err) {

                console.log(err);

                return res.send(`
                    <h2>Registration failed.</h2>

                    <a href="/register.html">
                        Try Again
                    </a>
                `);

            }

            // Email already registered
            if (user) {

                return res.send(`
                    <h2>Email already registered.</h2>

                    <p>Please login instead.</p>

                    <a href="/login.html">
                        Login
                    </a>
                `);

            }

            // Hash password
            const hashedPassword =
                await bcrypt.hash(password, 10);

            // Save user
            db.run(
                `
                INSERT INTO users
                (fullname, email, password)
                VALUES (?, ?, ?)
                `,
                [
                    fullname,
                    email,
                    hashedPassword
                ],
                function(err) {

                    if (err) {

                        console.log(err);

                        return res.send(`
                            <h2>Registration failed.</h2>

                            <a href="/register.html">
                                Try Again
                            </a>
                        `);

                    }

                    // Registration successful
                    res.redirect("/login.html");

                }
            );

        }
    );

});
// =====================================================
// USER LOGIN
// =====================================================

app.post("/login", (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {

        return res.send(`
            <h2>Email and password are required.</h2>

            <a href="/login.html">
                Go Back
            </a>
        `);

    }

    db.get(
        `SELECT * FROM users WHERE email = ?`,
        [email],
        async (err, user) => {

            if (err) {

                console.log(err);

                return res.send(`
                    <h2>Login failed.</h2>

                    <a href="/login.html">
                        Try Again
                    </a>
                `);

            }

            if (!user) {

                return res.send(`
                    <h2>Invalid email or password.</h2>

                    <a href="/login.html">
                        Try Again
                    </a>
                `);

            }

            const passwordMatch = await bcrypt.compare(
                password,
                user.password
            );

            if (!passwordMatch) {

                return res.send(`
                    <h2>Invalid email or password.</h2>

                    <a href="/login.html">
                        Try Again
                    </a>
                `);

            }

            req.session.user = {
                id: user.id,
                fullname: user.fullname,
                email: user.email
            };

            res.redirect("/booking.html");

        }
    );

});

// =====================================================
// USER LOGOUT
// =====================================================

app.get("/logout", (req, res) => {

    req.session.destroy((err) => {

        if (err) {

            console.log("Logout error:", err);

            return res.send("Logout failed.");

        }

        res.redirect("/");

    });

});
// =====================================================
// ADMIN LOGOUT
// =====================================================

app.get("/admin-logout", (req, res) => {

    // Remove admin session
    delete req.session.admin;

    res.redirect("/admin-login.html");

});

// Serve static files
// =====================================================
// PROTECT ADMIN DASHBOARD
// =====================================================

app.get("/admin/dashboard.html", (req, res, next) => {

    // No admin logged in
    if (!req.session.admin) {

        return res.redirect("/admin-login.html");

    }

    // Admin is logged in
    next();

});
app.use(express.static(path.join(__dirname)));
app.use(
    "/uploads",
    express.static(path.join(__dirname, "uploads"))
);

// Home page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// Booking form
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

    db.run(

        `INSERT INTO bookings
        (fullname,email,phone,destination,travelDate,guests,message)
        VALUES (?,?,?,?,?,?,?)`,

        [

            fullname,
            email,
            phone,
            destination,
            travelDate,
            guests,
            message

        ],

        function(err){

            if(err){

                console.log(err);

                return res.send("Booking Failed");

            }

            res.send(`

                <h1>Booking Successful!</h1>

                <h2>Booking Number: DDT-${this.lastID}</h2>

                <p>Thank you ${fullname}.</p>

                <a href="/">Return Home</a>

            `);

        }

    );

});
app.get("/bookings", (req, res) => {

    db.all("SELECT * FROM bookings ORDER BY id DESC", [], (err, rows) => {

        if(err){

            return res.status(500).json({error:err.message});

        }

        res.json(rows);

    });

});

// =====================================================
// ADMIN LOGIN
// =====================================================

app.post("/admin-login", (req, res) => {

    const { username, password } = req.body;


    // =========================================
    // ADMIN 1
    // =========================================

    if (
        username === "Admin" &&
        password === "12345"
    ) {

        req.session.admin = {
            username: "Admin",
            role: "admin"
        };

        return res.redirect("/admin/dashboard.html");

    }


    // =========================================
    // ADMIN 2 - SUPER ADMIN
    // =========================================

    if (
        username === "superadmin" &&
        password === "12"
    ) {

        req.session.admin = {
            username: "superadmin",
            role: "superadmin"
        };

        return res.redirect("/admin/dashboard.html");

    }


    // =========================================
    // WRONG LOGIN
    // =========================================

    res.send(`
        <h2>Wrong Username or Password</h2>

        <a href="/admin-login.html">
            Try Again
        </a>
    `);

});
// =====================================================
// GET CURRENT ADMIN
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
// ADVERTISEMENT MANAGEMENT
// =====================================================


// CREATE ADVERTISEMENT
// =====================================================

app.post(
    "/advertisements",
    upload.single("media"),
    (req, res) => {

        // =====================================================
        // ONLY SUPERADMIN CAN ADD ADVERTISEMENTS / EVENTS
        // =====================================================

        if (
            !req.session.admin ||
            req.session.admin.role !== "superadmin"
        ) {

            // Delete uploaded file if Admin 1 tried to upload
            if (req.file) {

                const uploadedFile =
                    path.join(
                        __dirname,
                        "uploads",
                        req.file.filename
                    );

                if (fs.existsSync(uploadedFile)) {

                    fs.unlinkSync(uploadedFile);

                }

            }

            return res.status(403).json({

                success: false,

                message:
                    "Access denied. Only Super Admin can add advertisements or events."

            });

        }


        const {

            title,
            description,
            price,
            advertisement_type,
            start_datetime,
            end_datetime

        } = req.body;


        if (!title || !description) {

            return res.status(400).json({

                success:false,

                message:"Title and description are required."

            });

        }


        if (!req.file) {

            return res.status(400).json({

                success:false,

                message:"Please upload a photo or video."

            });

        }


        // Check duration advertisement

        if (
            advertisement_type === "duration" &&
            (!start_datetime || !end_datetime)
        ) {

            return res.status(400).json({

                success:false,

                message:
                "Start and end date/time are required for duration advertisements."

            });

        }


        const mediaPath =
            "/uploads/" + req.file.filename;


        const mediaType =
            req.file.mimetype;


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
            VALUES (?,?,?,?,?,?,?,?,?)`,

            [

                title,
                description,
                price || "",
                mediaPath,
                mediaType,
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

                if(err) {

                    console.log(err);

                    return res.status(500).json({

                        success:false,

                        message:
                        "Failed to save advertisement."

                    });

                }


                res.json({

                    success:true,

                    message:
                    "Advertisement published successfully.",

                    id:this.lastID

                });

            }

        );

    }
);



// GET ALL ADVERTISEMENTS
// =====================================================

app.get(
    "/advertisements",
    (req, res) => {

        db.all(

            `SELECT *
             FROM advertisements
             ORDER BY id DESC`,

            [],

            (err, rows) => {

                if(err) {

                    console.log(err);

                    return res.status(500).json({

                        error:err.message

                    });

                }


                res.json(rows);

            }

        );

    }
);



// GET ACTIVE ADVERTISEMENTS
// =====================================================

app.get(
    "/advertisements/active",
    (req, res) => {

        db.all(

            `SELECT *
             FROM advertisements
             WHERE status = 'published'
             AND
             (
                 advertisement_type = 'permanent'

                 OR

                 (
                     advertisement_type = 'duration'
                     AND start_datetime <= datetime('now')
                     AND end_datetime >= datetime('now')
                 )
             )
             ORDER BY id DESC`,

            [],

            (err, rows) => {

                if(err) {

                    console.log(err);

                    return res.status(500).json({

                        error:err.message

                    });

                }


                res.json(rows);

            }

        );

    }
);



// DELETE ADVERTISEMENT
// =====================================================

app.delete(
    "/advertisements/:id",
    (req, res) => {

        const id = req.params.id;


        db.get(

            `SELECT media
             FROM advertisements
             WHERE id = ?`,

            [id],

            (err, ad) => {

                if(err) {

                    return res.status(500).json({

                        success:false,

                        message:err.message

                    });

                }


                db.run(

                    `DELETE FROM advertisements
                     WHERE id = ?`,

                    [id],

                    function(err) {

                        if(err) {

                            return res.status(500).json({

                                success:false,

                                message:err.message

                            });

                        }


                        if(this.changes === 0) {

                            return res.status(404).json({

                                success:false,

                                message:
                                "Advertisement not found."

                            });

                        }


                        // Delete uploaded file

                        if(ad && ad.media) {

                            const filePath =
                                path.join(
                                    __dirname,
                                    ad.media
                                );


                            if(fs.existsSync(filePath)) {

                                fs.unlinkSync(filePath);

                            }

                        }


                        res.json({

                            success:true,

                            message:
                            "Advertisement deleted."

                        });

                    }

                );

            }

        );

    }
);

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
