//import express you installed
const express = require("express");
//instantiate the express
const app = express();

//import the dbConfig file
const { pool } = require('./dbConfig');
//import bcrypt for password hashing
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');

const initializePassport = require('./passportConfig');

initializePassport(passport);

const PORT = process.env.PORT || 4000;

//Middleware to view ejs files
app.set("view engine", "ejs");
//This middleware allows use send data from front to backend
app.use(express.urlencoded({ extended: false }));
//Middleware for session
app.use(session({
    // Key we want to keep secret which will encrypt all of our information
    secret: 'secret',
    // Should we resave our session variables if nothing has changes which we dont
    resave: false,
    // Save empty value if there is no vaue which we do not want to do
    saveUninitialized: false,
}));

// Funtion inside passport which initializes passport
app.use(passport.initialize());
// Store our variables to be persisted across the whole session. Works with app.use(Session) above
app.use(passport.session());

//Middleware for flash messages
app.use(flash());

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/users/register', checkAuthenticated, (req, res) => {
    res.render('register');
});

app.get('/users/login', checkAuthenticated, (req, res) => {
    res.render('login');
});

app.get('/users/dashboard', checkNotAuthenticated, (req, res) => {
    res.render('dashboard', { user: req.user.name }); //this returns the user's name from our DB
});

app.get("/users/logout", (req, res) => {
    req.logout();
    req.flash("success_msg", "You have logged out");
    res.redirect("/users/login");
    //res.render("index", { message: "You have logged out successfully" }); //This routes you to index page
});

app.post('/users/register', async (req, res) => {
    let { name, email, password, password2 } = req.body;

    console.log({
        name,
        email,
        password,
        password2
    });

    //Error checks messages
    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ message: "Errors: Please enter all fields!" });
    }

    if (password.length < 6) {
        errors.push({ message: "Errors: Password should be at least 6 characters!" });
    }

    if (password != password2) {
        errors.push({ message: "Errors: Passwords do not match" });
    }

    if (errors.length > 0) {
        res.render("register", { errors });
    } else {
        //Form validation has passed so hash password
        let hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        // Check if user already exists in our DB
        pool.query(
            `SELECT * FROM users WHERE email = $1`, [email], (err, results) => {
                if (err) {
                    throw err
                }

                console.log(
                    results.rows
                );

                if (results.rows.length > 0) {
                    errors.push({ message: "Errors: Email already registered" });
                    res.render("register", { errors });
                } else {
                    pool.query(
                        `INSERT INTO users(name, email, password)
                        VALUES($1, $2, $3)
                        RETURNING id, password`, [name, email, hashedPassword],
                        (err, results) => {
                            if (err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash("success_msg", "You are now registered. Please log in");
                            res.redirect("/users/login");
                        }
                    );
                }

            });
    }
});

// This routes user to these pages if login/authenticate with password is successful or fails respectively
app.post(
    "/users/login",
    passport.authenticate("local", {
        successRedirect: "/users/dashboard",
        failureRedirect: "/users/login",
        failureFlash: true
    })
);

//if user is authenticated redirect them to the dashboard
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/users/dashboard");
    }
    next();
}

//if user is not authenticated redirect them to the login page
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/users/login");
}

app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`);
});