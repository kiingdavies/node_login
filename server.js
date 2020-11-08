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

const PORT = process.env.PORT || 4000;

//Middleware to view ejs files
app.set("view engine", "ejs");
//This middleware allows use send data from front to backend
app.use(express.urlencoded({ extended: false }));
//Middleware for session
app.use(session({
    secret: 'secret', //normally this secret should be longer and saved in .env file
    resave: false,
    saveUninitialized: false,
}));

//Middleware for flash messages
app.use(flash());

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/users/register', (req, res) => {
    res.render('register');
});

app.get('/users/login', (req, res) => {
    res.render('login');
});

app.get('/users/dashboard', (req, res) => {
    res.render('dashboard', { user: "Deji" });
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

app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`);
});