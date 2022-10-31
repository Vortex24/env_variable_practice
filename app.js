//jshint esversion:6

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const passport = require("passport");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "This is a secret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb+srv://admin-vortex:vortex24@secrets-cluster.vedyhh0.mongodb.net/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
    res.render("home");
});

app.get("/logout", function(req, res){
    req.logout(function(err){
        if (err)
            console.log(err);
        else
            res.redirect("/");
    });
});

app.get("/login", function(req, res){
    res.render("login");
});

app.post("/login", function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if (err)
            console.log(err);
        else
        {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/submit");
            });
        }
    });


    // const username = req.body.username;
    // const password = req.body.password;
    //
    // User.findOne({ email: username }, function(err, foundUser){
    //     if (!err)
    //     {
    //         if (foundUser)
    //         {
    //             bcrypt.compare(password, foundUser.password, function(err, result){
    //                 if (result === true)
    //                 {
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
    //     }
    // });
});


app.get("/secrets", function(req, res){
    User.find({ secret: {$ne: null}}, function(err, results){
        if (!err)
        {
            if (results)
            {
                res.render("secrets", { secretUsers: results });
            }
        }
    });
});


app.get("/submit", function(req, res){
    if (req.isAuthenticated())
        res.render("submit");
    else
        res.redirect("/login");
});

app.post("/submit", function(req, res){
    User.findById(req.user.id, function(err, result){
        if (!err)
        {
            if (result)
            {
                result.secret = req.body.secret;
                result.save(function(err){
                    if (!err)
                        res.redirect("secrets");
                });
            }
            else
                res.redirect("/login");
        }
    });
});



app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res){
        res.redirect("/secrets");
    }
);


app.get("/register", function(req, res){
    res.render("register");
});

app.post("/register", function(req, res){

    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err)
        {
            console.log(err);
            res.redirect("/");
        }
        else
        {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/submit");
            });
        }
    });

    // bcrypt.hash(req.body.password, saltRounds, function(err, hash){
    //     const userEntry = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    //
    //     userEntry.save(function(err){
    //         if (err)
    //             console.log(err);
    //         else
    //             res.render("secrets");
    //     });
    // });
});



app.listen(process.env.port || 3000, function(req, res){
    console.log("Server is up and running...");
});
