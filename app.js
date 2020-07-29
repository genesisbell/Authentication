//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport"), FacebookStrategy = require('passport-facebook').Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded ({extended:true}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true, useUnifiedTopology:true});
mongoose.set("useCreateIndex", true);


const usersSchema = new mongoose.Schema({
    username: {type: String, unique: true}, //values: email addressm googleId, facebookId
    password: String,
    provider: String, //values 'local', 'google', 'facebook'
    email: String,
    secret: String
})

usersSchema.plugin(passportLocalMongoose, {usernameField: "username"});
usersSchema.plugin(findOrCreate);

const User =  new mongoose.model("User", usersSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(acessToken, refreshToken, profile, cb) {
      User.findOrCreate({username: profile.id },
        {provider: "google", email: profile._json.email}, 
        function (err, user) {
            return cb(err, user);
      });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ["id", "email"]
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({username: profile.id}, 
        {provider: "facebook", email: profile._json.email},
        function(err, user) {
            if (err) { return done(err); }
            done(null, user);
    });
  }
));


app.get("/", function(req, res){
    res.render("home")
})

app.route("/secrets")
.get(function(req, res){

    // FB.getLoginStatus(function(response) {
    //     statusChangeCallback(response);
    //     if(response==="connected"){
    //         res.render("secrets")
    //     }else{
    //         res.redirect("/login")
    //     }
    // });

    User.find({"secret": {$ne: null}}, function(err, foundUSers){
        if(err){
            console.log(err)
        }else{
            if(foundUSers){
                res.render("secrets", {usersWithSecrets : foundUSers})
            }
        }
    })

})


app.route("/login")
.get(function(req, res){
    res.render("login")
})
.post(function(req, res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function(err){
        if(err){
            console.log(err)
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets")
            })
        }
    })

})

app.get("/auth/google", passport.authenticate("google", {scope: ["profile", "email"], prompt: 'select_account'}))

app.get("/auth/google/secrets", passport.authenticate("google" , {failureRedirect: "/login"}),
function(req, res){
    res.redirect("/secrets")
})

app.get('/auth/facebook', passport.authenticate('facebook', {scope: ["email"]}));

app.get('/auth/facebook/secrets',  passport.authenticate('facebook', { successRedirect: '/secrets', failureRedirect: '/login' }));

app.route("/logout")
.get(function(req, res){
    req.logout();
    res.redirect("/")
})

    
app.route("/register")
.get(function(req, res){
    res.render("register")
})
.post(function(req, res){
    const username = req.body.username;
    const password = req.body.password;

    User.register({username: username}, password, function(err, user){
        if(err){
            console.log(err)
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res, function(){
                User.updateOne(
                    {_id: user._id},
                    {$set: {provider: "local", email: username}}, 
                    () => res.redirect('/secrets')
                )
            })
        }
    })
})

app.route("/submit")
.get(function(req, res){
    if(req.isAuthenticated()){
        res.render("submit")
    }else{
        res.redirect("/login")
    }
})
.post(function(req, res){
    const submittedSecret = req.body.secret;
    console.log(req.user)
    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err)
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets")
                })
            }
        }
    })
})









app.listen(3000, function(){
    console.log("Server started on port 3000")
})

