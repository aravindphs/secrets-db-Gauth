require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const _ = require("lodash");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.use(cors(
    {
        origin: ["https://secrets-db-gauth-2x2xw7bsp-aravindphs.vercel.app/"],
        methods: ["POST", "GET"],
        credentials: true
    }
));
const port = process.env.PORT;

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
    secret: "This is going to be hell.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const uri = process.env.MONGO_DB_URL;
mongoose.connect(uri, {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email : String,
    password : String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

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
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  });

app.get("/login", (req,res) => {
    res.render("login");
});

app.get("/register", (req,res) => {
    res.render("register");
});

app.get("/secrets",(req,res)=>{
    User.find({"secret" : {$ne:null}})
        .then((foundUsers) => {
            if(foundUsers) {
                res.render("secrets", {usersWithSecrets : foundUsers});
            } else {
                console.log("Secrets not Found!");
            }
        })
        .catch((err) => {
            console.log(err);
        })
});

app.get("/submit", (req,res) => {
    if(req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;
 
    User.findById(req.user.id)
        .then((foundUser) => {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save()
                    .then(() => {
                        res.redirect("/secrets");
                    });
            } else {
                console.log("User not found");
            }
        })
        .catch((err) => {
            console.log(err);
        });
});


app.get("/logout", (req,res) => {
    req.logout((err) => {
        if(err){
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
});

app.post("/register", (req, res) => {
    
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if(!err){
            passport.authenticate("local")(req,res, ()=>{
            res.redirect("/secrets");
            })
        } else {
            console.log(err);
            res.redirect("/register");
        }
    })
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));



app.listen(port, () => {
    console.log(`Server started on ${port}.`);
});
