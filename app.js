require("dotenv").config() //This is for the .env packsge from https://www.npmjs.com/package/dotenv
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy; //this uses google OAuth and we will use it as a passport strategy
const FacebookStrategy = require("passport-facebook"); //this uses facebook and we will use it as a passport strategy
const findOrCreate = require("mongoose-findorcreate"); //for mongoose find or create one

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

//session code should be placed above mongoose connect and below express
//check https://www.npmjs.com/package/express-session to get better understanding on session
app.use(session({
  secret: "Our little secret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize()); //this method comes with passport and sets it up for use
app.use(passport.session()); //this tell the app to use passport to also set up session

//Connect to your mongodb database
mongoose.set('strictQuery', false);
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});

//creating encryption schema for the database https://www.npmjs.com/package/mongoose-encryption
const userSchema = new mongoose.Schema({ //This is to change our schema into a mongoose object schema ie https://www.npmjs.com/package/mongoose-encryption or https://mongoosejs.com/docs/schematypes.html
  email: String,
  password: String,
  googleId: String, //this takes their google id into the schema
  facebookId: String, //this takes their facebook id into the schema
  secret: String
});

//passport-local-mongoose
userSchema.plugin(passportLocalMongoose); //this is what we will use to hash and salt our data and save it in our mongoose database
userSchema.plugin(findOrCreate); //for mongoose fidorcreate

//creating a model for the database
const User = new mongoose.model("User", userSchema);

//passport local mongoose configuration code
// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

//this code is from the passport docs (https://www.passportjs.org/tutorials/google/session/)
passport.serializeUser(function(user, cb) { //this creates a cookie
  process.nextTick(function() {
    cb(null, {
      id: user.id,
      username: user.username,
      name: user.name
    });
  });
});

passport.deserializeUser(function(user, cb) { //this destroys the cookie
  process.nextTick(function() {
    return cb(null, user);
  });
});

//google strategy code from passport site "https://www.passportjs.org/packages/passport-google-oauth20/"
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID, //the client id stored in the .env file
    clientSecret: process.env.CLIENT_SECRET, //the client secret code stored in the .env file
    callbackURL: "http://localhost:3000/auth/google/secrets", //the Authorised redirect URIs you set in the google developer console (inside credentions, OAuth 2.0 Client IDs click the project name and scroll down)
    // the path the callbackURL hits up in the server is /auth/google/secrets
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //this makes retrieving user data instead of from the deprecated google plus, it should use the userinfo
    //be careful of typos
  },
  function(accessToken, refreshToken, profile, cb) { //here is where google sends back the access token that will allow us the user data
    console.log(profile); //this is to log the user profile that we get back from the get request on /auth/google route
    User.findOrCreate({ //we use the data we got back from google ie user email to find a user if they exist, if they dont to create one
      username: profile.emails[0].value, //this adds it as a new mail so we can dodge an error
      googleId: profile.id //when a new user gets created, this finds if the user googleId record already exists in our database, in which case we save all the data associated with that id otherwise we create on our database and save that information for the future
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

//facebook strategy. code from https://www.passportjs.org/packages/passport-facebook/
passport.use(new FacebookStrategy({ //this will create a new facebook strategy
    clientID: process.env.FACEBOOK_APP_ID, //the clientID stored in the .env file
    clientSecret: process.env.FACEBOOK_APP_SECRET, //the clientSecret stored in the .env file
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) { //here is where facebook sends back the access token that will allow us the user data
    console.log(profile); //this is to log the user profile that we get back from the get request on auth/facebook route
    User.findOrCreate({ //we use the data we got back from facebook ie username to find a user if they exist, if they dont to create one
      facebookId: profile.id //when a new user gets created, this finds if the user facebook record already exists in our database, in which case we save all the data associated with that user otherwise we create on our database and save that information for the future
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
  //this will render the home.ejs page as the starting page
});

//path for google button. this code was gotten from the passport-google-oauth20 docs (https://www.passportjs.org/packages/passport-google-oauth20/)
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"] //this increases the scope to accept email so that we can bypass an error
  }) //this will authenticate the user using google strategy. we are telling google that we need the users profile which includes their username and id
  //the code creates a pop-up that allows users sign in into their google accounts
  //it will initiate
);

//after user is authenticated using google, they are sent to this route
app.get("/auth/google/secrets", //this is the route you provided in the google app console under credentials, OAuth 2.0 Client IDs, Authorised redirect URIs
  passport.authenticate("google", {
    failureRedirect: "/login"
  }), //we authenticate the user locally and if there is any problem we send them back to the login page
  function(req, res) {
    res.redirect("/secrets"); //successful authentication and we send them to the secret route (to app.get /secrets)
  });

//authenticating requests using facebook. code from (https://www.passportjs.org/packages/passport-facebook/)
app.get("/auth/facebook",
  passport.authenticate('facebook') //this will authenticate the user using facebook strategy. we are telling facebook that we need the users profile which includes their username and id
  //the code creates a pop-up that allows users sign in into their facebook accounts
);

//after user is authenticated using facebook, they are sent to this route
app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", {
    failureRedirect: "/login"
  }), //we authenticate the user locally and if there is any problem we send them back to the login page
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets"); //successful authentication and we send them to the secret route (to app.get /secrets)
  });

app.get("/login", function(req, res) {
  res.render("login");
  //this will render the login.ejs page
});

app.get("/register", function(req, res) {
  res.render("register");
  //this will render the register.ejs page
});

app.get("/secrets", function(req, res) {//we search through the user collecion and check were the secret fiel has a value "https://stackoverflow.com/questions/4057196/how-do-you-query-for-is-not-null-in-mongo"
  User.find({"secret": {$ne: null}}, function(err, foundUsers) {
    if(err) {
      console.log(err);
    } else {
      if(foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers}); //this renders the secret.ejs page. then accepts a variable (usersWithSecrets) and passe in the found users as a value for the variable
        //this usersWithSecrets is what we will use in our secret.ejs page to replace the secret text
      }
    }
  });
});

//submitting a secret
app.get("/submit", function(req, res) { //this send a get request to the secret route and allows the page to display
  //here is where we check if the user is authenticated
  if (req.isAuthenticated()) { //if the user is authenticated we render the submit page
    res.render("submit");
  } else { //else send them to the login page so that they will login
    res.render("login");
  }
});

//adding a logout route
app.get("/logout", function(req, res) { //here we deauthenticate the user and end the user sesion
  req.logout(function(err) { //this is to logout using passport
    if (err) {
      console.log(err);
    } else {
      res.redirect("/"); //this should redirect them to the homepage
    }
  });
});

//using passport to authenticate new users
app.post("/register", function(req, res) { //This is to recieve the post request from the register form
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) { //using the User model, the argument thats a username value, password and a function
    if (err) {
      console.log(err);
      res.redirect("/register"); //this returns the user back to the regiser page so that they can retry
    } else { //if there are no errors we authenticate the user
      passport.authenticate("local")(req, res, function() { //this function only works if the authentication was successful
        res.redirect("/secrets"); //when the authentication works, the user gets sent into the secrets route
      });
    }
  });
});

app.post("/login", function(req, res) { //this route is to login after users have already registered. it i below the register route because you need to be inside the database before you can login
  const user = new User({ //we create a new user
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) { //this uses the new user to check if an existing user credentials is in our database
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() { //authenticates to see if username matches password in the database
        res.redirect("/secrets"); //this would send the user to the secrets route to check if they are authenticated or not
      });
    }
  });
});

//post route to save secrets
app.post("/submit", function(req, res) {
  const submettedSecret = req.body.secret; //this targets the input field for the submit.ejs page

  User.findById(req.user.id, function(err, foundUser) { //we tap into the user model and find by id the id of the user that triggered the post request
    if (err) { //if there is an error log it
      console.log(err);
    } else {
      if (foundUser) { //if the user is found in our database (by their id)
        foundUser.secret = submettedSecret; //we set the found users secret page to be equal to the submitted secret
        foundUser.save(function() { //save the secret into our database
          res.redirect("/secrets"); //once the secret is saved, we redirect them to the secret page so hat they can see their own secret
        });
      }
    }
  });
});

app.listen(3000, function() {
  console.log("Server is hot and running on port 3000");
});
//rs to restart nodemon
//to redirect in app.post route you just write the page name ("home"). but in app.post route u add a forward slash ("/home");
