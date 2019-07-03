const express        = require("express");
const passportRouter = express.Router();
const passport       = require('passport');
const bcrypt         = require('bcrypt');
// Require user model
const User         = require('../models/User');
// Add bcrypt to encrypt passwords

// Add passport 


const ensureLogin = require("connect-ensure-login");


passportRouter.get("/signup", (req, res) => {
  res.render("passport/signup");
});

passportRouter.get("/login", (req, res) => {
  res.render("passport/login");
});

passportRouter.post("/signup", (req, res) => {
  const { username, password } = req.body;

  if (!password || !username) {
    res.render("passport/signup", { errorMessage: "Both fields are required" });

    return;
  } else if (password.length < 8) {
    res.render("passport/signup", {
      errorMessage: "Password needs to be 8 characters min"
    });

    return;
  }

User.findOne({ username: username })
.then(user => {
  if (user) {
    res.render("passport/signup", {
      errorMessage: "This username is already taken"
    });

    return;
  }
  const salt = bcrypt.genSaltSync();
  const hash = bcrypt.hashSync(password, salt);

  return User.create({
    username,
    password: hash
  }).then(data => {
    res.redirect("/");
  });
})
.catch(err => {
  res.render("passport/signup", { errorMessage: err._message });
});
});

passportRouter.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true
  })
);

passportRouter.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  console.log(req.user)
  res.render("passport/private", { user: req.user });
});


passportRouter.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

module.exports = passportRouter;