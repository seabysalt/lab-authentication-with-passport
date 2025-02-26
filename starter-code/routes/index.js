const express = require('express');
const router  = express.Router();

const loginCheck = () => {
  return (req, res, next) => {
    if (req.isAuthenticated()) next();
    else res.redirect("/login");
  };
};

/* GET home page */
router.get('/', (req, res, next) => {
  res.render('index');
});

module.exports = router;
