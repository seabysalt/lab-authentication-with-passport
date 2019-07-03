require('dotenv').config();

const bodyParser   = require('body-parser');
const cookieParser = require('cookie-parser');
const express      = require('express');
const favicon      = require('serve-favicon');
const hbs          = require('hbs');
const mongoose     = require('mongoose');
const logger       = require('morgan');
const path         = require('path');
const passport     = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User         = require('./models/User');
const bcrypt       = require('bcrypt');
const flash        = require("connect-flash");
const session      = require('express-session')


mongoose
  .connect('mongodb://localhost/starter-code', {useNewUrlParser: true})
  .then(x => {
    console.log(`Connected to Mongo! Database name: "${x.connections[0].name}"`)
  })
  .catch(err => {
    console.error('Error connecting to mongo', err)
  });

const app_name = require('./package.json').name;
const debug = require('debug')(`${app_name}:${path.basename(__filename).split('.')[0]}`);

const app = express();

// Middleware Setup
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// Express View engine setup

app.use(require('node-sass-middleware')({
  src:  path.join(__dirname, 'public'),
  dest: path.join(__dirname, 'public'),
  sourceMap: true
}));
      

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(favicon(path.join(__dirname, 'public', 'images', 'favicon.ico')));


// app.use(
//   session({
//     secret: process.env.SESSION_SECRET,
//     cookie: { maxAge: 24 * 60 * 60 },
//     resave: false,
//     saveUninitialized: false
//   })
// );

app.use(flash());

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .then(user => {
      done(null, user);
    })
    .catch(err => {
      done(err);
    });
});

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username })
      .then(user => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
          return done(null, false, { message: "Invalid credentials" });
        }
        done(null, user);
      })
      .catch(err => {
        done(err);
      });
  })
);

app.use(session({
  secret: "our-passport-local-strategy-app",
  resave: true,
  saveUninitialized: true,
  // store: new MongoStore({ mongooseConnection: db })
}));

app.use(passport.initialize());
app.use(passport.session());



// default value for title local
app.locals.title = 'Express - Generated with IronGenerator';


// Routes middleware goes here
const index = require('./routes/index');
app.use('/', index);
const passportRouter = require("./routes/passportRouter");
app.use('/', passportRouter);


module.exports = app;
