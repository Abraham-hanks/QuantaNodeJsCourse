const express = require('express');
const mongoose = require('mongoose');
const User = require('./models/user');
const bcrypt = require('bcryptjs');
const session = require('express-session');
require('dotenv').config();

// CONSTANTS
const { DB_PASSWORD, PORT, SESS_NAME, SESS_SECRET } = process.env
const app = express();
const port = PORT || 3000;
const sess_duration = 1000 * 60 * 60 * 2; // 2 hours

mongoose.connect(`mongodb+srv://abraham-hanks:${DB_PASSWORD}@cluster0.f7rdy.mongodb.net/?retryWrites=true&w=majority`,
{
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log("MONGO CONNECTION OPEN!!!")
}).catch(err => {
  console.log("OH NO MONGO CONNECTION ERROR!!!!")
  console.log(err)
})

app.set('view engine', 'ejs');
app.set('views', 'views');
app.use(express.urlencoded({ extended: true }));
app.use(session({ 
  name: SESS_NAME,
  resave: false,
  saveUninitialized: false,
  secret: SESS_SECRET,
  cookie: {
    maxAge: sess_duration,
    sameSite: true
  }
}))

// ======= HELPER ==========
const validateRegister = (req, res, next) => {
  const { password, confirmPassword, username } = req.body;
  const errorMessages = [];
  if (!username) {
    errorMessages.push('Username is required!');
  }
  if (!password) {
    errorMessages.push('Password is required!');
  }
  if (!confirmPassword) {
    errorMessages.push('Confirm Password is required!');
  }

  if (password !== confirmPassword) {
    errorMessages.push('Password must match Confirm password');
  }

  if (errorMessages.length) {
    res.render('register', { errors: errorMessages, user: null });
  }
  else {
    next();
  }
}

const requireLogin = (req, res, next) => {
  if (!req.session.user_id) {
    return res.redirect('/login');
  }
  next();
}

// ====== GET =========
app.get('/', (req, res) => {
  if (req.session.user_id) {
    res.redirect("/profile")
  }
  res.render('home', { user: null })
})

app.get('/register', (req, res) => {
  res.render('register', { errors: null, user: null });
})

app.get('/login', (req, res) => {
  res.render('login', { errors: null, user: null });
})

app.get('/profile', requireLogin, async (req, res) => {
  const user = await User.findById(req.session.user_id);
  res.render('profile', { user });
})

// ====== POST =========
app.post('/register', validateRegister, async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username: username });
    if (existingUser) {
      return res.render('register', {
        errors: ['A user with this username already exists!'],
        user: null
      });
    }
    const salt = await bcrypt.genSalt(10);
    req.body.password = await bcrypt.hash(password, salt);
    const user = new User(req.body);
    await user.save();
    req.session.user_id = user._id;
    res.redirect('/');
  } catch (err) {
    console.log(err)
    res.render('register', { errors: ['Oops an Error Occurred!'], user: null })
  }
})

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const foundUser = await User.findOne({ username });
    const isValid = await bcrypt.compare(password, foundUser.password);
    if (isValid) {
      req.session.user_id = foundUser._id;
      res.redirect('/profile');
    }
    else {
      res.render('login', { errors: ['Invalid credentials!'], user: null});
    }
  } catch (error) {
    console.log(error);
    res.render('login', { errors: ['Oops an Error Occurred!'], useer: null });
  }
})

app.post('/logout', (req, res) => {
  req.session.user_id = null;
  req.session.destroy();
  res.redirect('/login');
})

app.listen(port, () => {
  console.log(`SERVING YOUR APP ON PORT ${port}!`);
});
