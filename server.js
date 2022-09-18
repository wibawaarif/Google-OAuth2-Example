const helmet = require("helmet");
const express = require("express");
const https = require("https");
const fs = require("fs");
const path = require("path");
const bodyParser = require("body-parser");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
const cookieSession = require("cookie-session");

require("dotenv").config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log("Google Profile", profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// save the session to cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// read the session from the cookie
passport.deserializeUser((id, done) => {
  done(null, id);
});

const app = express();

app.use(helmet());
app.use(
  cookieSession({
    name: "session",
    maxAge: 30 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: false }));

function loggedIn(req, res, next) {
  console.log("req.body", req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (!isLoggedIn) {
    return res.status(401).json({
      error: "you must logged in!",
    });
  }
  next();
}

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/secret",
    session: true,
  }),
  (req, res) => {
    console.log("Google called us back");
  }
);

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email"],
  })
);

app.get("/secret", loggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/login", (req, res) => {
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (isLoggedIn) {
    res.redirect("/secret");
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/secret",
    session: true,
  }),
  (req, res) => {
    console.log("Google called us back");
  }
);

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email"],
  })
);

app.get("/auth/logout", (req, res) => {
  req.logout();
  return res.redirect("/login");
});

app.get("/failure", (req, res) => {
  return res.send("failed to login!");
});

app.get("/", (req, res) => {
  res.redirect("/login");
});

https
  .createServer(
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listening to port ${PORT}....`);
  });
