import express from 'express';
import mongoose from 'mongoose';
import dotenv from "dotenv";
import cors from 'cors';
import session from 'express-session';
import passport from 'passport';
import User from './User';
import {IMongoDBUser} from './types';

dotenv.config(); //Uses env variables
const app = express();

//Database
mongoose.connect(`${process.env.START_MONGODB}${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}${process.env.END_MONGODB}`,{
    useNewUrlParser: true,
    useUnifiedTopology: true,    
}, () => {
    console.log("Connected to MongoDB");
});

// Middleware for passport, always add
app.use(express.json());
app.use(cors({origin: "https://brave-bhabha-63b32f.netlify.app", credentials: true})); //Allows requests from the client to affect the server

app.set("trust proxy",1); //The 1 means true, this is for the cookie.

app.use(
    session({
        secret: "secretcode",
        resave: true,
        saveUninitialized: true,
        cookie: {
          sameSite: "none",
          secure: true,
          maxAge: 1000 * 60 * 60 * 24 //One Day cookie in milliseconds
        }
    })
);
app.use(passport.initialize());
app.use(passport.session());

//Serialization to identify the session, req.user returns the user. Only store id.
passport.serializeUser((user: any, done: any)=>{ 
    console.log('serializing user');
    return done(null, user._id);
})

passport.deserializeUser((id: string, done: any) => {
  console.log('deserializing user');
  User.findById(id,(err:Error,doc:IMongoDBUser)=>{
    return done(null,doc);
  });
})

//Google strategy from http://www.passportjs.org/packages/passport-google-oauth20/
const GoogleStrategy = require('passport-google-oauth20').Strategy;
passport.use(new GoogleStrategy({ //Sets up the google strategy
    clientID: `${process.env.GOOGLE_CLIENT_ID}`,
    clientSecret: `${process.env.GOOGLE_CLIENT_SECRET}`,
    callbackURL: `/auth/google/callback`,
    proxy: true,
  },
  function(accessToken:any, refreshToken:any, profile:any, cb:any) {
      //Called on successful authentication, uses User model that we make ourself
      //Insert user, returned as a param of profile, into database
      //console.log(profile);
      //cb(null, profile);
    
      User.findOne({ googleId: profile.id }, async (err: Error, doc: IMongoDBUser) => {

        if (err) {
          return cb(err, null);
        }
  
        if (!doc) {
          const newUser = new User({
            googleId: profile.id,
            username: profile.username
          });
  
          await newUser.save();
          cb(null, newUser);
        }
        cb(null, doc);

    });
  }
));

//Google Authentication
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })); //Scope can also have email and openID.

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('https://brave-bhabha-63b32f.netlify.app/');
});

//Github Strategy
var GitHubStrategy = require('passport-github').Strategy;

passport.use(new GitHubStrategy({
    clientID: `${process.env.GITHUB_CLIENT_ID}`,
    clientSecret: `${process.env.GITHUB_CLIENT_SECRET}`,
    callbackURL: "/auth/github/callback"
  },
  function(accessToken:any, refreshToken:any, profile:any, cb:any) {
    //Called on successful authentication, uses User model that we make ourself
    //Insert user, returned as a param of profile, into database
    User.findOne({ githubId: profile.id }, async (err: Error, doc: IMongoDBUser) => {

      if (err) {
        return cb(err, null);
      }

      if (!doc) {
        const newUser = new User({
          githubId: profile.id,
          username: profile.username
        });

        await newUser.save();
        cb(null, newUser);
      }
      cb(null, doc);
    })

  }
));

//Github Authentication
app.get('/auth/github',
  passport.authenticate('github'));

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('https://brave-bhabha-63b32f.netlify.app/');
  });

//Twitter Strategy
const TwitterStrategy = require('passport-twitter').Strategy;
passport.use(new TwitterStrategy({
  consumerKey: `${process.env.TWITTER_KEY}`,
  consumerSecret: `${process.env.TWITTER_SECRET}`,
  callbackURL: "/auth/twitter/callback"
},
function(token: any, tokenSecret: any, profile: any, cb: any) {
//Called on successful authentication, uses User model that we make ourself
      //Insert user, returned as a param of profile, into database
      User.findOne({ twitterId: profile.id }, async (err: Error, doc: IMongoDBUser) => {

        if (err) {
          return cb(err, null);
        }
  
        if (!doc) {
          const newUser = new User({
            twitterId: profile.id,
            username: profile.username
          });
  
          await newUser.save();
          cb(null, newUser);
        }
        cb(null, doc);
  
  //User.findOrCreate({ twitterId: profile.id }, function (err, user) {
  //  return cb(err, user);
  });
}
));

//Twitter Authentication
app.get('/auth/twitter',
  passport.authenticate('twitter'));

app.get('/auth/twitter/callback', 
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('https://brave-bhabha-63b32f.netlify.app/');
  });

//API calls, not authentication
app.get('/', (req,res)=>{
    res.send("Hello World");
});

app.get('/getuser', (req,res)=>{
  res.send(req.user); //Used from deserialize user.
})

app.get("/auth/logout",(req,res)=>{
  if (req.user) {
    req.logout();
    res.send("done");
  }
})

app.listen(`${process.env.PORT}`,() => {
    console.log(`Server started on port ${process.env.PORT}`);
});
