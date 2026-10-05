const express=require('express');
const session=require('express-session');
const cors=require('cors');
const passport=require('passport');
const GoogleStrategy=require('passport-google-oauth20').Strategy;
const DiscordStrategy=require('passport-discord').Strategy;
const SteamStrategy=require('passport-steam').Strategy;

const app=express();
const PORT=process.env.PORT||10000;
const FRONTEND=process.env.FRONTEND_URL||'https://dexer.site.je';
const BACKEND=process.env.BACKEND_URL||'http://localhost:'+PORT;
const CLIENT_ID=process.env.GOOGLE_CLIENT_ID||'1011240819775-2pa9mj9049gsqkfccpki9norc2emt5v4.apps.googleusercontent.com';

app.set('trust proxy',1);
app.use(cors({origin:FRONTEND,credentials:true}));
app.use(express.json());
app.use(session({secret:process.env.SESSION_SECRET||'CHANGE_THIS_SECRET',resave:false,saveUninitialized:false,cookie:{httpOnly:true,secure:true,sameSite:'none',maxAge:7*24*60*60*1000}}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((u,done)=>done(null,u));
passport.deserializeUser((u,done)=>done(null,u));

passport.use(new GoogleStrategy({clientID:CLIENT_ID,clientSecret:process.env.GOOGLE_CLIENT_SECRET,callbackURL:BACKEND+'/auth/google/callback'},(accessToken,refreshToken,profile,done)=>done(null,{provider:'google',id:profile.id,name:profile.displayName,email:profile.emails?.[0]?.value,avatar:profile.photos?.[0]?.value})));
passport.use(new DiscordStrategy({clientID:process.env.DISCORD_CLIENT_ID,clientSecret:process.env.DISCORD_CLIENT_SECRET,callbackURL:BACKEND+'/auth/discord/callback',scope:['identify','email']},(accessToken,refreshToken,profile,done)=>done(null,{provider:'discord',id:profile.id,name:profile.username,email:profile.email,avatar:profile.avatar?`https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`:null})));
passport.use(new SteamStrategy({returnURL:BACKEND+'/auth/steam/callback',realm:BACKEND+'/',apiKey:process.env.STEAM_API_KEY||''},(identifier,profile,done)=>done(null,{provider:'steam',id:profile._json?.steamid||profile.id,name:profile.displayName,avatar:profile.photos?.[2]?.value||profile.photos?.[0]?.value})));

app.get('/',(req,res)=>res.json({ok:true,service:'DEXO Auth Backend'}));
app.get('/health',(req,res)=>res.json({ok:true}));
app.get('/me',(req,res)=>res.json({authenticated:!!req.user,user:req.user||null}));
app.get('/logout',(req,res)=>req.logout(()=>req.session.destroy(()=>res.redirect(FRONTEND))));

app.get('/auth/google',passport.authenticate('google',{scope:['profile','email'],session:true}));
app.get('/auth/google/callback',passport.authenticate('google',{failureRedirect:FRONTEND+'/?auth=google_failed'}),(req,res)=>res.redirect(FRONTEND+'/?auth=success&provider=google'));
app.get('/auth/discord',passport.authenticate('discord'));
app.get('/auth/discord/callback',passport.authenticate('discord',{failureRedirect:FRONTEND+'/?auth=discord_failed'}),(req,res)=>res.redirect(FRONTEND+'/?auth=success&provider=discord'));
app.get('/auth/steam',passport.authenticate('steam'));
app.get('/auth/steam/callback',passport.authenticate('steam',{failureRedirect:FRONTEND+'/?auth=steam_failed'}),(req,res)=>res.redirect(FRONTEND+'/?auth=success&provider=steam'));

app.listen(PORT,'0.0.0.0',()=>console.log(`DEXO auth listening on ${PORT}`));
