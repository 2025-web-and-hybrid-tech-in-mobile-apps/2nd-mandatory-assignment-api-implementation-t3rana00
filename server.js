const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const passport = require("passport");
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const port = process.env.PORT || 3000;

app.use(express.json()); // for parsing application/json

// ------ WRITE YOUR SOLUTION HERE BELOW ------//

const MYSECRETJWTKEY = "mysecret";
const userDetails = [];
const scoreBoard = [];
app.use(passport.initialize());

//------------------------singnup route to register a user--------------------------------//
app.post("/signup", (req,res) => {
  const userHandle = req.body.userHandle;
  const password = req.body.password;

  //validate inputs
  if(!userHandle || !password){
    return res.status(400).json({message: "Invalid request body"})
  }
  if(userHandle.length < 6){
    return res.status(400).json({message: "Invalid request body"})
  }
  if(password.length < 6){
    return res.status(400).json({message: "Invalid request body"})
  }

  // register the user
    userDetails.push({userHandle, password});
    return res.status(201).json({message:"User registered successfully"})
  
})


//-----------------------login route--------------------------//
//---function for access token creation---//
const generateAccessToken = (user) => {
  return jwt.sign(
      {userHandle : user}, 
      MYSECRETJWTKEY, 
      { expiresIn: '10m' }
  )
}
app.post("/login", (req,res) => {
  const userHandle = req.body.userHandle;
  const password = req.body.password;

  //check for extra fields
  const allowedFields = ["userHandle", "password"];
  const receivedFields = Object.keys(req.body);

  const extraFields = receivedFields.filter(field => !allowedFields.includes(field));

  if (extraFields.length > 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // validate inputs
  if (!userHandle || !password || userHandle == "" || password == ""){
    return res.status(400).json({message: "Bad Request"})
  }
  if (typeof userHandle !== "string" || typeof password !== "string") {
    return res.status(400).json({ message: "Bad Request" });
  }
  if(userHandle.length < 6){
    return res.status(400).json({message: "Bad Request"})
  }
  if(password.length < 6){
    return res.status(400).json({message: "Bad Request"})
  }

  // check user exists in db
  const foundUser = userDetails.find((e) => e.userHandle === userHandle )
  if (!foundUser || foundUser.password !== password) {
    return res.status(401).json({ message: "Unauthorized, incorrect username or password" });
  }
  const accessToken = generateAccessToken(foundUser.userHandle)
    res.status(200).json({
      jsonWebToken:accessToken
    })  
})


//-----------------------post high score route--------------------------//
//Middleware for JWT authentication and user verification
//Extracts the JWT from the Authorization header (Bearer token) and verifies JWT using the secret key
const optionsForJWTValidation = {
  jwtFromRequest : ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey : MYSECRETJWTKEY
}

// Sets up Passport to use JWT for authentication
passport.use( new JwtStrategy(optionsForJWTValidation, function (payload,done){
  //checks if the user in the JWT exists in the database
  const user = userDetails.find(user => user.userHandle === payload.userHandle);
  // If the user is found, they are authenticated; if not, an error message is returned.
  return user ? done(null, user) : done(null, false, { message: "User not found. Invalid token " });
}));

app.post("/high-scores", passport.authenticate('jwt', {session : false}), (req, res) => {
  const level = req.body.level;
  const userHandle = req.body.userHandle;
  const score = req.body.score;
  const timestamp = req.body.timestamp;

  if(!level || !userHandle || !score || !timestamp){
    return res.status(400).json({message: "Invalid request body"})
  }

  scoreBoard.push({level, userHandle, score, timestamp});
  return res.status(201).json({message:"High score posted successfully"})
})


app.get("/high-scores", (req, res) => {
  //get query parameters to variables
  const level = req.query.level;
  const page = Number(req.query.page)

  //sort score array to decending order
  scoreBoard.sort((a,b) => b.score - a.score);

  //assign scores to a new array according to level
  const selectedScores = scoreBoard.filter((e) => e.level == level)
  let resultArray =[]

  //check that scores available
  if(selectedScores.length > 0){
    //check page number is given or not and if not show first page
    if(!page){
      resultArray = scoreBoard.slice(0,20)
    }
    //if page number given show score details according to page number
    else{
      let totalPageCount = 0
      if((selectedScores.length % 20) != 0){
        totalPageCount = (Math.floor(selectedScores.length / 20)) + 1;
        let max = page*20;
        let min = max-20;
        resultArray = scoreBoard.slice((min+1),(max))
      } 
    }
    return res.status(200).json(resultArray)  
  }
  //return empty array if given level not found
  else{
    return res.status(200).json([])  
  }
   
});
//------ WRITE YOUR SOLUTION ABOVE THIS LINE ------//

let serverInstance = null;
module.exports = {
  start: function () {
    serverInstance = app.listen(port, () => {
      console.log(`Example app listening at http://localhost:${port}`);
    });
  },
  close: function () {
    serverInstance.close();
  },
};