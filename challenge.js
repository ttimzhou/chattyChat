// @Author: Tim Zhou
// @Date: 11/25/2019
const sqlite3 = require("sqlite3").verbose();
const express = require('express');
const server = express();
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const JWTstrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;
const JWTSecret = require("./JWTSecret");




// DB and Express configurations
//  ---------------------------------------------------------------------------------------------------------
// Initialize express Body Parser
server.use(bodyParser.json());
// Initializeation: creates database if not exist
const db = new sqlite3.Database("challenge.db");
// DB => users: id(PK) || username || password
db.run('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username text, password text)')
// DB => history: id(PK) || sender || recipient || messageType || message || timestamp
db.run('CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY AUTOINCREMENT, sender text, recipient text, messageType text, message text, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')

// Default Port set to 8000
const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log(`Hello it's Tim, I am listening on port ${PORT}`);
})





// Verification strategies(local and jwt) initializations
//  ---------------------------------------------------------------------------------------------------------
server.use(passport.initialize());
// Initialize local login verification
passport.use("local", new localStrategy((uName, pwd, done) => {
      var findUserID = 'SELECT * FROM users WHERE username = ?';
      var checkExist = 'SELECT COUNT(*) as "ifExist" FROM users WHERE username = ?'
      db.get(checkExist, uName, (err, row) => {
          if (err) {return done (null, false, {message: "Error occured while querying"})}
          if (row == 0) {return done(null, false, {message: "User doesn't exist"})}
          db.get(findUserID, uName, (err, row) => {
              if (err) {return done(null, false, {message: 'Error occured while querying'})}
              if (pwd != row.password) {return done(null, false, {message: 'Incorrect Password'})}
              return done(null, {username: row.username, id: row.id})
              })
          })
      }));

// configuration for JWT verifications
const options = {
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken("JWT"),
      secretOrKey: JWTSecret.jwtSecret
}

// InitializeJWT verification.
// Payload: userId
// @Returns: If successful, pass in userId and userName to callback.
passport.use('jwt', new JWTstrategy(options, (jwt_payload, done) => {
      try {
          console.log("Token Verification");
          var findUserID = 'SELECT * FROM users WHERE id = ?';
          var checkExist = 'SELECT COUNT(*) as ifExist FROM users WHERE id = ?';
          db.get(checkExist, jwt_payload.id, (err, row) => {
              if (err) {return done (null, false, {message: 'Error occured while querying'})}
              if (row == 0) {return done(null, false, {message: "User doesn't exist"})}
              db.get(findUserID, jwt_payload.id , (err, row) => {
                  done(null, {username: row.username, id: row.id})});
              })
      } catch (err) {
          res.send("ERROR Verifying token");
      }
  }));





//  Endpoints specifications
//  ---------------------------------------------------------------------------------------------------------

// Check state of Database
// @Return: "ok" if in memory-database is functional.
server.post('/check', (req, res) => {
      db.get("SELECT 1", (err, row) => {
          if (err || row["1"] != 1) {
              res.status(500).send("ERROR: data base not initialized");
              return;
          } else {
              res.send({health: "ok"});
          }
      })
  })

// User Registration Endpoint
// Body: username(text), password(text)
// @Returns: creates an account iff username is not taken
server.post("/users", (req, res) => {
    var newUserName = req.body.username;
    var newPwd = req.body.password;
    var findDuplicateSQL = 'SELECT COUNT(*) as "total" FROM users WHERE username = ?';
    var insertNewUser = 'INSERT INTO users(username, password) VALUES (?, ?)';
    var retriveID = 'SELECT id FROM users where username = ?';
    if (!newUserName || !newPwd) {
        res.send("Invalid Query");
        return;
    }
    try {
      db.get(findDuplicateSQL, [newUserName], (err, row) => {
            if (row.total >= 1) {
                console.log("username has been taken.");
                res.send("ERROR: USERNAME HAS BEEN TAKEN");
                return;
            } else {
                db.run(insertNewUser, [newUserName, newPwd], (err) => {
                if (err) {
                    console.log("Error while creating new user");
                    return;
                }
                console.log("Successfully created user:" +  newUserName);
                db.get(retriveID, [newUserName], (err, row) => {
                    if (row) {
                        res.send({id: row.id});
                    } else {
                        res.send("Invalid Query");
                    }
                })
            })}})
      } catch (err) {
          res.send("Invalid Query");
      }})

// User Login Endpoint
// Body: username(text), password(text)
// @Return: if password matches with username, returns JWT token and user id.
server.post("/login", passport.authenticate('local', {session: false}), (req, res) => {
        const token = jwt.sign({id: req.user.id}, JWTSecret.jwtSecret);
        console.log("USER ID IS: " + req.user.id);
        res.status(200).send({
            id: req.user.id,
            token: token
        });
    })

// User send message endpoint
// Header: JWT bearer token
// Body: sender(int id), recipient(int id), type([string, image, video]), message: (string)
// @Returns: returns timestamp and messageID
server.post("/messages", passport.authenticate('jwt', {session: false}), (req, res) => {
      var insertMessage = 'INSERT INTO history(sender, recipient, messageType, message) VALUES (?, ?, ?, ?)';
      if (req.user.id != req.body.sender) {
         res.send("Error: Invalid token");
         return;
      }
      db.run(insertMessage, [req.body.sender, req.body.recipient, req.body.content.type, req.body.content.text], (err) => {
          if (err) {
              res.send("Error: Failed to send new message");
              return;
          } else {
              res.send({id: req.body.sender, timestamp: new Date()});
              return;
          }})
      })

// Message Retriveal endpoint.
// Header: HWT bearer token
// Body: start message ID(int) => specifies the messages to returns, in ascending order;
// recipient ID(int) => id history to retrive from
// limit: # of messages to return(DEFAULT: 100)
// @Return: Array of messages returned as Json Objects
server.get("/messages", passport.authenticate('jwt', {session: false}), (req, res) => {
    var retriveMessage = 'SELECT * FROM history WHERE id >= ? ORDER BY id ASC LIMIT ?';
    var limit = req.body.limit;
    //  If limit isn't specified, set to default 100
    if (!limit) {
        limit = 100;
    }
    db.all(retriveMessage, [req.body.start, limit], (err, rows) => {
        if (err) {
            res.send("ERROR: Failed to retrieved messages");
            return;
        }
        var result = [];
        rows.forEach((row) => {
        result.push({id: row.id, timestamp: row.timestamp,
                    sender: row.sender, recipient: row.recipient,
                    content: {type: row.messageType, text: row.message}})
                  });
        res.send({messages: result});
        return;
        })
    })
