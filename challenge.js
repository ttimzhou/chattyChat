// const http = require("http");
const sqlite3 = require("sqlite3").verbose();
const express = require('express');
const server = express();
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const JWTstrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;
const bodyParser = require("body-parser");
const JWTSecret = require("./JWTSecret");
const jwt = require("jsonwebtoken")
server.use(bodyParser.json());



const db = new sqlite3.Database("challenge.db");
db.run('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username text, password text)')
db.run('CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY AUTOINCREMENT, sender text, recipient text, messageType text, message text, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')

server.listen(8000, () => {
  console.log("Listening on port 8000");
})

server.use(passport.initialize());
// Initialize local login verification
//
passport.use("local", new localStrategy(
  function(uName, pwd, done) {
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
  }
));

const options = {
  jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken("JWT"),
  secretOrKey: JWTSecret.jwtSecret
}

// InitializeJWT verification.
// @Returns: If successful, pass in userId and userName to callback.
passport.use('jwt', new JWTstrategy(options, (jwt_payload, done) => {
  console.log("HI");
  try {
    console.log("Hello");
    var findUserID = 'SELECT * FROM users WHERE id = ?';
    var checkExist = 'SELECT COUNT(*) as ifExist FROM users WHERE id = ?'
    console.log("PAYLOAD: " + jwt_payload.id);
    db.get(checkExist, jwt_payload.id, (err, row) => {
      if (err) {return done (null, false, {message: 'Error occured while querying'})}
      if (row == 0) {return done(null, false, {message: "User doesn't exist"})}
      db.get(findUserID, jwt_payload.id , (err, row) => {
        done(null, {username: row.username, id: row.id})
        })
      })
    } catch(err) {
      res.send("ERROR Verifying token")
    }
  })
);


server.post("/users", (req, res) => {
    var newUserName = req.body.username;
    var newPwd = req.body.password;
    var findDuplicateSQL = 'SELECT COUNT(*) as "total" FROM users WHERE username = ?';
    var insertNewUser = 'INSERT INTO users(username, password) VALUES (?, ?)';
    var retriveID = 'SELECT id FROM users where username = ?'
    if (!newUserName || !newPwd) {
      res.send("Invalid Query");
      return
    }
    try {
      db.get(findDuplicateSQL, [newUserName], (err, row) => {
          if (row.total >= 1) {
            console.log("username has been taken.")
            res.send("ERROR: USERNAME HAS BEEN TAKEN")
            return
          } else {
            db.run(insertNewUser, [newUserName, newPwd], (err) => {
              if (err) {
                console.log("Error while creating new user");
                return
              }
              console.log("Successfully created user:" +  newUserName);
              db.get(retriveID, [newUserName], (err, row) => {
                  if (row) {
                      res.send({id: row.id});
                  } else {
                    res.send("Invalid Query")
                  }
              })
            })

          }
      })
    } catch (err) {
      res.send("Invalid Query")
    }
  })

server.post("/login", passport.authenticate('local', {session: false}), (req, res) => {
        const token = jwt.sign({id: req.user.id}, JWTSecret.jwtSecret);
        console.log("USER ID IS: " + req.user.id)
        res.status(200).send({
          id: req.user.id,
          token: token
        })
})


server.post("/messages", passport.authenticate('jwt', {session: false}), (req, res) => {
      var insertMessage = 'INSERT INTO history(sender, recipient, messageType, message) VALUES (?, ?, ?, ?)'
      if (req.user.id != req.body.sender) {
         res.send("Error: Invalid token")
         return
      }
      db.run(insertMessage, [req.body.sender, req.body.recipient, req.body.content.type, req.body.content.text]
        , (err) => {
          if (err) {
            res.send("Error: Failed to send new message");
            return
          } else {
            res.send({id: req.body.sender, timestamp: new Date()});
            return
          }
        })
})


server.get("/messages", passport.authenticate('jwt', {session: false}), (req, res) => {
    var retriveMessage = 'SELECT * FROM history WHERE id >= ? ORDER BY id ASC LIMIT ?';
    var limit = req.body.limit;
//  If limit isn't specified, set to default 100
    if (!limit) {
      limit = 100;
    }
    console.log(req.body.start);
    db.all(retriveMessage, [req.body.start, limit], (err, rows) => {
      if (err) {
        res.send("ERROR: Failed to retrieved messages")
        return
      }
      var result = []
      rows.forEach((row) => {
        result.push({id: row.id, timestamp: row.timestamp,
                      sender: row.sender, recipient: row.recipient,
                    content: {type: row.messageType, text: row.message}})
      })
      res.send({message: result});
      return
      })
})

server.post('/check', (req, res) => {
    res.send({health: "ok"});
})










//
// app.post("/check", (req, res) => {
//
// })



//
//
// const server = http.createServer((message, response) => {
//   if (message.method === "POST" && message.url === "/check") {
//     db.get("SELECT 1", (err, row) => {
//       if (err || row["1"] != 1) {
//         response.statusCode = 500;
//         response.end();
//         return;
//       }
//
//       response.write(JSON.stringify({ health: "ok" }));
//       response.end();
//     });
//     return;
//   }
//
//
//   response.statusCode = 400;
//   response.end();
// });
//
// server.listen(8080, "127.0.0.1");
