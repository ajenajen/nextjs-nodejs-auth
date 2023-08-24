const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());

app.use(express.json());
app.use(express.static("./public"));

const users = [
  { id: 1, name: "John", password: "P@ssw0rd", refresh: null },
  { id: 2, name: "Tom", password: "P@ssw0rd", refresh: null },
  { id: 3, name: "Chris", password: "P@ssw0rd", refresh: null },
  { id: 4, name: "David", password: "P@ssw0rd", refresh: null },
];

// Running server //
app
  .listen(port, () => {
    console.log("Server is running on port " + port);
  })
  .on("error", (err) => {
    console.log(err);
    process.exit();
  });

const jwtGenerate = (user) => {
  const accessToken = jwt.sign(
    { name: user.name, id: user.id },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_EXPIRES_IN, algorithm: "HS256" }
  );

  return accessToken;
};

const jwtRefreshTokenGenerate = (user) => {
  const refreshToken = jwt.sign(
    { name: user.name, id: user.id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_EXPIRES_IN, algorithm: "HS256" }
  );

  return refreshToken;
};

const jwtValidate = (req, res, next) => {
  try {
    if (!req.headers["authorization"]) return res.sendStatus(401);

    const token = req.headers["authorization"].replace("Bearer ", "");

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) throw new Error(error);
    });

    next();
  } catch (error) {
    return res.sendStatus(403);
  }
};

const jwtRefreshTokenValidate = (req, res, next) => {
  try {
    if (!req.headers["authorization"]) return res.sendStatus(401);
    const token = req.headers["authorization"].replace("Bearer ", "");

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
      if (err) throw new Error(error);

      req.user = decoded;
      req.user.token = token;
      delete req.user.exp;
      delete req.user.iat;
    });
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
};

app.get("/", jwtValidate, (req, res) => {
  res.send("Hello World!");
});

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;

  //find user
  const user = users.findIndex((e) => e.name === username);
  const validated = users[user]?.password === password;

  if (!username || user < 0 || !validated) {
    return res.send(400);
  }

  const access_token = jwtGenerate(users[user]);
  const refresh_token = jwtRefreshTokenGenerate(users[user]);

  users[user].refresh = refresh_token;

  res.json({
    access_token,
    refresh_token,
  });
});

app.post("/auth/refresh", jwtRefreshTokenValidate, (req, res) => {
  const user = users.find(
    (e) => e.id === req.user.id && e.name === req.user.name
  );

  const userIndex = users.findIndex((e) => e.refresh === req.user.token);

  if (!user || userIndex < 0) return res.sendStatus(401);

  const access_token = jwtGenerate(user);
  const refresh_token = jwtRefreshTokenGenerate(user);
  users[userIndex].refresh = refresh_token;

  return res.json({
    access_token,
    refresh_token,
  });
});
