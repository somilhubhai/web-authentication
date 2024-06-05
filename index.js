const express = require("express");
const crypto = require("crypto");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const PORT = 5000;

if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

const app = express();
app.use(express.static("./public"));
app.use(express.json());
//states
const challengeStore = {};
const userStore = {};
app.post("/register", (req, res) => {
  const { userName, password } = req.body;
  const id = `user_${Date.now()}`;

  const user = {
    id,
    userName,
    password,
  };
  userStore[id] = user;
  return res.json({ id });
});

app.post("/register-challenge", async (req, res) => {
  const { userId } = req.body;

  if (!userStore[userId]) {
    return res.json({ error: "user not found" });
  }
  const user = userStore[userId];
  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "my localhost",
    userName: user.userName,
  });
  challengeStore[userId] = challengePayload.challenge;
  return res.json({ options: challengePayload });
});

app.post("/register-verify", async (req, res) => {
  const { userId, cred } = req.body;
  const challenge = challengeStore[userId];
  const verificationResult = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:5000",
    expectedRPID: "localhost",
    response: cred,
  });
  if (!verificationResult.verified)
    return res.json({ error: "could not verify user" });

  userStore[userId].passkey = verificationResult.registrationInfo;
  return res.json({ verified: true });
});

app.post("/login-challenge", async (req, res) => {
  const { userId } = req.body;
  const opts = await generateAuthenticationOptions({
    rpID: "localhost",
  });
  challengeStore[userId] = opts.challenge;
  return res.json({ options: opts });
});

app.post("/login-verify", async (req, res) => {
  const { userId, cred } = req.body;
  const user = userStore[userId];
  const challenge = challengeStore[userId];

  const result = await verifyAuthenticationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:5000/",
    expectedRPID: "localhost",
    response: cred,
    authenticator: user.passkey,
  });
  if (!result.verified) return res.json({ error: "something went wrong" });
  return res.json({ success: true, userId });
});

app.listen(PORT, () => console.log(`Server started at PORT : ${PORT}`));
