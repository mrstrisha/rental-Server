
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient } from 'mongodb';
import { createRemoteJWKSet, jwtVerify } from 'jose';

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const client = new MongoClient(process.env.MONGO_DB_URL);

let userCollection;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
async function run() {
  try {
    await client.connect();

    const db = client.db('equipment_rental');
    userCollection = db.collection('users');

    console.log('MongoDB Connected Successfully!');
  } catch (error) {
    console.log(error);
  }
}

run();

// Test Route
app.get('/', (req, res) => {
  res.send('Equipment Rental Platform Server is Running!');
});

// JWT Public Key
const JWKS = createRemoteJWKSet(
  new URL('http://localhost:3000/api/auth/jwks')
);

// Verify Token Middleware
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({
      message: 'Unauthorized',
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: 'http://localhost:3000',
      audience: 'http://localhost:3000',
    });

    req.user = payload;

    next();
  } catch (error) {
    console.log(error);

    return res.status(401).send({
      message: 'Invalid or expired token',
    });
  }
};

// Protected Route
app.get('/protected', verifyToken, (req, res) => {
  res.send({
    message: 'You are authenticated!',
    user: req.user,
  });
});

// Get Users (Protected)
app.get('/users', verifyToken, async (req, res) => {
  try {
    const result = await userCollection.find().toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({
      message: 'Failed to get users',
    });
  }
});

// Create User (Protected)
app.post('/users', verifyToken, async (req, res) => {
  try {
    const userData = req.body;

    const result = await userCollection.insertOne(userData);

    res.send(result);
  } catch (error) {
    res.status(500).send({
      message: 'Failed to create user',
    });
  }
});

// Server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
