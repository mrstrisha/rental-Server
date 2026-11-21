import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient } from 'mongodb';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { ObjectId } from 'mongodb';
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const client = new MongoClient(process.env.MONGO_DB_URL);

let userCollection;
let equipmentCollection;
let bookingCollection;
let authUserCollection;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
async function run() {
  try {
    await client.connect();

    const db = client.db('equipment_rental');
    userCollection = db.collection('users');
    equipmentCollection = db.collection('equipment');
    bookingCollection = db.collection('bookings');
    authUserCollection = db.collection('user'); // Better Auth er user collection

    console.log('MongoDB Connected Successfully!');
  }  catch (error) {
    console.error("MongoDB Connection Error:", error);
    throw error;
  }
}


// Test Route
app.get('/', (req, res) => {
  res.send('Equipment Rental Platform Server is Running!');
});

// JWT Public Key
const JWKS = createRemoteJWKSet(
  new URL('http://localhost:3000/api/auth/jwks')
);

// Id diye database theke user khuje ber kore
async function findUserById(id) {
  const filter = ObjectId.isValid(id)
    ? { $or: [{ _id: new ObjectId(id) }, { id }] }
    : { id };
  return authUserCollection.findOne(filter);
}

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

    // Token thik, ebar database theke asol user ar tar role ana
    const userId = payload.sub || payload.id;

    const dbUser = await findUserById(userId);

    if (!dbUser) {
      return res.status(401).send({ message: 'User not found' });
    }

    req.user = {
      id: String(dbUser._id),
      name: dbUser.name,
      email: dbUser.email,
      role: String(dbUser.role || 'customer').toLowerCase(),
    };

    next();
  } catch (error) {
    console.log(error);

    return res.status(401).send({
      message: 'Invalid or expired token',
    });
  }
};

// Shudhu owner ra dhukte parbe
const verifyOwner = (req, res, next) => {
  if (req.user?.role !== 'owner') {
    return res.status(403).send({ message: 'Forbidden: owners only' });
  }
  next();
};

app.post("/api/owner/equipment", verifyToken, verifyOwner, async (req, res) => {
  try {
    console.log("Equipment request received");
    console.log("Logged in user:", req.user);

    const equipmentData = req.body;

    if (!equipmentCollection) {
      throw new Error("Equipment collection is not connected");
    }

    if (!req.user) {
      return res.status(401).send({
        message: "User authentication required",
      });
    }

    const newEquipment = {
      ...equipmentData,
      ownerName: req.user.name,
      ownerEmail: req.user.email,
      ownerId: req.user.id || req.user.sub,
      status: "Pending",
      createdAt: new Date(),
    };

    const result = await equipmentCollection.insertOne(newEquipment);

    res.status(201).send({
      success: true,
      message: "Equipment added successfully",
      result,
    });

  } catch (error) {
    console.error("Equipment Error:", error);

    res.status(500).send({
      success: false,
      message: error.message || "Failed to add equipment",
    });
  }
});

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


// ---------- Owner: My Equipment ----------

// Equipment er je field gulo update kora jabe
const allowedFields = [
  'name', 'description', 'category', 'location', 'rentalPrice', 'rentalType',
  'quantity', 'condition', 'brand', 'model', 'image', 'terms',
];

// GET: owner er nijer equipment
app.get('/api/owner/equipment', verifyToken, verifyOwner, async (req, res) => {
  try {
    const result = await equipmentCollection
      .find({ ownerId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to get equipment' });
  }
});

// PUT: equipment update (shudhu nijer ta)
app.put('/api/owner/equipment/:id', verifyToken, verifyOwner, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: 'Invalid id' });
    }

    const item = await equipmentCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!item) return res.status(404).send({ message: 'Equipment not found' });

    // Onner equipment hole 403
    if (item.ownerId !== req.user.id) {
      return res.status(403).send({ message: 'This is not your equipment' });
    }

    const updatedData = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) updatedData[field] = req.body[field];
    }

    await equipmentCollection.updateOne(
      { _id: item._id },
      { $set: { ...updatedData, updatedAt: new Date() } }
    );
    res.send({ message: 'Equipment updated' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update equipment' });
  }
});

// DELETE: equipment delete (shudhu nijer ta)
app.delete('/api/owner/equipment/:id', verifyToken, verifyOwner, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: 'Invalid id' });
    }

    const item = await equipmentCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!item) return res.status(404).send({ message: 'Equipment not found' });

    if (item.ownerId !== req.user.id) {
      return res.status(403).send({ message: 'This is not your equipment' });
    }

    await equipmentCollection.deleteOne({ _id: item._id });
    res.send({ message: 'Equipment deleted' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to delete equipment' });
  }
});

// ---------- Owner: My Equipment Rental ----------

// GET: owner er equipment e jara booking korese
app.get('/api/owner/bookings', verifyToken, verifyOwner, async (req, res) => {
  try {
    const result = await bookingCollection
      .find({ ownerId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to get bookings' });
  }
});

// ---------- Profile (customer, owner, admin shobar) ----------

// GET: nijer profile
app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const dbUser = await findUserById(req.user.id);
    if (!dbUser) return res.status(404).send({ message: 'User not found' });

    res.send({
      name: dbUser.name || '',
      email: dbUser.email || '',
      image: dbUser.image || '',
      phone: dbUser.phone || '',
      address: dbUser.address || '',
      role: req.user.role,
    });
  } catch (error) {
    res.status(500).send({ message: 'Failed to get profile' });
  }
});

// PUT: phone ar address update (email ar role kokhono bodlay na)
app.put('/api/profile', verifyToken, async (req, res) => {
  try {
    const { phone, address } = req.body;
    const dbUser = await findUserById(req.user.id);
    if (!dbUser) return res.status(404).send({ message: 'User not found' });

    await authUserCollection.updateOne(
      { _id: dbUser._id },
      {
        $set: {
          phone: String(phone || '').trim().slice(0, 20),
          address: String(address || '').trim().slice(0, 300),
          updatedAt: new Date(),
        },
      }
    );
    res.send({ message: 'Profile updated' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update profile' });
  }
});


// Server
async function startServer() {
  try {
    await run();

    if (!equipmentCollection) {
      throw new Error("Equipment collection initialization failed");
    }

    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });

  } catch (error) {
    console.error("Server startup failed:", error);
  }
}

startServer();
