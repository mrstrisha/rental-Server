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
let sessionCollection;
let accountCollection;

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
    sessionCollection = db.collection('session'); // Better Auth er session
    accountCollection = db.collection('account'); // Better Auth er account

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

// Shudhu admin ra dhukte parbe
const verifyAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).send({ message: 'Forbidden: admins only' });
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


// =====================================================
// ADMIN: Page 1 - All Users
// =====================================================

// GET: shob user
app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await authUserCollection.find().sort({ createdAt: -1 }).toArray();

    const result = users.map((u) => ({
      id: String(u._id),
      name: u.name,
      email: u.email,
      role: String(u.role || 'customer').toLowerCase(),
      createdAt: u.createdAt,
    }));

    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to get users' });
  }
});

// PATCH: user er role bodlano (customer, owner, admin)
app.patch('/api/admin/users/:id/role', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { role } = req.body;

    if (!['customer', 'owner', 'admin'].includes(role)) {
      return res.status(400).send({ message: 'Role must be customer, owner or admin' });
    }
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: 'Invalid id' });
    }
    // Nijer role bodlano jabe na
    if (req.params.id === req.user.id) {
      return res.status(403).send({ message: 'You cannot change your own role' });
    }

    const result = await authUserCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'User not found' });
    }
    res.send({ message: `Role updated to ${role}` });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update role' });
  }
});

// DELETE: user delete (Manage Users)
app.delete('/api/admin/users/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: 'Invalid id' });
    }
    // Nijeke delete kora jabe na
    if (req.params.id === req.user.id) {
      return res.status(403).send({ message: 'You cannot delete yourself' });
    }

    const id = req.params.id;
    const result = await authUserCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'User not found' });
    }

    // Oi user er login session ar account o muche dao
    await sessionCollection.deleteMany({ userId: { $in: [id, new ObjectId(id)] } });
    await accountCollection.deleteMany({ userId: { $in: [id, new ObjectId(id)] } });

    res.send({ message: 'User deleted' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to delete user' });
  }
});

// =====================================================
// ADMIN: Page 2 - All Equipment
// =====================================================

// GET: shob equipment
app.get('/api/admin/equipment', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await equipmentCollection.find().sort({ createdAt: -1 }).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to get equipment' });
  }
});

// PATCH: Approve / Reject
app.patch('/api/admin/equipment/:id/status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;

    if (!['approved', 'rejected', 'pending'].includes(status)) {
      return res.status(400).send({ message: 'Invalid status' });
    }
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: 'Invalid id' });
    }

    const result = await equipmentCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'Equipment not found' });
    }
    res.send({ message: `Equipment ${status}` });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update status' });
  }
});

// PUT: Update (admin je kono equipment update korte pare)
app.put('/api/admin/equipment/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: 'Invalid id' });
    }

    const updatedData = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) updatedData[field] = req.body[field];
    }

    const result = await equipmentCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { ...updatedData, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'Equipment not found' });
    }
    res.send({ message: 'Equipment updated' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update equipment' });
  }
});

// DELETE: Delete
app.delete('/api/admin/equipment/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: 'Invalid id' });
    }

    const result = await equipmentCollection.deleteOne({ _id: new ObjectId(req.params.id) });

    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'Equipment not found' });
    }
    res.send({ message: 'Equipment deleted' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to delete equipment' });
  }
});

// =====================================================
// ADMIN: Page 3 - All Rentals
// =====================================================

// GET: shob booking (owner er naam na thakle database theke ene dei)
app.get('/api/admin/bookings', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const bookings = await bookingCollection.find().sort({ createdAt: -1 }).toArray();

    const result = await Promise.all(
      bookings.map(async (b) => {
        if (b.ownerName || !b.ownerId) return b;
        const owner = await findUserById(b.ownerId);
        return { ...b, ownerName: owner?.name, ownerEmail: owner?.email };
      })
    );

    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to get bookings' });
  }
});

// PATCH: booking status bodlano
app.patch('/api/admin/bookings/:id/status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;

    if (!['pending', 'confirmed', 'completed', 'cancelled', 'rejected'].includes(status)) {
      return res.status(400).send({ message: 'Invalid status' });
    }
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: 'Invalid id' });
    }

    const result = await bookingCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { bookingStatus: status, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'Booking not found' });
    }
    res.send({ message: 'Booking updated' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update booking' });
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
