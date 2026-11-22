import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient } from 'mongodb';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { ObjectId } from 'mongodb';
import Stripe from 'stripe';
import { fileURLToPath } from 'url';

dotenv.config();
// Local monorepo convenience only; Vercel uses project environment variables.
dotenv.config({ path: fileURLToPath(new URL('../equipmentrental/.env', import.meta.url)) });

const app = express();
const port = process.env.PORT || 5000;
const frontendUrl = process.env.FRONTEND_URL || process.env.BETTER_AUTH_URL || 'http://localhost:3000';
// Better Auth signs JWTs with BETTER_AUTH_URL; verification must use the same value.
const authUrl = process.env.BETTER_AUTH_URL || frontendUrl;

let stripe;
function getStripe() {
  if (!stripe) {
    if (!process.env.STRIPE_SECRET_KEY) {
      throw new Error('STRIPE_SECRET_KEY is not configured');
    }
    stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
  }
  return stripe;
}

let client;
function getMongoClient() {
  if (!client) {
    if (!process.env.MONGO_DB_URL) {
      throw new Error('MONGO_DB_URL is not configured');
    }
    client = new MongoClient(process.env.MONGO_DB_URL);
  }
  return client;
}

let userCollection;
let equipmentCollection;
let bookingCollection;
let authUserCollection;
let sessionCollection;
let accountCollection;
let favoriteCollection;
let paymentCollection;

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://rental-client-wine.vercel.app',
    frontendUrl,
  ].filter(Boolean),
  credentials: true
}));
// Stripe needs the exact raw body for signature verification.
app.use('/api/webhooks/stripe', express.raw({ type: 'application/json' }));
app.use(express.json());

// MongoDB Connection
async function run() {
  try {
    await getMongoClient().connect();

    const db = client.db('equipment_rental');
    userCollection = db.collection('users');
    equipmentCollection = db.collection('equipment');
    bookingCollection = db.collection('bookings');
    authUserCollection = db.collection('user'); // Better Auth er user collection
    sessionCollection = db.collection('session'); // Better Auth er session
    accountCollection = db.collection('account'); // Better Auth er account
    favoriteCollection = db.collection('favorites'); // Customer favorites
    paymentCollection = db.collection('payments'); // Stripe payment transactions

    await paymentCollection.createIndex({ stripeSessionId: 1 }, { unique: true });
    await paymentCollection.createIndex(
      { stripePaymentIntentId: 1 },
      { unique: true, partialFilterExpression: { stripePaymentIntentId: { $type: 'string' } } }
    );

    console.log('MongoDB Connected Successfully!');
  }  catch (error) {
    console.error("MongoDB Connection Error:", error);
    throw error;
  }
}

let dbReady;
function ensureDb() {
  if (!dbReady) {
    dbReady = run().catch((error) => {
      dbReady = null;
      throw error;
    });
  }
  return dbReady;
}


// Test Route
app.get('/', (req, res) => {
  res.send('Equipment Rental Platform Server is Running!');
});

// Serverless-safe database initialization (cached per warm instance).
app.use(async (req, res, next) => {
  try {
    await ensureDb();
    next();
  } catch (error) {
    console.error('Database initialization failed:', error.message);
    res.status(500).send({ message: 'Database is not available' });
  }
});

// JWT Public Key
const JWKS = createRemoteJWKSet(
  new URL(`${authUrl}/api/auth/jwks`)
);

// Id diye database theke user khuje ber kore
async function findUserById(id) {
  const filter = ObjectId.isValid(id)
    ? { $or: [{ _id: new ObjectId(id) }, { id }] }
    : { id };
  return authUserCollection.findOne(filter);
}

// ID diye equipment khuje ber kore
async function findEquipmentById(id) {
  if (!ObjectId.isValid(id)) return null;
  return equipmentCollection.findOne({ _id: new ObjectId(id) });
}

// Status gulo ek-i format e rakhar jonno
function normalizeStatus(value) {
  const status = String(value || '').toLowerCase();
  if (status === 'approved') return 'Approved';
  if (status === 'rejected') return 'Rejected';
  if (status === 'pending') return 'Pending';
  return '';
}

// Public details page a login thakle user chine (login na thakle null)
async function getOptionalUser(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;

  try {
    const token = authHeader.split(' ')[1];
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: authUrl,
      audience: authUrl,
    });
    const dbUser = await findUserById(payload.sub || payload.id);
    if (!dbUser) return null;

    return {
      id: String(dbUser._id),
      name: dbUser.name,
      email: dbUser.email,
      role: String(dbUser.role || 'customer').toLowerCase(),
    };
  } catch {
    return null;
  }
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

// Shudhu customer ra dhukte parbe
const verifyCustomer = (req, res, next) => {
  if (req.user?.role !== 'customer') {
    return res.status(403).send({ message: 'Forbidden: customers only' });
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
      updatedAt: new Date(),
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

    const currentStatus = normalizeStatus(item.status) || 'Pending';
    const importantChanged = allowedFields.some((field) =>
      updatedData[field] !== undefined && String(updatedData[field]) !== String(item[field] ?? '')
    );
    const nextStatus = currentStatus === 'Approved' && importantChanged ? 'Pending' : currentStatus;

    await equipmentCollection.updateOne(
      { _id: item._id },
      { $set: { ...updatedData, status: nextStatus, updatedAt: new Date() } }
    );
    res.send({
      message: 'Equipment updated',
      status: nextStatus,
      reapprovalRequired: currentStatus === 'Approved' && importantChanged,
    });
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
// EQUIPMENT: Browse and details (logged in users)
// =====================================================

// GET: approved equipment (public browse page)
app.get('/api/equipment', async (req, res) => {
  try {
    // Homepage ke jonno chobi limit kora jay; baire default behavior one bojay thake.
    const requestedLimit = Number(req.query.limit);
    const limit = Number.isFinite(requestedLimit) && requestedLimit > 0
      ? Math.min(Math.floor(requestedLimit), 6)
      : 0;

    let query = equipmentCollection
      .find({ status: { $in: ['Approved', 'approved'] } })
      .sort({ createdAt: -1 });

    if (limit > 0) query = query.limit(limit);

    const result = await query.toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to get equipment' });
  }
});

// GET: single equipment details (public, approved items only)
app.get('/api/equipment/:id', async (req, res) => {
  try {
    const item = await findEquipmentById(req.params.id);
    if (!item) return res.status(404).send({ message: 'Equipment not found' });

    const user = await getOptionalUser(req);
    const status = String(item.status || '').toLowerCase();
    const isOwner = String(item.ownerId || '') === user?.id;
    const isAdmin = user?.role === 'admin';

    if (status !== 'approved' && !isOwner && !isAdmin) {
      return res.status(404).send({ message: 'Equipment not found' });
    }

    res.send(item);
  } catch (error) {
    res.status(500).send({ message: 'Failed to get equipment' });
  }
});

// =====================================================
// CUSTOMER: Favorites
// =====================================================

// POST: add equipment to current customer's favorites
app.post('/api/customer/favorites', verifyToken, verifyCustomer, async (req, res) => {
  try {
    const { equipmentId } = req.body;
    const id = String(equipmentId || '');

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: 'Invalid equipment id' });
    }

    const equipment = await findEquipmentById(id);
    if (!equipment) return res.status(404).send({ message: 'Equipment not found' });
    if (String(equipment.status || '').toLowerCase() !== 'approved') {
      return res.status(400).send({ message: 'Only approved equipment can be saved' });
    }

    const alreadySaved = await favoriteCollection.findOne({
      customerId: req.user.id,
      equipmentId: id,
    });
    if (alreadySaved) {
      return res.send({ message: 'Already in favorites' });
    }

    await favoriteCollection.insertOne({
      customerId: req.user.id,
      equipmentId: id,
      createdAt: new Date(),
    });

    res.status(201).send({ message: 'Added to favorites' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to add favorite' });
  }
});

// GET: current customer's favorites with equipment details
app.get('/api/customer/favorites', verifyToken, verifyCustomer, async (req, res) => {
  try {
    const favorites = await favoriteCollection
      .find({ customerId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();

    const items = await Promise.all(
      favorites.map(async (favorite) => {
        const equipment = await findEquipmentById(favorite.equipmentId);
        if (!equipment) return null;
        return {
          ...equipment,
          _id: String(equipment._id),
          favoriteId: String(favorite._id),
          favoritedAt: favorite.createdAt,
        };
      })
    );

    res.send(items.filter(Boolean));
  } catch (error) {
    res.status(500).send({ message: 'Failed to get favorites' });
  }
});

// DELETE: remove one favorite (customer identity comes from the token)
app.delete('/api/customer/favorites/:id', verifyToken, verifyCustomer, async (req, res) => {
  try {
    const result = await favoriteCollection.deleteOne({
      customerId: req.user.id,
      equipmentId: req.params.id,
    });

    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'Favorite not found' });
    }

    res.send({ message: 'Removed from favorites' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to remove favorite' });
  }
});

// =====================================================
// STRIPE HELPERS
// =====================================================

function stripeObjectId(value) {
  if (!value) return null;
  return typeof value === 'string' ? value : value.id || null;
}

function bookingIdFromSession(session) {
  const reference = session.client_reference_id || session.metadata?.bookingId;
  return ObjectId.isValid(reference) ? new ObjectId(reference) : null;
}

async function markCheckoutSessionPaid(session) {
  const bookingId = bookingIdFromSession(session);
  if (!bookingId) return;

  const booking = await bookingCollection.findOne({ _id: bookingId });
  if (!booking) return;

  const paymentIntentId = stripeObjectId(session.payment_intent);
  const amountPaid = Number(session.amount_total || 0) / 100;
  const nextBookingStatus = booking.bookingStatus === 'cancelled' ? 'cancelled' : 'confirmed';

  await bookingCollection.updateOne(
    { _id: bookingId, paymentStatus: { $ne: 'paid' } },
    {
      $set: {
        paymentStatus: 'paid',
        bookingStatus: nextBookingStatus,
        stripeSessionId: session.id,
        stripePaymentIntentId: paymentIntentId,
        amountPaid,
        currency: session.currency || 'usd',
        paidAt: new Date(),
        updatedAt: new Date(),
      },
    }
  );

  await paymentCollection.updateOne(
    { stripeSessionId: session.id },
    {
      $setOnInsert: {
        bookingId,
        customerId: booking.customerId,
        customerEmail: booking.customerEmail,
        equipmentId: booking.equipmentId,
        equipmentName: booking.equipmentName,
        stripeSessionId: session.id,
        currency: session.currency || 'usd',
        createdAt: new Date(),
      },
      $set: {
        stripePaymentIntentId: paymentIntentId,
        amount: amountPaid,
        status: 'paid',
        bookingStatus: nextBookingStatus,
        updatedAt: new Date(),
      },
    },
    { upsert: true }
  );
}

async function markCheckoutSessionUnpaid(session, status) {
  const bookingId = bookingIdFromSession(session);
  if (!bookingId) return;

  const booking = await bookingCollection.findOne({ _id: bookingId });
  if (!booking) return;

  await bookingCollection.updateOne(
    { _id: bookingId, paymentStatus: { $ne: 'paid' } },
    {
      $set: {
        paymentStatus: 'unpaid',
        bookingStatus: 'cancelled',
        updatedAt: new Date(),
      },
    }
  );

  await paymentCollection.updateOne(
    { stripeSessionId: session.id },
    {
      $setOnInsert: {
        bookingId,
        customerId: booking.customerId,
        customerEmail: booking.customerEmail,
        equipmentId: booking.equipmentId,
        equipmentName: booking.equipmentName,
        stripeSessionId: session.id,
        currency: session.currency || 'usd',
        createdAt: new Date(),
      },
      $set: {
        stripePaymentIntentId: stripeObjectId(session.payment_intent),
        amount: Number(session.amount_total || 0) / 100,
        status,
        bookingStatus: 'cancelled',
        updatedAt: new Date(),
      },
    },
    { upsert: true }
  );
}

// =====================================================
// CUSTOMER: My rentals / bookings
// =====================================================

// GET: only the logged-in customer's bookings
app.get('/api/customer/bookings', verifyToken, verifyCustomer, async (req, res) => {
  try {
    const result = await bookingCollection
      .find({ customerId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to get bookings' });
  }
});

// POST: validate booking, create a Stripe Checkout Session, then store the pending booking
app.post('/api/customer/bookings', verifyToken, verifyCustomer, async (req, res) => {
  let createdSessionId = null;

  try {
    const { equipmentId, startDate, endDate, quantity, phone, deliveryAddress, notes } = req.body;
    const id = String(equipmentId || '');

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: 'Invalid equipment id' });
    }

    const equipment = await findEquipmentById(id);
    if (!equipment) return res.status(404).send({ message: 'Equipment not found' });
    if (String(equipment.status || '').toLowerCase() !== 'approved') {
      return res.status(400).send({ message: 'This equipment is not available yet' });
    }

    const start = new Date(startDate);
    const end = new Date(endDate);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end < start) {
      return res.status(400).send({ message: 'Invalid rental dates' });
    }

    const qty = Number(quantity);
    if (!Number.isInteger(qty) || qty <= 0) {
      return res.status(400).send({ message: 'Quantity must be a positive whole number' });
    }
    if (Number(equipment.quantity || 0) < qty) {
      return res.status(400).send({ message: 'Requested quantity is not available' });
    }

    const overlappingBooking = await bookingCollection.findOne({
      equipmentId: id,
      bookingStatus: { $nin: ['cancelled', 'rejected'] },
      startDate: { $lte: end },
      endDate: { $gte: start },
    });
    if (overlappingBooking) {
      return res.status(400).send({ message: 'Equipment is already booked for these dates' });
    }

    const days = Math.max(1, Math.ceil((end.getTime() - start.getTime()) / 86400000));
    // Rental type hishebe unit hisob: Daily -> day, Weekly -> week, Monthly -> month.
    const rentalType = String(equipment.rentalType || 'Daily').toLowerCase();
    const units = rentalType === 'weekly'
      ? Math.max(1, Math.ceil(days / 7))
      : rentalType === 'monthly'
      ? Math.max(1, Math.ceil(days / 30))
      : days;
    // Amount is always calculated here from stored equipment data; frontend totals are ignored.
    const totalAmount = Number(equipment.rentalPrice || 0) * units * qty;
    const bookingId = new ObjectId();

    const session = await getStripe().checkout.sessions.create({
      mode: 'payment',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: equipment.name || 'Equipment rental',
              description: `${units} ${rentalType} unit(s) x ${qty}`,
            },
            unit_amount: Math.round(Number(equipment.rentalPrice || 0) * 100),
          },
          quantity: units * qty,
        },
      ],
      client_reference_id: String(bookingId),
      customer_email: req.user.email,
      metadata: {
        bookingId: String(bookingId),
        equipmentId: id,
        customerId: String(req.user.id),
      },
      success_url: `${frontendUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${frontendUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}&canceled=1`,
    });

    createdSessionId = session.id;
    if (!session.url) {
      throw new Error('Stripe did not return a checkout URL');
    }

    const newBooking = {
      _id: bookingId,
      customerId: req.user.id,
      customerName: req.user.name,
      customerEmail: req.user.email,
      equipmentId: id,
      equipmentName: equipment.name,
      ownerId: String(equipment.ownerId || ''),
      ownerName: equipment.ownerName || '',
      ownerEmail: equipment.ownerEmail || '',
      startDate: start,
      endDate: end,
      quantity: qty,
      phone: String(phone || ''),
      deliveryAddress: String(deliveryAddress || ''),
      notes: String(notes || ''),
      totalAmount,
      stripeSessionId: session.id,
      stripePaymentIntentId: null,
      stripeAmountTotal: Number(session.amount_total || 0) / 100,
      currency: session.currency || 'usd',
      paymentStatus: 'unpaid',
      bookingStatus: 'pending',
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    await bookingCollection.insertOne(newBooking);
    res.status(201).send({
      success: true,
      message: 'Checkout session created',
      checkoutUrl: session.url,
      sessionId: session.id,
      bookingId: String(bookingId),
      totalAmount,
    });
  } catch (error) {
    if (createdSessionId) {
      await getStripe().checkout.sessions.expire(createdSessionId).catch(() => {});
    }
    console.error('Checkout session creation failed:', error.message);
    res.status(500).send({ message: 'Could not start payment' });
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
    const status = normalizeStatus(req.body.status);

    if (!status) {
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


// =====================================================
// STRIPE WEBHOOK
// =====================================================

app.post('/api/webhooks/stripe', async (req, res) => {
  const signature = req.headers['stripe-signature'];
  if (!signature) {
    return res.status(400).send({ message: 'Missing Stripe signature' });
  }

  if (!process.env.STRIPE_SECRET_KEY || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(500).send({ message: 'Stripe is not configured' });
  }

  let event;
  try {
    event = getStripe().webhooks.constructEvent(req.body, signature, process.env.STRIPE_WEBHOOK_SECRET);
  } catch {
    return res.status(400).send({ message: 'Invalid Stripe webhook signature' });
  }

  try {
    if (
      event.type === 'checkout.session.completed' ||
      event.type === 'checkout.session.async_payment_succeeded'
    ) {
      const session = event.data.object;
      if (session.payment_status === 'paid') {
        await markCheckoutSessionPaid(session);
      }
    } else if (
      event.type === 'checkout.session.expired' ||
      event.type === 'checkout.session.async_payment_failed'
    ) {
      await markCheckoutSessionUnpaid(event.data.object, 'failed');
    }

    res.json({ received: true });
  } catch (error) {
    console.error('Stripe webhook processing failed:', error.message);
    res.status(500).send({ message: 'Webhook processing failed' });
  }
});

// Vercel best practice: keep function state predictable on unhandled errors.
app.use((err, req, res, next) => {
  console.error('Unhandled route error:', err.message);
  if (!res.headersSent) {
    res.status(500).send({ message: 'Internal server error' });
  }
});

// Server
async function startServer() {
  try {
    await ensureDb();

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

// Vercel invokes the exported handler; local development still uses app.listen.
if (process.env.VERCEL !== '1') {
  startServer();
}

export default app;
