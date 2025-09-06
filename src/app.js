import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
app.use(cors());
app.use(express.json());

// For file paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, '../public')));

// 🔹 MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/ecofinds', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error(err));

/* =======================
   USER MODEL + ROUTES
========================= */
// 🔹 User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  profile_pic: { type: String, default: '/img/default-user.png' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// JWT Secret
const SECRET = "supersecretkey"; // change in production

// Middleware to check token
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "Unauthorized" });

  try {
    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// Serve pages
app.get('', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

// 🔹 Signup API
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, profile_pic } = req.body;

    // Hash password
    const hashed = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashed,
      profile_pic
    });

    await newUser.save();
    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 🔹 Login API
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid password" });

  const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "1h" });
  res.json({ token });
});

// 🔹 Current User API
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// 🔹 Update User API
app.put('/api/me', authMiddleware, async (req, res) => {
  try {
    const { name, email, profile_pic } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { name, email, profile_pic },
      { new: true }
    ).select("-password");

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(updatedUser);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =======================
   PRODUCT MODEL + ROUTES
========================= */
// 🔹 Product Schema
const productSchema = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  image: { type: String, default: '/img/placeholder.png' },
  category: String,
  condition: { type: String, enum: ["new", "used"], default: "used" },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add a new product (logged in only)
app.post('/api/products', authMiddleware, async (req, res) => {
  try {
    const { name, description, price, image, category, condition } = req.body;

    const newProduct = new Product({
      name,
      description,
      price,
      image,
      category,
      condition,
      seller: req.userId
    });

    await newProduct.save();
    res.json(newProduct);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Update a product (only seller can update)
app.put('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    if (product.seller.toString() !== req.userId) {
      return res.status(403).json({ message: "Not authorized" });
    }

    Object.assign(product, req.body);
    await product.save();
    res.json(product);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Delete a product
app.delete('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    if (product.seller.toString() !== req.userId) {
      return res.status(403).json({ message: "Not authorized" });
    }

    await product.deleteOne();
    res.json({ message: "Product deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.listen(5000, '0.0.0.0', () => {
  console.log("🚀 Server running on http://localhost:5000");
});
