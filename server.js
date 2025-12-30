// server.js
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const sql = require("mssql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config(); // for JWT_SECRET

// ✅ Middleware
app.use(express.json());
app.use(cors());
app.use(bodyParser.json());

// ✅ SQL Server Configuration
const dbConfig = {
  user: "sa",
  password: "1234",
  server: "127.0.0.1",
  database: "SportsCubeDB",
  port: 1433,
  options: {
    encrypt: true,
    trustServerCertificate: true,
  },
};

// ✅ Connect to SQL Server
let poolPromise;
(async function initPool() {
  try {
    poolPromise = await sql.connect(dbConfig);
    console.log("✅ Connected to SQL Server");
  } catch (err) {
    console.error("❌ SQL Connection Error:", err);
  }
})();

// ✅ JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// ✅ JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) return res.status(401).json({ message: "Access denied" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user; // contains { id: userId }
    next();
  });
}

// ✅ SIGNUP API
app.post("/signup", async (req, res) => {
  const { name, email, password, phone = "", address = "" } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "Name, email, and password are required!" });
  }

  try {
    const pool = await sql.connect(dbConfig);

    // Check if user exists
    const existingUser = await pool
      .request()
      .input("email", sql.VarChar, email)
      .query("SELECT * FROM Users WHERE email=@email");

    if (existingUser.recordset.length > 0) {
      return res.json({ success: false, message: "User already exists!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user with all columns
    await pool
      .request()
      .input("name", sql.VarChar, name)
      .input("email", sql.VarChar, email)
      .input("password", sql.VarChar, hashedPassword)
      .input("phone", sql.VarChar, phone)
      .input("address", sql.VarChar, address)
      .query(`
        INSERT INTO Users (name, email, password, phone, address, createdAt)
        VALUES (@name, @email, @password, @phone, @address, GETDATE())
      `);

    res.json({ success: true, message: "Account created successfully!" });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ success: false, message: "Server error during signup" });
  }
});

// ✅ LOGIN API
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password required" });
  }

  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool
      .request()
      .input("email", sql.VarChar, email)
      .query("SELECT * FROM Users WHERE email=@email");

    if (result.recordset.length === 0) {
      return res.json({ success: false, message: "User not found!" });
    }

    const user = result.recordset[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.json({ success: false, message: "Incorrect password!" });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });

    res.json({
      success: true,
      message: "Login successful!",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        address: user.address,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ success: false, message: "Server error during login" });
  }
});

// ✅ PLACE ORDER API
app.post("/place-order", authenticateToken, async (req, res) => {
  try {
    const { cartItems, phone, address } = req.body;

    if (!cartItems || cartItems.length === 0) {
      return res.status(400).json({ message: "Cart is empty" });
    }
    if (!phone || !address) {
      return res.status(400).json({ message: "Phone and address required" });
    }

    const pool = await sql.connect(dbConfig);

    for (const item of cartItems) {
      await pool
        .request()
        .input("UserId", sql.Int, req.user.id)
        .input("ProductName", sql.NVarChar, item.name)
        .input("Size", sql.NVarChar, item.size)
        .input("Price", sql.Decimal(10, 2), parseFloat(item.price))
        .input("Quantity", sql.Int, parseInt(item.quantity))
        .input("Phone", sql.NVarChar, phone)
        .input("Address", sql.NVarChar, address)
        .query(`
          INSERT INTO Orders (UserId, ProductName, Size, Price, Quantity, Phone, Address)
          VALUES (@UserId, @ProductName, @Size, @Price, @Quantity, @Phone, @Address)
        `);
    }

    res.status(200).json({ message: "Order placed successfully!" });
  } catch (err) {
    console.error("Order Error:", err);
    res.status(500).json({ message: "Error placing order" });
  }
});
app.get("/profile", authenticateToken, async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);

        const result = await pool
            .request()
            .input("id", sql.Int, req.user.id)
            .query("SELECT id, name, email, phone, address, createdAt FROM Users WHERE id=@id");

        if (result.recordset.length === 0) {
            return res.json({ success: false, message: "User not found" });
        }

        res.json({ success: true, user: result.recordset[0] });

    } catch (error) {
        console.error("Profile Error:", error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});


// ✅ Start Server
app.listen(3000, () => console.log("🚀 Server running on http://localhost:3000"));
