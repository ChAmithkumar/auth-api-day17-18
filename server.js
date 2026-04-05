require("dotenv").config();



const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");


const User = require("./models/User");
const auth = require("./middleware/auth");
const isAdmin = require("./middleware/isAdmin");
const blacklist = require("./utils/blacklist");


const app = express();
app.use(express.json());
app.use(cors());

// DB
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));


app.get("/", (req, res) => {
    res.send("API is working 🚀");
});

/* ================= SIGNUP ================= */
app.post("/signup", async (req, res) => {
    const { name, email, password, role } = req.body;

    const exist = await User.findOne({ email });
    if (exist) return res.status(400).json({ msg: "Email exists" });

    const hash = await bcrypt.hash(password, 10);

    const user = new User({ name, email, password: hash, role });
    await user.save();

    res.json({ msg: "Signup success" });
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ msg: "Wrong password" });

    const token = jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );

    res.json({ token });
});


/* ================= USERS ================= */

app.get("/users", auth, async (req, res) => {
    const users = await User.find().select("-password");
    res.json(users);
});

app.post("/users", async (req, res) => {
    const { name, email } = req.body;
    const hash = await bcrypt.hash("123456", 10);
    const user = new User({ name, email, password: hash });
    await user.save();
    res.json(user);
});

//
app.put("/users/:id", auth, async (req, res) => {
    const { name } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
        req.params.id,
        { name },
        { new: true }
    );

    res.json(updatedUser);
});

app.delete("/users/:id", async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ msg: "Deleted" });
});

/* ================= PROFILE ================= */
app.get("/profile", auth, async (req, res) => {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
});

/* ================= ADMIN ================= */
app.get("/admin", auth, isAdmin, (req, res) => {
    res.json({ msg: "Admin access" });
});

/* ================= LOGOUT ================= */
app.post("/logout", (req, res) => {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (token) blacklist.push(token);
    res.json({ msg: "Logged out" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
/* ================= START ================= */
app.listen(3000, () => console.log("Server running http://localhost:3000"));