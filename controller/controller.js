const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../schema/regUserSchema");
require("dotenv").config();

exports.register = async (req, res) => {
    try {
        const { FirstName, LastName, email, password } = req.body;

        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(406).json({ message: "Account already exists. Please log in." });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate a unique userId starting from 1000
        const lastUser = await User.findOne().sort({ userId: -1 });
        const userId = lastUser ? lastUser.userId + 1 : 1000;

        // Create a new user instance
        const newUser = new User({
            userId,
            FirstName,
            LastName,
            Address: "",
            Location: "",
            Contact: "",
            email,
            password: hashedPassword,
        });

        // Save the user to the database
        await newUser.save();

        return res.status(201).json({ message: "User registered successfully", user: newUser });
    } catch (error) {
        return res.status(500).json({ message: "Server error", error: error.message });
    }
};


exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if the user exists
        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(400).json({ message: "User not found" });
        }

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, existingUser.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        // Generate JWT token
        const token = jwt.sign({ email: existingUser.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
        
        return res.status(200).json({ message: "Login successful", user: existingUser, token });
    } catch (error) {
        return res.status(500).json({ message: "Server error", error: error.message });
    }
};

exports.getUser = async (req, res) => {
    try {
        const userId = parseInt(req.params.userId);

        // Check if the user exists
        const existingUser = await User.findOne({ userId: userId });
        if (!existingUser) {
            return res.status(400).json({ message: "User not found" });
        }

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, existingUser.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        // Generate JWT token
        const token = jwt.sign({ email: existingUser.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
        
        return res.status(200).json({ message: "Login successful", user: existingUser, token });
    } catch (error) {
        return res.status(500).json({ message: "Server error", error: error.message });
    }
};