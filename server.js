require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: ['http://localhost:3000', 'https://your-frontend-url.vercel.app'],
    credentials: true
}));
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/practice-tracker', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB successfully');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// Add error handler
mongoose.connection.on('error', err => {
    console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected');
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    instruments: [{ type: String }],
    categories: [{ type: String }],
    practiceSessions: [{
        date: Date,
        duration: Number,
        instrument: String,
        category: String,
        notes: String
    }]
});

const User = mongoose.model('User', userSchema);

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            console.error('Token verification error:', err);
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes
// Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ message: 'Username or email already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user with default instruments
        const user = new User({
            username,
            email,
            password: hashedPassword,
            instruments: ['Oboe', 'Clarinet', 'Trumpet', 'Trombone', 'Saxophone'],
            categories: ['Technique', 'Repertoire', 'Scales', 'Sight Reading']
        });

        await user.save();

        // Generate token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );

        res.status(201).json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error creating user' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );

        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in' });
    }
});

// Get user data
app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching user data' });
    }
});

// Update user data
app.put('/api/user', authenticateToken, async (req, res) => {
    try {
        const { instruments, categories, practiceSessions } = req.body;
        const user = await User.findById(req.user.userId);
        
        if (instruments) user.instruments = instruments;
        if (categories) user.categories = categories;
        if (practiceSessions) user.practiceSessions = practiceSessions;

        await user.save();
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error updating user data' });
    }
});

// Add practice session
app.post('/api/user/practice', authenticateToken, async (req, res) => {
    console.log('Received practice session request');
    console.log('User:', req.user);
    console.log('Body:', req.body);
    
    try {
        const { instrument, category, duration, notes, date } = req.body;
        
        // Validate required fields
        if (!instrument || !category || !duration) {
            console.log('Missing required fields:', { instrument, category, duration });
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // Create new practice session
        const practiceSession = {
            instrument,
            category,
            duration: parseInt(duration),
            notes,
            date: new Date(date)
        };

        console.log('Looking for user with ID:', req.user.userId);
        // Add practice session to user's data
        const user = await User.findById(req.user.userId);
        if (!user) {
            console.log('User not found with ID:', req.user.userId);
            return res.status(404).json({ message: 'User not found' });
        }

        user.practiceSessions.push(practiceSession);
        await user.save();

        console.log('Practice session saved successfully');
        res.json(user);
    } catch (error) {
        console.error('Error adding practice session:', error);
        res.status(500).json({ message: 'Error adding practice session' });
    }
});

// Delete account
app.delete('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        await User.findByIdAndDelete(req.user.userId);
        res.json({ message: 'Account deleted successfully' });
    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ message: 'Error deleting account' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 