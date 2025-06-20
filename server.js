const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/money-tracker', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Ledger Schema
const ledgerSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  name: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Ledger = mongoose.model('Ledger', ledgerSchema);

// Entry Schema
const entrySchema = new mongoose.Schema({
  ledgerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Ledger', required: true },
  creditor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Person who gave money
  debtor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Person who owes money
  amount: { type: Number, required: true },
  description: { type: String, required: true },
  type: { type: String, enum: ['debt', 'payment'], default: 'debt' }, // debt = someone owes money, payment = paying back debt
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'close_requested', 'closed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  approvedAt: { type: Date },
  closeRequestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  closeRequestedAt: { type: Date },
  closedAt: { type: Date }
});

const Entry = mongoose.model('Entry', entrySchema);

// Auth middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.user = decoded;
    console.log('Authenticated user:', req.user); // Debug log
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Routes

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret');
    res.status(201).json({ 
      token, 
      user: { id: user._id, username: user.username, email: user.email } 
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret');
    res.json({ 
      token, 
      user: { id: user._id, username: user.username, email: user.email } 
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user profile
app.get('/api/user', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Search users
app.get('/api/users/search', authMiddleware, async (req, res) => {
  try {
    const { query } = req.query;
    const users = await User.find({
      $and: [
        { _id: { $ne: req.user.userId } },
        {
          $or: [
            { username: { $regex: query, $options: 'i' } },
            { email: { $regex: query, $options: 'i' } }
          ]
        }
      ]
    }).select('-password').limit(10);
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Create ledger
app.post('/api/ledgers', authMiddleware, async (req, res) => {
  try {
    const { name, participantIds } = req.body;
    
    const participants = [req.user.userId, ...participantIds];
    const ledger = new Ledger({
      name,
      participants,
      createdBy: req.user.userId
    });
    
    await ledger.save();
    await ledger.populate('participants', 'username email');
    
    res.status(201).json(ledger);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user's ledgers
app.get('/api/ledgers', authMiddleware, async (req, res) => {
  try {
    const ledgers = await Ledger.find({
      participants: req.user.userId
    }).populate('participants', 'username email').populate('createdBy', 'username email');
    
    res.json(ledgers);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Add entry to ledger
app.post('/api/entries', authMiddleware, async (req, res) => {
  try {
    const { ledgerId, debtorId, creditorId, amount, description, type = 'debt' } = req.body;
    
    // Verify user is part of the ledger
    const ledger = await Ledger.findById(ledgerId);
    console.log('Ledger found:', ledger);
    console.log('User ID:', req.user.userId);
    console.log('Participants:', ledger?.participants);
    
    if (!ledger) {
      return res.status(404).json({ message: 'Ledger not found' });
    }
    
    // Convert ObjectId to string for comparison
    const participantIds = ledger.participants.map(id => id.toString());
    if (!participantIds.includes(req.user.userId.toString())) {
      return res.status(403).json({ message: 'Access denied - not a participant' });
    }
    
    let entryCreditor, entryDebtor;
    
    if (type === 'debt') {
      // For debt entries: current user is creditor (lending money)
      entryCreditor = req.user.userId;
      entryDebtor = debtorId;
    } else if (type === 'payment') {
      // For payment entries: current user is debtor (paying money), other person is creditor (receiving money)
      entryCreditor = creditorId; // Person receiving the payment
      entryDebtor = req.user.userId; // Person making the payment
    } else {
      return res.status(400).json({ message: 'Invalid entry type' });
    }
    
    const entry = new Entry({
      ledgerId,
      creditor: entryCreditor,
      debtor: entryDebtor,
      amount,
      description,
      type
    });
    
    await entry.save();
    await entry.populate('creditor', 'username email');
    await entry.populate('debtor', 'username email');
    
    res.status(201).json(entry);
  } catch (error) {
    console.error('Add entry error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get entries for a ledger
app.get('/api/ledgers/:ledgerId/entries', authMiddleware, async (req, res) => {
  try {
    const { ledgerId } = req.params;
    
    // Verify user is part of the ledger
    const ledger = await Ledger.findById(ledgerId);
    if (!ledger) {
      return res.status(404).json({ message: 'Ledger not found' });
    }
    
    // Convert ObjectId to string for comparison
    const participantIds = ledger.participants.map(id => id.toString());
    if (!participantIds.includes(req.user.userId.toString())) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    const entries = await Entry.find({ ledgerId })
      .populate('creditor', 'username email')
      .populate('debtor', 'username email')
      .populate('closeRequestedBy', 'username email')
      .sort({ createdAt: -1 });
    
    console.log('Entries being returned:', entries.map(e => ({
      id: e._id,
      type: e.type,
      amount: e.amount,
      status: e.status,
      creditor: e.creditor.username,
      debtor: e.debtor.username
    })));
    
    res.json(entries);
  } catch (error) {
    console.error('Get entries error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Approve/Reject entry or Close transaction
app.patch('/api/entries/:entryId', authMiddleware, async (req, res) => {
  try {
    const { entryId } = req.params;
    const { status, action } = req.body; // 'approved', 'rejected', or action: 'request_close', 'approve_close', 'reject_close'
    
    const entry = await Entry.findById(entryId);
    if (!entry) {
      return res.status(404).json({ message: 'Entry not found' });
    }

    // Handle close transaction requests
    if (action === 'request_close') {
      // Only creditor or debtor can request to close
      if (entry.creditor.toString() !== req.user.userId.toString() && 
          entry.debtor.toString() !== req.user.userId.toString()) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      // Only approved entries can be closed
      if (entry.status !== 'approved') {
        return res.status(400).json({ message: 'Only approved entries can be closed' });
      }

      entry.status = 'close_requested';
      entry.closeRequestedBy = req.user.userId;
      entry.closeRequestedAt = new Date();
      
      await entry.save();
      await entry.populate('creditor', 'username email');
      await entry.populate('debtor', 'username email');
      await entry.populate('closeRequestedBy', 'username email');

      return res.json(entry);
    }

    // Handle close approval/rejection
    if (action === 'approve_close' || action === 'reject_close') {
      if (entry.status !== 'close_requested') {
        return res.status(400).json({ message: 'No close request to respond to' });
      }

      // Only the other party (not the one who requested) can approve/reject
      if (entry.closeRequestedBy.toString() === req.user.userId.toString()) {
        return res.status(403).json({ message: 'Cannot respond to your own close request' });
      }

      // Must be either creditor or debtor
      if (entry.creditor.toString() !== req.user.userId.toString() && 
          entry.debtor.toString() !== req.user.userId.toString()) {
        return res.status(403).json({ message: 'Access denied' });
      }

      if (action === 'approve_close') {
        entry.status = 'closed';
        entry.closedAt = new Date();
      } else {
        entry.status = 'approved'; // Revert back to approved
        entry.closeRequestedBy = undefined;
        entry.closeRequestedAt = undefined;
      }

      await entry.save();
      await entry.populate('creditor', 'username email');
      await entry.populate('debtor', 'username email');
      if (entry.closeRequestedBy) {
        await entry.populate('closeRequestedBy', 'username email');
      }

      return res.json(entry);
    }

    // Original approve/reject logic for pending entries
    if (status && ['approved', 'rejected'].includes(status)) {
      
      if (entry.status !== 'pending') {
        return res.status(400).json({ message: 'Entry is not pending' });
      }

      // For debt entries: only debtor can approve/reject
      // For payment entries: only creditor can approve/reject
      let canApprove = false;
      if (entry.type === 'debt') {
        canApprove = entry.debtor.toString() === req.user.userId.toString();
      } else if (entry.type === 'payment') {
        canApprove = entry.creditor.toString() === req.user.userId.toString();
      }

      if (!canApprove) {
        return res.status(403).json({ message: 'Access denied - you cannot approve/reject this entry' });
      }

      entry.status = status;
      if (status === 'approved') {
        entry.approvedAt = new Date();
      }

      await entry.save();
      await entry.populate('creditor', 'username email');
      await entry.populate('debtor', 'username email');

      return res.json(entry);
    }

    return res.status(400).json({ message: 'Invalid action or status' });
  } catch (error) {
    console.error('Entry action error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get pending close requests for user
app.get('/api/entries/close-requests', authMiddleware, async (req, res) => {
  try {
    const entries = await Entry.find({
      $and: [
        { status: 'close_requested' },
        { closeRequestedBy: { $ne: req.user.userId } }, // Not requested by current user
        {
          $or: [
            { creditor: req.user.userId },
            { debtor: req.user.userId }
          ]
        }
      ]
    }).populate('creditor', 'username email')
      .populate('debtor', 'username email')
      .populate('closeRequestedBy', 'username email')
      .populate('ledgerId', 'name')
      .sort({ closeRequestedAt: -1 });
    
    res.json(entries);
  } catch (error) {
    console.error('Close requests error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get pending entries for user
app.get('/api/entries/pending', authMiddleware, async (req, res) => {
  try {
    console.log('Fetching pending entries for user:', req.user.userId);
    
    // Get entries where:
    // 1. For debt entries: user is the debtor (needs to approve debt)
    // 2. For payment entries: user is the creditor (needs to approve payment received)
    const entries = await Entry.find({
      $and: [
        { status: 'pending' },
        {
          $or: [
            // Debt entries where user is debtor
            { 
              type: 'debt',
              debtor: req.user.userId 
            },
            // Payment entries where user is creditor  
            { 
              type: 'payment',
              creditor: req.user.userId 
            },
            // Handle entries without type (backward compatibility) - treat as debt
            {
              type: { $exists: false },
              debtor: req.user.userId
            }
          ]
        }
      ]
    }).populate('creditor', 'username email')
      .populate('debtor', 'username email')
      .populate('ledgerId', 'name')
      .sort({ createdAt: -1 });
    
    console.log('Found pending entries:', entries.length);
    res.json(entries);
  } catch (error) {
    console.error('Pending entries error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});