const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
      openapi: '3.0.0',
      info: {
          title: 'Welcome To Group Battleship Game',
          version: '1.0.0'
      },
      components: {  // Add 'components' section
          securitySchemes: {  // Define 'securitySchemes'
              bearerAuth: {  // Define 'bearerAuth'
                  type: 'http',
                  scheme: 'bearer',
                  bearerFormat: 'JWT'
              }
          }
      }
  },
  apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const uri = "mongodb+srv://ainfaqihah:Ain_020803@cluster0.5nmy5.mongodb.net/";
const client = new MongoClient(uri);
app.use(express.json());

const dbName = "battleship_game"; // Replace with your actual database name
let db;

async function connectToDB() {
  try {
    await client.connect(); // Connect to the MongoDB server
    db = client.db(dbName); // Select the database
    console.log(`Connected to database: ${dbName}`);
  } catch (error) {
    console.error("Error connecting to the database", error);
  }
}

connectToDB();



/**
 * @swagger
 * /admin/login:
 *   post:
 *     summary: Authenticate admin user
 *     description: Login with admin credentials to receive a JWT token.
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: Admin username
 *                 example: admin_user
 *               password:
 *                 type: string
 *                 description: Admin password
 *                 example: password123
 *     responses:
 *       '200':
 *         description: Login successful, returns a JWT token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT token for authenticated requests
 *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *       '401':
 *         description: Unauthorized - Invalid credentials.
 *       '500':
 *         description: Internal server error.
 */

// Authentication: Admin Login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  console.log(`Received login attempt with username: ${username}`);

  const admin = await client.db("gameDB").collection("admins").findOne({ username });

  if (admin) {
    console.log(`Admin found with username: ${username}`);
    const isPasswordValid = bcrypt.compareSync(password, admin.password);
    console.log(`Password valid: ${isPasswordValid}`);

    if (isPasswordValid) {
      const token = jwt.sign({ userId: admin._id, role: 'admin' }, 'secretkey', { expiresIn: '1h' });
      return res.send({ token });
    }
  }

  res.status(401).send('Invalid credentials');
});

/**
 * @swagger
 * /admin/logout:
 *   post:
 *     summary: Admin logout
 *     description: Logs out an admin by invalidating their token and adding it to the blacklist.
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: "admin123"
 *               password:
 *                 type: string
 *                 example: "securePassword123"
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Admin successfully logged out and token invalidated.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Logged out successfully"
 *       '401':
 *         description: Invalid credentials provided (username or password is incorrect).
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Invalid credentials"
 *       '403':
 *         description: Forbidden access (only the logged-in admin can log out).
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Unauthorized to log out this admin"
 *       '404':
 *         description: Admin not found in the database.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Admin not found"
 *       '500':
 *         description: Internal server error occurred during the logout process.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Internal server error"
 */

// Authentication: Admin Logout
app.post('/admin/logout', verifyToken, async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find admin by username
    const admin = await client.db("gameDB").collection("admins").findOne({ username });

    if (!admin) {
      return res.status(404).send('Admin not found');
    }

    // Verify admin's password
    const isPasswordValid = bcrypt.compareSync(password, admin.password);
    if (!isPasswordValid) {
      return res.status(401).send('Invalid credentials');
    }

    // Verify if the token belongs to an admin
    if (req.user.role === 'admin') {
      const adminIdFromToken = req.user.userId;

      if (adminIdFromToken !== admin._id.toString()) {
        return res.status(403).send('Unauthorized to log out this admin');
      }
    } else {
      return res.status(403).send('Admin access required');
    }

    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

    // Add token to the blacklist
    await client.db("gameDB").collection("blacklist").insertOne({ token });
    res.send({ message: 'Logged out successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});




/**
 * @swagger
 * /player/signup:
 *   post:
 *     summary: Sign up a new player
 *     description: Create a new player account with a username and password.
 *     tags:
 *       - Player
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: Desired username for the new player
 *                 example: player1
 *               password:
 *                 type: string
 *                 description: Password for the new player
 *                 example: password123
 *     responses:
 *       '201':
 *         description: Player signed up successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Player signed up
 *                 playerId:
 *                   type: string
 *                   description: ID of the newly created player
 *                   example: 60a7b4f5313e5a001d6fe8a9
 *       '400':
 *         description: Bad Request - Username already taken.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Error message
 *                   example: Username already taken
 *       '500':
 *         description: Internal server error.
 */
// Authentication: Player Sign Up
app.post('/player/signup', async (req, res) => {
    const { username, password } = req.body;
  
    const existingPlayer = await client.db("gameDB").collection("players").findOne({ username });
    if (existingPlayer) {
      return res.status(400).send({ message: 'Username already taken' });
    }
  
    // Check the password strength
    const passwordValidation = isStrongPassword(password);
    if (passwordValidation !== true) {
      return res.status(400).send({ message: passwordValidation.join(' ') });
    }
  
    const hashedPassword = bcrypt.hashSync(password, 10);
  
    try {
      const result = await client.db("gameDB").collection("players").insertOne({ username, password: hashedPassword });
      res.status(201).send({ message: 'Player signed up', playerId: result.insertedId });
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal server error');
    }
  });

/**
 * @swagger
 * /player/login:
 *   post:
 *     summary: Sign in a player
 *     description: Authenticate a player with their username and password to receive a JWT token.
 *     tags:
 *       - Player
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: Player's username
 *                 example: player1
 *               password:
 *                 type: string
 *                 description: Player's password
 *                 example: password123
 *     responses:
 *       '200':
 *         description: Login successful, returns a JWT token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT token for authenticated requests
 *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *       '401':
 *         description: Unauthorized - Invalid credentials.
 *       '500':
 *         description: Internal server error.
 */

// Authentication: Player Sign In
app.post('/player/login', async (req, res) => {
  const { username, password } = req.body;

  const player = await client.db("gameDB").collection("players").findOne({ username });

  if (player) {
    const isPasswordValid = bcrypt.compareSync(password, player.password);

    if (isPasswordValid) {
      const token = jwt.sign({ userId: player._id, role: 'player' }, 'secretkey', { expiresIn: '1h' });
      return res.send({ token });
    }
  }

  res.status(401).send('Invalid credentials');
});

/**
 * @swagger
 * /player/logout:
 *   post:
 *     summary: Player sign out
 *     description: Logs out a player by invalidating their token and adding it to the blacklist. Admin can log out players as well.
 *     tags:
 *       - Player
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: "player123"
 *               password:
 *                 type: string
 *                 example: "playerPassword123"
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Player successfully logged out and token invalidated (or admin logged out a player).
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Logged out successfully"
 *       '401':
 *         description: Invalid credentials provided (username or password is incorrect).
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Invalid credentials"
 *       '403':
 *         description: Forbidden access (player trying to log out another player or an unauthorized admin action).
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Unauthorized to log out this player"
 *       '404':
 *         description: Player not found in the database.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Player not found"
 *       '500':
 *         description: Internal server error occurred during the logout process.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Internal server error"
 */

// Authentication: Player Sign Out
app.post('/player/logout', verifyToken, async (req, res) => {
  const { username, password } = req.body;

  try {
    // Verify if the token belongs to the current user (player)
    if (req.user.role === 'player') {
      const playerIdFromToken = req.user.userId;

      // Find the player by username to verify identity
      const player = await client.db("gameDB").collection("players").findOne({ username });
      if (!player) {
        return res.status(404).send('Player not found');
      }

      // Verify player's password
      const isPasswordValid = bcrypt.compareSync(password, player.password);
      if (!isPasswordValid) {
        return res.status(401).send('Invalid credentials');
      }

      // Ensure the player can only log out themselves
      if (playerIdFromToken !== player._id.toString()) {
        return res.status(403).send('Unauthorized to log out this player');
      }

      // Add player's token to the blacklist
      const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
      await client.db("gameDB").collection("blacklist").insertOne({ token });

      res.send({ message: 'Logged out successfully' });

    } else if (req.user.role === 'admin') {
      // Admins can log out players, but not other admins
      // Directly proceed to log out the player based on token

      const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

      // Ensure admin token is not added to blacklist
      res.send({ message: 'Logged out successfully' });
    }

  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

// Middleware for Authorization
async function verifyToken(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).send('Access denied');

  try {
    const blacklistedToken = await client.db("gameDB").collection("blacklist").findOne({ token });
    if (blacklistedToken) return res.status(403).send('Invalid token');
    
    jwt.verify(token, 'secretkey', (err, decoded) => {
      if (err) return res.status(403).send('Invalid token');
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
}

// Middleware for Authorization: Admin Only
function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).send('Admin access required');
  next();
}

// Middleware for Authorization: Player Only
function isPlayer(req, res, next) {
  if (req.user.role !== 'player') return res.status(403).send('Player access required');
  next();
}

// Middleware for Authorization: Admin or Player (to access their own data)
async function isAdminOrPlayer(req, res, next) {
  const { id } = req.params;

  try {
    // Check if the endpoint is for a game or a player
    const game = await client.db("gameDB").collection("games").findOne({ _id: new ObjectId(id) });
    const player = await client.db("gameDB").collection("players").findOne({ _id: new ObjectId(id) });

    if (game) {
      // Endpoint is for a game
      if (req.user.role === 'admin') {
        return next(); // Admins can access any game
      }

      // Check if the user is one of the players associated with the game
      if (req.user.userId === game.player1.toString() || req.user.userId === game.player2.toString()) {
        return next();
      }

      // If neither admin nor player, deny access
      return res.status(403).send('Access denied');
    } else if (player) {
      // Endpoint is for a player
      if (req.user.role === 'admin' || req.user.userId === player._id.toString()) {
        return next(); // Admins can access any player, players can access their own data
      }

      // If neither admin nor the player themselves, deny access
      return res.status(403).send('Access denied');
    } else {
      // Neither game nor player found with the given ID
      return res.status(404).send('Resource not found');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
}

// CRUD for Players

/**
 * @swagger
 * /player:
 *   post:
 *     summary: Create a new player
 *     description: Allows an admin to create a new player account with a username and password. Requires admin authorization.
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: Desired username for the new player
 *                 example: player2
 *               password:
 *                 type: string
 *                 description: Password for the new player
 *                 example: password456
 *     responses:
 *       '201':
 *         description: Player created successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Player created
 *                 playerId:
 *                   type: string
 *                   description: ID of the newly created player
 *                   example: 60a7b4f5313e5a001d6fe8a9
 *       '400':
 *         description: Bad Request - Username already taken.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Error message
 *                   example: Username already taken
 *       '401':
 *         description: Unauthorized - Invalid token or insufficient permissions.
 *       '500':
 *         description: Internal server error.
 */

// Create a Player (Only Admin)
app.post('/player', verifyToken, isAdmin, async (req, res) => {
    const { username, password } = req.body;
  
    // Check the password strength
    const passwordValidation = isStrongPassword(password);
    if (passwordValidation !== true) {
      return res.status(400).send({ message: passwordValidation.join(' ') });
    }
  
    const existingPlayer = await client.db("gameDB").collection("players").findOne({ username });
    if (existingPlayer) {
      return res.status(400).send({ message: 'Username already taken' });
    }
  
    const hashedPassword = bcrypt.hashSync(password, 10);
  
    try {
      const result = await client.db("gameDB").collection("players").insertOne({ username, password: hashedPassword });
      res.status(201).send({ message: 'Player created', playerId: result.insertedId });
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal server error');
    }
  });

/**
 * @swagger
 * /players:
 *   get:
 *     summary: Retrieve all players (Admin only)
 *     description: Allows an admin to retrieve a list of all players from the game database.
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: A list of all players in the database.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: string
 *                     description: The unique ID of the player.
 *                     example: 60a7b4f5313e5a001d6fe8a9
 *                   username:
 *                     type: string
 *                     description: The username of the player.
 *                     example: playerOne
 *                   email:
 *                     type: string
 *                     description: The email address of the player.
 *                     example: playerOne@example.com
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *                     description: The date and time when the player was created.
 *                     example: '2025-01-18T14:25:00Z'
 *       '403':
 *         description: Forbidden, the user is not an admin.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "You do not have permission to access this resource."
 *       '500':
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Internal server error"
 */

// Read all Players (Admin only)
app.get('/players', verifyToken, isAdmin, async (req, res) => {
  try {
    const players = await client.db("gameDB").collection("players").find().toArray();
    res.send(players);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

/**
 * @swagger
 * /player/{id}:
 *   patch:
 *     summary: Update a player's information (Player can update their own data, Admin can update any)
 *     description: Allows a player to update their username or password. Admin can update any player's data.
 *     tags:
 *       - Admin
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The unique ID of the player to update.
 *         schema:
 *           type: string
 *           example: 60a7b4f5313e5a001d6fe8a9
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The new username for the player.
 *                 example: playerNewUsername
 *               password:
 *                 type: string
 *                 description: The new password for the player (hashed).
 *                 example: newpassword123
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Player data updated successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Player updated"
 *       '400':
 *         description: Bad request, such as when the username is already taken.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Username already taken"
 *       '404':
 *         description: Player not found or no updates made.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Player not found"
 *       '500':
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Internal server error"
 */

// Update a Player by ID (Player can update their own data, Admin can update any)
app.patch('/player/:id', verifyToken, isAdminOrPlayer, async (req, res) => {
  const { id } = req.params;
  const { username, password } = req.body;

  try {
    const player = await client.db("gameDB").collection("players").findOne({ _id: new ObjectId(id) });

    if (!player) {
      return res.status(404).send('Player not found');
    }

    // Initialize an empty object to hold updates
    const updates = {};

    // Check if the new username is provided and is different from the current one
    if (username && username !== player.username) {
      const existingPlayer = await client.db("gameDB").collection("players").findOne({ username });
      if (existingPlayer) {
        return res.status(400).send({ message: 'Username already taken' });
      }
      updates.username = username;
    }

    // Check if a new password is provided and is different from the current one
    if (password) {
      const isPasswordValid = bcrypt.compareSync(password, player.password);
      if (!isPasswordValid) {
        const hashedPassword = bcrypt.hashSync(password, 10);
        updates.password = hashedPassword;
      }
    }

    // If no updates were made, respond with "No changes made"
    if (Object.keys(updates).length === 0) {
      return res.send({ message: 'No changes made' });
    }

    // Perform the update
    const result = await client.db("gameDB").collection("players").updateOne(
      { _id: new ObjectId(id) },
      { $set: updates }
    );

    if (result.matchedCount > 0) {
      res.send({ message: 'Player updated' });
    } else {
      res.status(404).send('Player not found');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});


/**
 * @swagger
 * /player/{id}:
 *   delete:
 *     summary: Delete a player by ID (Admin only)
 *     description: Allows an admin to delete a player from the system by their ID.
 *     tags:
 *       - Admin
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The unique ID of the player to delete.
 *         schema:
 *           type: string
 *           example: 60a7b4f5313e5a001d6fe8a9
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Player deleted successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Player deleted"
 *       '404':
 *         description: Player not found.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Player not found"
 *       '500':
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Internal server error"
 */

// Delete a Player by ID (Admin only)
app.delete('/player/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const result = await client.db("gameDB").collection("players").deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount > 0) res.send({ message: 'Player deleted' });
    else res.status(404).send('Player not found');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

// Battleship Game Logic

// Creating battleship function

const GRID_SIZE = 10;
const SHIPS = [
    { name: 'Aircraft Carrier', size: 5 },
    { name: 'Battleship', size: 4 },
    { name: 'Cruiser', size: 3 },
    { name: 'Submarine', size: 3 },
    { name: 'Destroyer', size: 2 }
];

function createGame() {
    // Initialize game boards for both players
    const board1 = Array.from({ length: GRID_SIZE }, () => Array(GRID_SIZE).fill('~'));
    const board2 = Array.from({ length: GRID_SIZE }, () => Array(GRID_SIZE).fill('~'));
  
    // Initialize ships for both players
    const ships1 = SHIPS.map(ship => ({
      name: ship.name,
      size: ship.size,
      placed: false, // Indicates if ship is placed on the board
      coordinates: [] // Coordinates of ship placement
    }));
    const ships2 = SHIPS.map(ship => ({
      name: ship.name,
      size: ship.size,
      placed: false,
      coordinates: []
    }));
  
    // Return the initial game object
    return {
      board1,
      board2,
      ships1,
      ships2,
      currentPlayer: null, // Initial player turn (can be set later)
      gameStatus: 'pending' // Initial game status
    };
  }

  // Function to fetch player usernames from player IDs
  async function fetchPlayerUsernames(player1Id, player2Id) {
    try {
      const player1 = await client.db("gameDB").collection("players").findOne({ _id: new ObjectId(player1Id) });
      const player2 = player2Id ? await client.db("gameDB").collection("players").findOne({ _id: new ObjectId(player2Id) }) : null;
  
      const username1 = player1 ? player1.username : "Unknown";
      const username2 = player2 ? player2.username : "Unknown";
  
      return { username1, username2 };
    } catch (error) {
      console.error("Error fetching player usernames:", error);
      return { username1: "Unknown", username2: "Unknown" };
    }
  }

  /**
 * @swagger
 * /game:
 *   post:
 *     summary: Create a new Battleship game
 *     description: Allows a player to create a new Battleship game. Requires player authorization.
 *     tags:
 *       - Game
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '201':
 *         description: Game created successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Game created
 *                 gameId:
 *                   type: string
 *                   description: ID of the newly created game
 *                   example: 60a7b4f5313e5a001d6fe8a9
 *       '401':
 *         description: Unauthorized - Invalid token or insufficient permissions.
 *       '500':
 *         description: Internal server error.
 */

// Battleship Game Routes
app.post('/game', verifyToken, isPlayer, async (req, res) => {
    try {
      const game = createGame();
      const result = await client.db("gameDB").collection("games").insertOne({ ...game, player1: req.user.userId });
      res.status(201).send({ message: 'Game created', gameId: result.insertedId });
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal server error');
    }
  });

  /**
 * @swagger
 * /game/{id}:
 *   get:
 *     summary: Get game information
 *     description: Retrieve information about a specific game, including player usernames, current player, and board states. Requires authorization.
 *     tags:
 *       - Game
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the game to retrieve
 *         schema:
 *           type: string
 *           example: 60a7b4f5313e5a001d6fe8a9
 *     responses:
 *       '200':
 *         description: Game information retrieved successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 gameId:
 *                   type: string
 *                   description: ID of the game
 *                   example: 60a7b4f5313e5a001d6fe8a9
 *                 currentPlayer:
 *                   type: string
 *                   description: ID of the current player
 *                   example: 60a7b4f5313e5a001d6fe8b0
 *                 player1:
 *                   type: object
 *                   properties:
 *                     userId:
 *                       type: string
 *                       description: ID of player 1
 *                       example: 60a7b4f5313e5a001d6fe8b1
 *                     username:
 *                       type: string
 *                       description: Username of player 1
 *                       example: player1
 *                 player2:
 *                   type: object
 *                   nullable: true
 *                   properties:
 *                     userId:
 *                       type: string
 *                       description: ID of player 2
 *                       example: 60a7b4f5313e5a001d6fe8b2
 *                     username:
 *                       type: string
 *                       description: Username of player 2
 *                       example: player2
 *                 board1:
 *                   type: array
 *                   items:
 *                     type: array
 *                     items:
 *                       type: string
 *                       description: Board state for player 1
 *                 board2:
 *                   type: array
 *                   items:
 *                     type: array
 *                     items:
 *                       type: string
 *                       description: Board state for player 2
 *                 ships1:
 *                   type: array
 *                   items:
 *                     type: object
 *                     description: Ships for player 1
 *                 ships2:
 *                   type: array
 *                   items:
 *                     type: object
 *                     description: Ships for player 2
 *       '404':
 *         description: Game not found.
 *       '401':
 *         description: Unauthorized - Invalid token or insufficient permissions.
 *       '500':
 *         description: Internal server error.
 */

// Get game information including player usernames
app.get('/game/:id', verifyToken, isAdminOrPlayer, async (req, res) => {
  const { id } = req.params;

  try {
    const game = await client.db("gameDB").collection("games").findOne({ _id: new ObjectId(id) });
    if (!game) return res.status(404).send('Game not found');

    // Fetch usernames for player1 and player2 using the function
    const { username1, username2 } = await fetchPlayerUsernames(game.player1, game.player2);

    const response = {
      gameId: game._id,
      currentPlayer: game.currentPlayer,
      player1: {
        userId: game.player1,
        username: username1
      },
      player2: game.player2 ? {
        userId: game.player2,
        username: username2
      } : null,
      board1: game.board1,
      board2: game.board2,
      ships1: game.ships1,
      ships2: game.ships2
    };

    res.send(response);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});
  

/**
 * @swagger
 * /game/{id}/join:
 *   post:
 *     summary: Join an existing game as Player 2
 *     description: Allows a player to join an existing game as Player 2. The player cannot join their own game, and the game must not already have two players. Requires player authorization.
 *     tags:
 *       - Game
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the game to join.
 *         schema:
 *           type: string
 *           example: 60a7b4f5313e5a001d6fe8a9
 *     responses:
 *       '200':
 *         description: Successfully joined the game.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Joined game
 *       '400':
 *         description: Bad request - Game already full or player attempting to join their own game.
 *         content:
 *           application/json:
 *             schema:
 *               type: string
 *               example: Game already full
 *       '404':
 *         description: Game not found.
 *         content:
 *           application/json:
 *             schema:
 *               type: string
 *               example: Game not found
 *       '401':
 *         description: Unauthorized - Invalid token or insufficient permissions.
 *       '500':
 *         description: Internal server error.
 */

// Join a Game (Player 2)
app.post('/game/:id/join', verifyToken, isPlayer, async (req, res) => {
  const { id } = req.params;

  try {
    const game = await client.db("gameDB").collection("games").findOne({ _id: new ObjectId(id) });

    if (!game) {
      return res.status(404).send('Game not found');
    }

    if (game.player2) {
      return res.status(400).send('Game already full');
    }

    // Ensure the current player (Player 2) is not the same as Player 1
    if (req.user.userId === game.player1) {
      return res.status(400).send('You cannot join your own game');
    }

    await client.db("gameDB").collection("games").updateOne(
      { _id: new ObjectId(id) },
      { $set: { player2: req.user.userId } }
    );

    // Check if both players have placed their ships
    const player1ShipsPlaced = game.ships1.every(ship => ship.placed);
    const player2ShipsPlaced = game.ships2.every(ship => ship.placed);

    if (player1ShipsPlaced && player2ShipsPlaced) {
      await client.db("gameDB").collection("games").updateOne(
        { _id: new ObjectId(id) },
        { $set: { gameStatus: 'active' } }
      );
      console.log('Game started'); // Optional logging
    }

    res.send({ message: 'Joined game' });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

/**
 * @swagger
 * /game/{id}/place:
 *   post:
 *     summary: Place ships on the game board
 *     description: Allows a player to place their ships on the game board. The placement details must be provided, and the API validates the placements against game rules.
 *     tags:
 *       - Game
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the game where the ships are to be placed.
 *         schema:
 *           type: string
 *           example: 60a7b4f5313e5a001d6fe8a9
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               placements:
 *                 type: array
 *                 description: Array of ship placement details
 *                 items:
 *                   type: object
 *                   properties:
 *                     x:
 *                       type: integer
 *                       description: X-coordinate of the placement
 *                       example: 0
 *                     y:
 *                       type: integer
 *                       description: Y-coordinate of the placement
 *                       example: 1
 *                     direction:
 *                       type: string
 *                       description: Direction of the ship (horizontal or vertical)
 *                       example: horizontal
 *                     shipName:
 *                       type: string
 *                       description: Name of the ship to be placed
 *                       example: Destroyer
 *     responses:
 *       '200':
 *         description: Ships placed successfully. May indicate that the game can now start or that it's waiting for the other player.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Ships placed successfully. Game can now start.
 *       '400':
 *         description: Errors during ship placement, such as invalid ship names or overlapping ships.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Errors placing ships
 *                 errors:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       message:
 *                         type: string
 *                         example: Invalid ship name Destroyer
 *                       placement:
 *                         type: object
 *                         properties:
 *                           x:
 *                             type: integer
 *                             example: 0
 *                           y:
 *                             type: integer
 *                             example: 1
 *                           direction:
 *                             type: string
 *                             example: horizontal
 *       '403':
 *         description: Unauthorized - The player is not part of the game or attempting unauthorized ship placement.
 *         content:
 *           application/json:
 *             schema:
 *               type: string
 *               example: Not part of this game
 *       '404':
 *         description: Game not found.
 *         content:
 *           application/json:
 *             schema:
 *               type: string
 *               example: Game not found
 *       '500':
 *         description: Internal server error during ship placement.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Error placing ships
 *                 error:
 *                   type: string
 *                   example: Some internal error details
 */

app.post('/game/:id/place', verifyToken, isPlayer, async (req, res) => {
    const { id } = req.params;
    const { placements } = req.body;

    try {
        const game = await client.db('gameDB').collection('games').findOne({ _id: new ObjectId(id) });

        if (!game) {
            return res.status(404).json({ message: 'Game not found' });
        }

        // Ensure the current player is part of this game
        if (![game.player1.toString(), game.player2.toString()].includes(req.user.userId)) {
            return res.status(403).json({ message: 'Not part of this game' });
        }

        let updatedShips;
        let updatedBoard;
        let otherPlayerId;

        if (req.user.userId === game.player1.toString()) {
            updatedShips = game.ships1;
            updatedBoard = game.board1;
            otherPlayerId = game.player2.toString();
        } else if (req.user.userId === game.player2.toString()) {
            updatedShips = game.ships2;
            updatedBoard = game.board2;
            otherPlayerId = game.player1.toString();
        } else {
            return res.status(403).json({ message: 'Unauthorized to place ships for this game' });
        }

        // Check if ships are already placed
        if (updatedShips.every(ship => ship.placed)) {
            if (game.ships1.every(ship => ship.placed) && game.ships2.every(ship => ship.placed)) {
                return res.json({ message: 'Ships already placed. Game can now start.' });
            } else {
                return res.json({ message: 'Ships already placed. Waiting for the other player to place ships.' });
            }
        }

        let errors = [];

        // Validate ship placements
        for (const { x, y, direction, shipName } of placements) {
            const ship = SHIPS.find(ship => ship.name === shipName);
            if (!ship) {
                errors.push({ message: `Invalid ship name ${shipName}`, placement: { x, y, direction } });
                continue;
            }

            // Check if ship exceeds grid boundaries
            if ((direction === 'horizontal' && x + ship.size > GRID_SIZE) || (direction === 'vertical' && y + ship.size > GRID_SIZE)) {
                errors.push({ message: `Ship ${shipName} exceeds grid boundaries at ${x},${y} ${direction}`, placement: { x, y, direction } });
                continue;
            }

            let valid = true;
            let overlapDetails = [];
            const tempBoard = JSON.parse(JSON.stringify(updatedBoard)); // Create a deep copy of board for overlap check

            // Function to check for overlaps
            const checkOverlap = (tempBoard, x, y, ship, direction) => {
                for (let i = 0; i < ship.size; i++) {
                    if (direction === 'horizontal' && tempBoard[y][x + i] !== '~') {
                        return false;
                    }
                    if (direction === 'vertical' && tempBoard[y + i][x] !== '~') {
                        return false;
                    }
                }
                return true;
            };

            // Check for overlaps in a single pass
            if (direction === 'horizontal') {
                if (!checkOverlap(tempBoard, x, y, ship, direction)) {
                    valid = false;
                    for (let i = 0; i < ship.size; i++) {
                        overlapDetails.push({ grid: `${x + i},${y}`, ship: tempBoard[y][x + i] });
                    }
                }
            } else { // Vertical
                if (!checkOverlap(tempBoard, x, y, ship, direction)) {
                    valid = false;
                    for (let i = 0; i < ship.size; i++) {
                        overlapDetails.push({ grid: `${x},${y + i}`, ship: tempBoard[y + i][x] });
                    }
                }
            }

            if (!valid) {
                errors.push({
                    message: `Position overlaps with another ship at ${x},${y} ${direction}`,
                    overlapDetails,
                    placement: { x, y, direction }
                });
                continue;
            }

            // If placement is valid, update the main board
            if (direction === 'horizontal') {
                for (let i = 0; i < ship.size; i++) {
                    updatedBoard[y][x + i] = ship.name[0]; // Using the first character of ship name as the identifier
                }
            } else { // Vertical
                for (let i = 0; i < ship.size; i++) {
                    updatedBoard[y + i][x] = ship.name[0];
                }
            }

            // Update ships' placement details
            const shipIndex = updatedShips.findIndex(s => s.name === shipName);
            if (shipIndex !== -1) {
                updatedShips[shipIndex].placed = true;
                updatedShips[shipIndex].coordinates = placements.map(p => ({ x: p.x, y: p.y }));
            }
        }

        if (errors.length > 0) {
            res.status(400).json({ message: 'Errors placing ships', errors });
        } else {
            // Update the game state with updated ships and boards
            const updateData = {
                board1: game.player1.toString() === req.user.userId ? updatedBoard : game.board1,
                board2: game.player2.toString() === req.user.userId ? updatedBoard : game.board2,
                ships1: game.player1.toString() === req.user.userId ? updatedShips : game.ships1,
                ships2: game.player2.toString() === req.user.userId ? updatedShips : game.ships2,
                gameStatus: 'pending' // Game status remains 'pending' until both players place ships
            };

            // Check if both players have placed ships
            if (game.ships1.every(ship => ship.placed) && game.ships2.every(ship => ship.placed)) {
                    // Update currentPlayer to start with player1 or player2 based on game rules
                updateData.currentPlayer = game.player1.toString(); // or game.player2.toString() depending on your starting logic
                updateData.gameStatus = 'active'; // Both players have placed ships, game can start
                res.json({ message: 'Ships placed successfully. Game can now start.' });
            } else {
                res.json({ message: 'Ships placed successfully. Waiting for the other player to place ships.' });
            }

            await client.db('gameDB').collection('games').updateOne({ _id: new ObjectId(id) }, { $set: updateData });
        }
    } catch (err) {
        console.error('Error placing ships:', err);
        res.status(500).json({ message: 'Error placing ships', error: err.message });
    }
});

/**
 * @swagger
 * /game/{id}/move:
 *   post:
 *     summary: Make a move in the game
 *     description: Allows a player to make a move by targeting a coordinate on the opponent's board. The API checks if it's the player's turn, validates the coordinates, and updates the game state accordingly.
 *     tags:
 *       - Game
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the game where the move is to be made.
 *         schema:
 *           type: string
 *           example: 60a7b4f5313e5a001d6fe8a9
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               x:
 *                 type: integer
 *                 description: X-coordinate of the target cell.
 *                 example: 5
 *               y:
 *                 type: integer
 *                 description: Y-coordinate of the target cell.
 *                 example: 3
 *     responses:
 *       '200':
 *         description: Move successful. The response includes the updated game board and whether the move was a hit or miss.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Result of the move (hit or miss)
 *                   example: Hit! You can continue your turn.
 *                 yourBoard:
 *                   type: string
 *                   description: The current player's board, showing all positions (ships and hits).
 *                   example: |
 *                     ~ ~ ~ ~ ~
 *                     ~ X ~ ~ ~
 *                     ~ ~ ~ ~ ~
 *                 opponentBoard:
 *                   type: string
 *                   description: The opponent's board, showing only hit/miss information.
 *                   example: |
 *                     ~ ~ ~ X ~
 *                     ~ M ~ ~ ~
 *                     ~ ~ ~ ~ ~
 *       '400':
 *         description: Invalid target coordinates or move (e.g., out of bounds or already targeted).
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Invalid target coordinates 10,11. Coordinates must be within 0 to 9.
 *       '403':
 *         description: Forbidden action, either the player is not part of the game or it is not their turn.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: It is not your turn
 *       '404':
 *         description: Game not found.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Game not found
 *       '500':
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Error making move
 *                 error:
 *                   type: string
 *                   example: Some internal error details
 */

app.post('/game/:id/move', verifyToken, isPlayer, async (req, res) => {
  const { id } = req.params;
  const { x, y } = req.body; // Assuming the coordinates to target are passed in the request body

  // Function to format the grid for the current player (show everything)
  const formatGridForPlayer = (board) => {
      return board.map(row => row.join('')).join('\n');
  };

  // Function to format the grid for the opponent (hide ships)
  const formatGridForOpponent = (board) => {
      return board.map(row => row.map(cell => (cell === 'X' || cell === 'M' ? cell : '~')).join('')).join('\n');
  };

  try {
      const game = await client.db('gameDB').collection('games').findOne({ _id: new ObjectId(id) });

      if (!game) {
          return res.status(404).json({ message: 'Game not found' });
      }

      // Ensure the current player is part of this game
      if (![game.player1.toString(), game.player2.toString()].includes(req.user.userId)) {
          return res.status(403).json({ message: 'Not part of this game' });
      }

      // Check if the game is already over
      if (game.isGameOver) {
          return res.status(400).json({ message: 'The game is already over. No further moves can be made.' });
      }

      // Determine whose turn it is based on the currentPlayer property in the game
      const currentPlayerId = game.currentPlayer;

      // Check if it's the current player's turn
      if (req.user.userId !== currentPlayerId) {
          return res.status(403).json({ message: 'It is not your turn' });
      }

      // Determine the player's and opponent's board
      const isPlayer1 = req.user.userId === game.player1.toString();
      const currentPlayerBoard = isPlayer1 ? 'board1' : 'board2';
      const opponentBoard = isPlayer1 ? 'board2' : 'board1';

      // Validate target coordinates and board status
      if (
          x < 0 || x >= GRID_SIZE || y < 0 || y >= GRID_SIZE ||
          !Array.isArray(game[opponentBoard]) ||
          typeof game[opponentBoard][y] === 'undefined' ||
          typeof game[opponentBoard][y][x] === 'undefined'
      ) {
          return res.status(400).json({ message: `Invalid target coordinates ${x},${y}. Coordinates must be within 0 to 9.` });
      }

      // Check if the targeted grid cell has already been targeted ('X' for hit, 'M' for miss)
      if (game[opponentBoard][y][x] === 'X' || game[opponentBoard][y][x] === 'M') {
          return res.status(400).json({ message: `Already targeted grid ${x},${y}. Choose a different target.` });
      }

      let hit = false;

      // Check if the targeted grid has a ship ('~' represents water, any other character represents a ship)
      if (game[opponentBoard][y][x] !== '~') {
          // Mark hit on the opponent's board
          game[opponentBoard][y][x] = 'X';
          hit = true;
      } else {
          // Mark miss on the opponent's board
          game[opponentBoard][y][x] = 'M';
      }

      // Check if all ships of the opponent have been sunk
      const allShipsSize = SHIPS.reduce((acc, ship) => acc + ship.size, 0);
      const opponentHits = game[opponentBoard].reduce((acc, row) => acc + row.filter(cell => cell === 'X').length, 0);

      if (opponentHits === allShipsSize) {
          // Game completed, the current player wins
          game.isGameOver = true;

          // Fetch usernames for winner and loser
          const { username1, username2 } = await fetchPlayerUsernames(game.player1, game.player2);

          const winMessage = `Last ship hit! Congratulations! ${isPlayer1 ? username1 : username2} wins the game!`;
          const loseMessage = `${isPlayer1 ? username2 : username1} has won the game. Better luck next time.`;

          // Update game status in database
          await client.db('gameDB').collection('games').updateOne({ _id: new ObjectId(id) }, { $set: { isGameOver: true, board1: game.board1, board2: game.board2, currentPlayer: game.currentPlayer } });

          // Notify both players with appropriate messages and boards
          const winnerResponse = {
              message: winMessage,
              yourBoard: formatGridForPlayer(isPlayer1 ? game.board1 : game.board2),
              opponentBoard: formatGridForOpponent(isPlayer1 ? game.board2 : game.board1)
          };

          const loserResponse = {
              message: loseMessage,
              yourBoard: formatGridForPlayer(isPlayer1 ? game.board1 : game.board2),
              opponentBoard: formatGridForOpponent(isPlayer1 ? game.board2 : game.board1)
          };

          // Send response to the winner
          if (isPlayer1) {
              return res.json(winnerResponse);
          } else {
              return res.json(loserResponse);
          }
      }

      // Update the game state if it's not over
      if (!hit) {
          // Switch turn to the other player immediately after a miss
          game.currentPlayer = currentPlayerId === game.player1.toString() ? game.player2.toString() : game.player1.toString();
      }

      const updateData = {
          board1: game.board1,
          board2: game.board2,
          currentPlayer: game.currentPlayer
      };

      await client.db('gameDB').collection('games').updateOne({ _id: new ObjectId(id) }, { $set: updateData });

      // Determine message based on hit or miss
      const responseMessage = hit ? 'Hit! You can continue your turn.' : 'Miss. Let the other player take their turn.';

      const response = {
          message: responseMessage,
          yourBoard: formatGridForPlayer(isPlayer1 ? game.board1 : game.board2),
          opponentBoard: formatGridForOpponent(isPlayer1 ? game.board2 : game.board1)
      };

      return res.json(response);

  } catch (err) {
      console.error('Error making move:', err);
      res.status(500).json({ message: 'Error making move', error: err.message });
  }
});

// Updated password policy check
function isStrongPassword(password) {
    const errors = [];
  
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long.');
    }
  
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter.');
    }
  
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter.');
    }
  
    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one digit.');
    }
  
    if (!/\W/.test(password)) {
      errors.push('Password must contain at least one special character.');
    }
  
    return errors.length === 0 ? true : errors;
  }

// Connect to MongoDB and start the server
async function run() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });

    app.get('/', (req, res) => {
        res.send('Welcome to the BattleShip Game');
      });

  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}
run();