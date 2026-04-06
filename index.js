const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;

// --- CORS ---
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:5174',
  ],
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// --- MONGODB ---
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.w0vxmse.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// --- COOKIE OPTIONS ---
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};

// --- VERIFY TOKEN MIDDLEWARE ---
const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).send({ message: 'Unauthorized: No token' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'Unauthorized: Invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    const db = client.db('project-micromint');
    const usersCollection = db.collection('users')
    
    //save and update user on database
    app.post('/users/:email', async(req, res)=>{
      
      const email = req.params.email;
      const query = {email}
      const user = req.body;

      //check user already exists
      const isExist = await usersCollection.findOne(query)
      if(isExist) return res.send(isExist)
      
      //else save user on db
      const result = await usersCollection.insertOne({
        ...user, 
        role: user.role || 'worker',
        timestamp: Date.now(),
      });
      res.send(result);  
    })
    
    
    
    
    // await client.connect();

    // Issue token
    app.post('/jwt', (req, res) => {
      const { email } = req.body;
      if (!email) return res.status(400).send({ message: 'Email is required' });

      const token = jwt.sign({ email }, process.env.JWT_SECRET, {
        expiresIn: '7d',
      });

      res.cookie('token', token, cookieOptions).send({ success: true });
    });

    // Logout
    app.post('/logout', (req, res) => {
      res.clearCookie('token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      }).send({ success: true });
    });

    console.log('Connected to MongoDB!');
  } finally {
    // await client.close();
  }
}

run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Server is running smoothly');
});

app.listen(port, () => console.log(`Server listening on port ${port}`));