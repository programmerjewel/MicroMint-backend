const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 3000;

// --- CORS ---
const corsOptions = {
  origin: ["http://localhost:5173", "http://localhost:5174"],
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
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};

// --- VERIFY TOKEN MIDDLEWARE ---
const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).send({ message: "Unauthorized: No token" });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .send({ message: "Unauthorized: Invalid or expired token" });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    // Issue token
    app.post("/jwt", (req, res) => {
      const { email } = req.body;
      if (!email) return res.status(400).send({ message: "Email is required" });

      const token = jwt.sign({ email }, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });

      res.cookie("token", token, cookieOptions).send({ success: true });
    });

    // Logout
    app.post("/logout", (req, res) => {
      res
        .clearCookie("token", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        })
        .send({ success: true });
    });

    const db = client.db("project-micromint");
    const usersCollection = db.collection("users");
    const taskCollection = db.collection("tasks");
    const submittedTasksCollection = db.collection("submitted_tasks");
    const roleRequestsCollection = db.collection("user_role_requests");

    // Register and save user on db — form or google sign in
    app.post('/users', async (req, res) => {
      const { name, email, image, role } = req.body;

      try {
        const isExist = await usersCollection.findOne({ email });
        if (isExist) return res.send(isExist);

        const allowedRoles = ['worker', 'buyer'];
        const safeRole = allowedRoles.includes(role) ? role : 'worker';

        const newUser = {
          name,
          email,
          image,
          role: safeRole,
          timestamp: Date.now(),
        };

        await usersCollection.insertOne(newUser);
        res.status(201).send(newUser);

      } catch (error) {
        res.status(500).send({ message: 'Failed to save user' });
      }
    });

     // Get user by email
    app.get('/users/:email', verifyToken, async (req, res) => {
      const email = req.params.email;

      try {
        if (req.user.email !== email) {
          return res.status(403).send({ message: 'Forbidden' });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: 'User not found' });

        res.send(user);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch user' });
      }
    });

    // Update name and image only — no role
    app.patch('/users/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      const { name, image } = req.body;

      try {
        if (req.user.email !== email) {
          return res.status(403).send({ message: 'Forbidden' });
        }

        const existingUser = await usersCollection.findOne({ email });
        if (!existingUser) {
          return res.status(404).send({ message: 'User not found' });
        }

        const updateFields = {};
        if (name) updateFields.name = name;
        if (image) updateFields.image = image;

        if (Object.keys(updateFields).length === 0) {
          return res.status(400).send({ message: 'No valid fields to update' });
        }

        await usersCollection.updateOne({ email }, { $set: updateFields });

        const updatedUser = await usersCollection.findOne({ email });
        res.send(updatedUser);

      } catch (error) {
        res.status(500).send({ message: 'Update failed' });
      }
    });

    //save add task to the tasks collection
    app.post("/tasks", async (req, res) => {
      const task = req.body;
      const result = await taskCollection.insertOne(task);
      res.send(result);
    });

    //get all tasks
    app.get("/tasks", async (req, res) => {
      const result = await taskCollection.find().toArray();
      res.send(result);
    });

    //get a specific task by id
    app.get("/tasks/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await taskCollection.findOne(query);
      res.send(result);
    });

    //save submitted_tasks on the database also patch i.e., update task workers
    app.post("/submitted-task", async (req, res) => {
      const { task_id, submission_details, worker_email, worker_name } =
        req.body;
      const task = await taskCollection.findOne({ _id: new ObjectId(task_id) });
      const newSubmission = {
        task_id: task_id,
        task_title: task.task_title,
        payable_amount: task.payable_amount,
        worker: { email: worker_email, name: worker_name },
        submission_details: submission_details,
        buyer: { name: task.buyer.name, email: task.buyer.email },
        current_date: new Date().toISOString().split("T")[0],
        status: "pending",
      };
      const result = await submittedTasksCollection.insertOne(newSubmission);
      await taskCollection.updateOne(
        { _id: new ObjectId(task_id) },
        {
          $inc: { required_workers: -1 },
        },
      );
      res.send(result);
    });

    //get all submitted tasks for a specific worker
    app.get("/submitted-task/:email", async (req, res) => {
      const email = req.params.email;
      const query = { "worker.email": email };
      const result = await submittedTasksCollection.find(query).toArray();
      res.send(result);
    });

    //delete or cancel submitted task
    app.delete("/submitted-task/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };

      const submission = await submittedTasksCollection.findOne(query);

      // 1. Check if submission exists and is still pending
      if (submission && submission.status.toLowerCase() === "pending") {
        // 2. Delete the submission
        const result = await submittedTasksCollection.deleteOne(query);

        // 3. Refund the worker slot to the task
        await taskCollection.updateOne(
          { _id: new ObjectId(submission.task_id) },
          { $inc: { required_workers: 1 } },
        );
        res.send(result);
      } else {
        res.send({ error: "Action not allowed or record not found" });
      }
    });

    // await client.connect();

    console.log("Connected to MongoDB!");
  } finally {
    // await client.close();
  }
}

run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Server is running smoothly");
});

app.listen(port, () => console.log(`Server listening on port ${port}`));
