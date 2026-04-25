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

    // User submits role change request
    app.post('/role-requests', verifyToken, async (req, res) => {
      const email = req.user.email;
      const { requestedRole } = req.body;

      try {
        
        //Fetch current user to check their existing role
        const currentUser = await usersCollection.findOne({ email });

        //Block request if the user is already an Admin
        if (currentUser?.role === 'admin') {
          return res.status(403).send({ message: 'Admins cannot request role changes.' });
        }

        const allowedRoles = ['worker', 'buyer'];
        if (!allowedRoles.includes(requestedRole)) {
          return res.status(400).send({ message: 'Invalid role requested' });
        }

        const existingRequest = await roleRequestsCollection.findOne({
          email,
          status: 'pending',
        });

        if (existingRequest) {
          return res.status(409).send({ message: 'You already have a pending request' });
        }

        await roleRequestsCollection.insertOne({
          email,
          requestedRole,
          status: 'pending',
          requestDate: new Date(),
        });

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to submit request' });
      }
    });

    // User checks their own pending request
    app.get('/role-requests/:email/pending', verifyToken, async (req, res) => {
      const email = req.params.email;

      try {
        if (req.user.email !== email) {
          return res.status(403).send({ message: 'Forbidden' });
        }

        const result = await roleRequestsCollection.findOne({
          email,
          status: 'pending',
        });

        res.send(result ?? null);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching request' });
      }
    });

    // Admin gets all pending role requests
    app.get('/role-requests', verifyToken, async (req, res) => {
      try {
        const result = await roleRequestsCollection.find({ status: 'pending' }).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch requests' });
      }
    });

    // Admin approves or rejects a role request
    app.patch('/role-requests/:id', verifyToken,  async (req, res) => {
      const id = req.params.id;
      const { status } = req.body;

      try {
        if (!['approved', 'rejected'].includes(status)) {
          return res.status(400).send({ message: 'Invalid status' });
        }

        const request = await roleRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!request) return res.status(404).send({ message: 'Request not found' });
        if (request.status !== 'pending') {
          return res.status(400).send({ message: 'Request already processed' });
        }

        await roleRequestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status, resolvedAt: new Date() } }
        );

        if (status === 'approved') {
          await usersCollection.updateOne(
            { email: request.email },
            { $set: { role: request.requestedRole } }
          );
        }

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to process request' });
      }
    });

      app.get('/users', verifyToken, async (req, res) => {
      try {
        const result = await usersCollection.find().toArray();
        res.send(result);
      } catch (error) {
    res.status(500).send({ message: 'Failed to fetch users' });
      }
    });


    //save add task to the tasks collection
    app.post("/tasks", async (req, res) => {
      const task = req.body;
      const result = await taskCollection.insertOne(task);
      res.send(result);
    });

    //get all tasks
    app.get("/tasks", verifyToken, async (req, res) => {
      const result = await taskCollection.find().toArray();
      res.send(result);
    });

    //get tasks data by email for buyer
    app.get("/tasks/buyer/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { "buyer.email": email };
      const result = await taskCollection.find(query).toArray();
      res.send(result);
    });

    //get a specific task by id and also check whether worker submitted 
    app.get("/tasks/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const task = await taskCollection.findOne(query);
      if(!task) return res.status(404).send({ message: "Task not found" });

      const existingSubmittedTask = await submittedTasksCollection.findOne({
        task_id: id,
        "worker.email": req.user.email,
      })
      res.send({...task, submissionStatus: existingSubmittedTask ? existingSubmittedTask.status : null});
    });

    //update task info buyer
    app.patch("/tasks/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const buyerEmail = req.user.email;
      try {
        //fetch task first
        const task = await taskCollection.findOne({ _id: new ObjectId(id) });
        if (!task)
          return res.status(404).send({ message: "Forbidden: Not your task" });

        //check buyer email
        if (task.buyer.email !== buyerEmail) {
          return res.status(403).send({ message: "Forbidden: Not your task" });
        }

        const {
          task_title,
          task_detail,
          required_workers,
          payable_amount,
          completion_date,
          submission_info,
        } = req.body;

        const updateFields = {};
        const errors = [];

        //count existing submissions once to avoid redundant DB calls
        const activeSubmissions = await submittedTasksCollection.countDocuments(
          {
            task_id: id,
            status: { $ne: "rejected" },
          },
        );

        if (task_title) updateFields.task_title = task_title;
        if (task_detail) updateFields.task_detail = task_detail;
        if (submission_info) updateFields.submission_info = submission_info;
        if (completion_date) {
          const today = new Date();
          today.setHours(0, 0, 0, 0);
          if (new Date(completion_date) < today) {
            errors.push("Completion date cannot be in the past");
          } else {
            updateFields.completion_date = completion_date;
          }
        }

        // Logic: required_workers from frontend represents the NEW TOTAL target
        if (required_workers !== undefined) {
          const newTotalWorkers = Number(required_workers);
          if (newTotalWorkers < activeSubmissions) {
            errors.push(
              `Total workers cannot be less than active submissions (${activeSubmissions})`,
            );
          } else {
            // We store the "remaining slots" in required_workers
            updateFields.required_workers = newTotalWorkers - activeSubmissions;

            // Recalculate total escrow/payable amount
            const price =
              payable_amount !== undefined
                ? Number(payable_amount)
                : Number(task.payable_amount);
            updateFields.total_payable_amount = newTotalWorkers * price;
          }
        }
        if (payable_amount !== undefined) {
          const newPrice = Number(payable_amount);
          if (newPrice < task.payable_amount) {
            errors.push("Payable amount per worker can only be increased");
          } else {
            updateFields.payable_amount = newPrice;

            // If workers weren't updated in this request, recalculate total based on existing total target
            if (required_workers === undefined) {
              const currentTotalWorkers =
                Number(task.required_workers) + activeSubmissions;
              updateFields.total_payable_amount =
                currentTotalWorkers * newPrice;
            }
          }
        }
        if (errors.length > 0) {
          return res.status(400).send({ message: errors.join("; ") });
        }

        if (Object.keys(updateFields).length === 0) {
          return res.status(400).send({ message: "No valid changes detected" });
        }

        await taskCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateFields },
        );

        const updatedTask = await taskCollection.findOne({
          _id: new ObjectId(id),
        });
        res.send(updatedTask);
      } catch (error) {
        console.error("Task Update Error:", error);
        res
          .status(500)
          .send({ message: "Failed to update task due to a server error" });
      }
    });

    //save submitted_tasks on the database also patch i.e., update task workers
    app.post("/submitted-task", verifyToken, async (req, res) => {
      const { task_id, submission_details, worker_email, worker_name } = req.body;
      try {
        //check status for block the submission
        const activeSubmission = await submittedTasksCollection.findOne({
          task_id: task_id,
          "worker.email": worker_email,
          status: {$in: ["pending", "approved"]}
        });
        if (activeSubmission) {
          return res
            .status(400)
            .send({ message: "You have already have a pending or approved submission." });
        }

        //now check if this is a re-submission of a rejected task
        const prevRejected = await submittedTasksCollection.findOne({
          task_id: task_id,
          "worker.email": worker_email,
          status: "rejected",
        })

        const task = await taskCollection.findOne({
          _id: new ObjectId(task_id),
        });

        if (!prevRejected && (!task || task.required_workers <= 0)) {
          return res
            .status(400)
            .send({ message: "Task is no longer available." });
        }
        //Create the submission
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

        // then upsert the submission-Update if rejected, Insert if new
        const result = await submittedTasksCollection.updateOne(
          { task_id, "worker.email": worker_email },
          { $set: newSubmission },
          { upsert: true }
        );

        //only decrease slot if this is worker's first attempt
        if (!prevRejected) {
          await taskCollection.updateOne(
          { _id: new ObjectId(task_id) },
          { $inc: { required_workers: -1 } }
        );
    }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to submit task" });
      }
    });

    //get all submitted tasks for a specific worker
    app.get("/submitted-task/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { "worker.email": email };
      const result = await submittedTasksCollection.find(query).toArray();
      res.send(result);
    });

    //delete or cancel submitted task
    app.delete("/submitted-task/:id", verifyToken, async (req, res) => {
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

    //get worker stats
    app.get("/worker-stats/:email", verifyToken, async (req, res) => {
      const email = req.params.email;

      //check user is request their own stats
      if (req.user.email !== email) {
        return res.status(403).send({ message: "Forbidden Access" });
      }

      try {
        const stats = await submittedTasksCollection
          .aggregate([
            //filter only this worker's submission data
            { $match: { "worker.email": email } },
            {
              $group: {
                _id: null,
                totalSubmissions: { $sum: 1 },
                totalPendingSubmissions: {
                  $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] },
                },
              },
            },
            {
              $project: {
                _id: 0,
                totalSubmissions: 1,
                totalPendingSubmissions: 1,
              },
            },
          ])
          .toArray();

        const result =
          stats.length > 0
            ? stats[0]
            : {
                totalSubmissions: 0,
                totalPendingSubmissions: 0,
                totalEarnings: 0,
              };
        res.send(result);
      } catch (error) {
        console.error("Aggregation Error", error);
        res.status(500).send({ message: "Internal Server Error" });
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
