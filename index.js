const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { DateTime } = require("luxon");
const admin = require("firebase-admin");

//initialize firebase admin
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.set("trust proxy", 1);
const port = process.env.PORT || 3000;

// --- CORS ---
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "https://project-micromint.vercel.app",
    "https://micromint-2025.web.app",
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

// --- COOKIE OPTIONS function ---
const getCookieOptions = (req) => {
  // check if the request comes from localhost or Vercel production
  const isLocal = req.get("origin")?.includes("localhost") || req.get("host")?.includes("localhost");

  return {
    httpOnly: true,
    secure: !isLocal, // true on Vercel (HTTPS), false on localhost (HTTP)
    sameSite: isLocal ? "strict" : "none", // "none" allows cross-site cookies across Vercel apps
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  };
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

      // pass req to getCookieOptions to dynamically calculate properties
      res.cookie("token", token, getCookieOptions(req)).send({ success: true });
    });

    // Logout
    app.post("/logout", (req, res) => {
      const options = getCookieOptions(req);
      
      // maxAge isn't required for clearCookie
      delete options.maxAge; 

      res
        .clearCookie("token", options)
        .send({ success: true });
    });

    const db = client.db("project-micromint");
    const usersCollection = db.collection("users");
    const taskCollection = db.collection("tasks");
    const submittedTasksCollection = db.collection("submitted_tasks");
    const roleRequestsCollection = db.collection("user_role_requests");
    const transactionsCollection = db.collection("transactions");
    const withdrawalsCollection = db.collection("withdrawals");
    const packagesCollection = db.collection("packages");
    const purchasesCollection = db.collection("purchases");
    const notificationsCollection = db.collection("notifications");

    // global variables
    const MIN_WITHDRAW_COINS = parseInt(process.env.MIN_WITHDRAW_COINS);
    const DAILY_COIN_LIMIT = parseInt(process.env.DAILY_COIN_LIMIT);
    const MONTHLY_COIN_LIMIT = parseInt(process.env.MONTHLY_COIN_LIMIT);
    const DEFAULT_COIN_BUYER = parseInt(process.env.DEFAULT_COIN_BUYER);
    const DEFAULT_COIN_WORKER = parseInt(process.env.DEFAULT_COIN_WORKER);
    const COIN_TO_DOLLAR_RATE = parseInt(process.env.COIN_TO_DOLLAR_RATE);
    const WITHDRAW_COIN_TO_DOLLAR_RATE = parseInt(
      process.env.WITHDRAW_COIN_TO_DOLLAR_RATE,
    );

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

    // verifyAdmin middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.user?.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      const isAdmin = user?.role === "admin";

      if (!isAdmin)
        return res.status(403).send({ message: "forbidden access " });
      next();
    };

    // helper function for notification
    async function dispatchNotification(
      { to_email, title, message, type, action_route = null },
      session = null,
    ) {
      const notificationDoc = {
        to_email,
        title,
        message,
        type,
        action_route,
        isRead: false,
        timestamp: new Date(),
      };
      const options = session ? { session } : {};
      return await notificationsCollection.insertOne(notificationDoc, options);
    }

    const getPurchaseUsage = async (email, timezone = "UTC") => {
      const now = DateTime.now().setZone(timezone);

      const startOfDay = now.startOf("day").toJSDate();
      const startOfMonth = now.startOf("month").toJSDate();

      const result = await transactionsCollection
        .aggregate([
          {
            $match: {
              email,
              type: "purchase",
              status: "completed",
              timestamp: { $gte: startOfMonth },
            },
          },
          {
            $group: {
              _id: null,

              monthlyPurchased: {
                $sum: "$coins",
              },

              dailyPurchased: {
                $sum: {
                  $cond: [{ $gte: ["$timestamp", startOfDay] }, "$coins", 0],
                },
              },
            },
          },
        ])
        .toArray();

      return (
        result[0] || {
          dailyPurchased: 0,
          monthlyPurchased: 0,
        }
      );
    };

    // Register and save user on db — form or google sign in
    app.post("/users", async (req, res) => {
      const { name, email, image, role, timezone } = req.body;

      try {
        // check if user already exists
        const isExist = await usersCollection.findOne({ email });
        if (isExist) return res.send(isExist);

        // allow roles with default worker role and coins
        const allowedRoles = ["worker", "buyer"];
        const defaultRole = allowedRoles.includes(role) ? role : "worker";
        const initialCoins =
          defaultRole === "buyer" ? DEFAULT_COIN_BUYER : DEFAULT_COIN_WORKER;

        // new user data
        const newUser = {
          name,
          email,
          image,
          role: defaultRole,
          coins: initialCoins,
          timezone: timezone, // add timezone to track user daily coin limti
          timestamp: new Date(),
        };

        await usersCollection.insertOne(newUser);

        // save coin transaction data
        await transactionsCollection.insertOne({
          receiver_email: email,
          amount: initialCoins,
          type: "signup_bonus",
          status: "completed",
          description: "Welcome Bonus",
          timestamp: new Date(),
        });

        // save data on notification
        await dispatchNotification({
          to_email: email,
          title: "Welcome Bonus Credited!",
          message: `Your MicroMint account is ready. We've credited ${initialCoins} coins to your balance as a welcome gift.`,
          type: "system",
          action_route:
            defaultRole === "buyer"
              ? "/dashboard/buyer-home"
              : "/dashboard/worker-home",
        });

        res.status(201).send(newUser);
      } catch (error) {
        res.status(500).send({ message: "Failed to save user" });
      }
    });

    // Get user by email
    app.get("/users/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      try {
        if (req.user.email !== email) {
          return res.status(403).send({ message: "Forbidden" });
        }
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found" });
        res.send(user);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch user" });
      }
    });

    // User delete route from firebase and database
    app.delete("/users/:email", verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const session = client.startSession();

      try {
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res
            .status(404)
            .send({ message: "User not found in database" });
        }

        // prevent admin from deleting their own account
        if (email === req.user.email) {
          return res
            .status(403)
            .send({ message: "Admins cannot delete their own account" });
        }

        // delete from Firebase Authentication first
        try {
          const firebaseUser = await admin.auth().getUserByEmail(email);
          await admin.auth().deleteUser(firebaseUser.uid);
        } catch (firebaseError) {
          if (firebaseError.code === "auth/user-not-found") {
            console.warn(
              `User ${email} already missing from Firebase Authentication.`,
            );
          } else {
            console.error("Firebase deletion error:", firebaseError.message);
            return res.status(500).send({
              message: "Failed to delete user from authentication provider",
            });
          }
        }

        // Execute all DB operations atomically
        await session.withTransaction(async () => {
          // delete main user profile
          await usersCollection.deleteOne({ email }, { session });

          // clear pending/resolved role change requests
          await roleRequestsCollection.deleteMany({ email }, { session });

          // buyer cleanup
          if (user.role === "buyer") {
            const buyerTasks = await taskCollection
              .find({ "buyer.email": email }, { session })
              .toArray();
            const taskIds = buyerTasks.map((t) => t._id.toString());

            // delete all tasks posted by this buyer
            await taskCollection.deleteMany(
              { "buyer.email": email },
              { session },
            );

            if (taskIds.length > 0) {
              const affectedSubmissions = await submittedTasksCollection
                .find(
                  {
                    task_id: { $in: taskIds },
                    status: { $in: ["pending", "rejected"] },
                  },
                  { session },
                )
                .toArray();

              // mark pending/rejected worker submissions as cancelled
              await submittedTasksCollection.updateMany(
                {
                  task_id: { $in: taskIds },
                  status: { $in: ["pending", "rejected"] },
                },
                {
                  $set: {
                    status: "cancelled account deleted",
                    cancelledAt: new Date(),
                  },
                },
                { session },
              );

              await submittedTasksCollection.deleteMany(
                { task_id: { $in: taskIds }, status: "approved" },
                { session },
              );

              for (const sub of affectedSubmissions) {
                await dispatchNotification(
                  {
                    to_email: sub.worker.email,
                    title: "Task Cancelled (Account Purged)",
                    message: `The task "${sub.task_title}" was closed because the buyer's account was deleted by administration.`,
                    type: "task_lifecycle",
                    action_route: "/dashboard/worker-submissions",
                  },
                  session,
                );
              }
            }
          }

          // worker cleanup
          if (user.role === "worker") {
            // refund task slots for pending submissions before deleting them
            const pendingSubmissions = await submittedTasksCollection
              .find({ "worker.email": email, status: "pending" }, { session })
              .toArray();

            for (const sub of pendingSubmissions) {
              await taskCollection.updateOne(
                { _id: new ObjectId(sub.task_id) },
                { $inc: { required_workers: 1 } },
                { session },
              );

              // notify affected buyer for worker account removal
              await dispatchNotification(
                {
                  to_email: sub.buyer.email,
                  title: "Task Slot Restored",
                  message: `A submission for "${sub.task_title}" was dropped and the slot was returned because the worker's account was deleted.`,
                  type: "task_lifecycle",
                  action_route: `/dashboard/tasks/buyer/${sub.buyer.email}`,
                },
                session,
              );
            }

            // delete all submissions by this worker
            await submittedTasksCollection.deleteMany(
              { "worker.email": email },
              { session },
            );

            // cancel pending withdrawals only
            await withdrawalsCollection.updateMany(
              { worker_email: email, status: "pending" },
              {
                $set: {
                  status: "cancelled_account_deleted",
                  cancelledAt: new Date(),
                },
              },
              { session },
            );
          }
        });

        res.send({
          success: true,
          message: `User ${email} and all associated data has been completely removed.`,
        });
      } catch (error) {
        console.error("Cascading Delete User Error:", error);
        res
          .status(500)
          .send({ message: "Internal server error during full data wipeout" });
      } finally {
        await session.endSession();
      }
    });

    // Update name and image only — no role
    app.patch("/users/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const { name, image } = req.body;

      try {
        // only allow user himself
        if (req.user.email !== email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        const existingUser = await usersCollection.findOne({ email });
        if (!existingUser) {
          return res.status(404).send({ message: "User not found" });
        }

        // update user name and profile picture
        const updateFields = {};
        if (name) updateFields.name = name;
        if (image) updateFields.image = image;

        if (Object.keys(updateFields).length === 0) {
          return res.status(400).send({ message: "No valid fields to update" });
        }

        //save updated user data with timestamp
        updateFields.updatedAt = new Date();
        await usersCollection.updateOne({ email }, { $set: updateFields });

        const updatedUser = await usersCollection.findOne({ email });
        res.send(updatedUser);
      } catch (error) {
        res.status(500).send({ message: "Update failed" });
      }
    });

    // User submits role change request
    app.post("/role-requests", verifyToken, async (req, res) => {
      const email = req.user.email;
      const { requestedRole } = req.body;

      try {
        const currentUser = await usersCollection.findOne({ email });

        // block request if the user is already an Admin
        if (currentUser?.role === "admin") {
          return res
            .status(403)
            .send({ message: "Admins cannot request role changes." });
        }

        const allowedRoles = ["worker", "buyer"];
        if (!allowedRoles.includes(requestedRole)) {
          return res.status(400).send({ message: "Invalid role requested" });
        }

        const existingRequest = await roleRequestsCollection.findOne({
          email,
          status: "pending",
        });

        if (existingRequest) {
          return res
            .status(409)
            .send({ message: "You already have a pending request" });
        }

        await roleRequestsCollection.insertOne({
          email,
          requestedRole,
          status: "pending",
          requestDate: new Date(),
        });

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: "Failed to submit request" });
      }
    });

    // User checks their own pending request
    app.get("/role-requests/:email/pending", verifyToken, async (req, res) => {
      const email = req.params.email;

      try {
        if (req.user.email !== email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        const result = await roleRequestsCollection.findOne({
          email,
          status: "pending",
        });

        res.send(result ?? null);
      } catch (error) {
        res.status(500).send({ message: "Error fetching request" });
      }
    });

    // Admin gets all pending role requests
    app.get("/role-requests", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await roleRequestsCollection
          .find({ status: "pending" })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch requests" });
      }
    });

    // Admin approves or rejects a role request
    app.patch("/role-requests/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const { status } = req.body;

      try {
        if (!["approved", "rejected"].includes(status)) {
          return res.status(400).send({ message: "Invalid status" });
        }

        const request = await roleRequestsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!request)
          return res.status(404).send({ message: "Request not found" });
        if (request.status !== "pending") {
          return res.status(400).send({ message: "Request already processed" });
        }

        await roleRequestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status, resolvedAt: new Date() } },
        );

        if (status === "approved") {
          await usersCollection.updateOne(
            { email: request.email },
            { $set: { role: request.requestedRole } },
          );
        }

        // save role requrest data on notification
        await dispatchNotification({
          to_email: request.email,
          title:
            status === "approved"
              ? "Role Change Approved!"
              : "Role Change Declined",
          message:
            status === "approved"
              ? `Congratulations! Your request has been approved. You are now authorized as a ${request.requestedRole.toUpperCase()}.`
              : `Your application to change your platform role to ${request.requestedRole} was rejected by administration.`,
          type: "role_change",
          action_route: "/",
        });
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: "Failed to process request" });
      }
    });

    // Get all users from database
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await usersCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch users" });
      }
    });

    // Save Add task to the tasks collection
    app.post("/tasks", verifyToken, async (req, res) => {
      const task = req.body;
      const buyerEmail = req.user.email;
      const totalPayable = Number(task.required_workers) * Number(task.payable_amount);

      try {
        const user = await usersCollection.findOne({ email: buyerEmail });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        // automatically track past-deadline tasks
        const todayStr = new Date().toISOString().slice(0, 10);

        await taskCollection.updateMany(
          {
            "buyer.email": buyerEmail,
            status: "open", // Only active tasks can expire
            completion_date: { $lt: todayStr },
          },
          {
            $set: { status: "expired" },
          },
        );

        // calculate locked coins only from "open" tasks
        const commitmentStats = await taskCollection
          .aggregate([
            {
              $match: {
                "buyer.email": buyerEmail,
                status: "open",
              },
            },
            {
              $group: {
                _id: null,
                totalCommitted: {
                  $sum: {
                    $multiply: [
                      Number("$required_workers"),
                      Number("$payable_amount"),
                    ],
                  },
                },
              },
            },
            { $project: { totalCommitted: 1, _id: 0 } },
          ])
          .toArray();

        const totalCommitted = commitmentStats[0]?.totalCommitted ?? 0;
        const virtuallyAvailable = user.coins - totalCommitted;

        // evaluate excrow validity
        if (virtuallyAvailable < totalPayable) {
          return res.status(400).send({
            message: `Insufficient balance. You have ${user.coins} coins total, ${totalCommitted} locked in active tasks. Only ${virtuallyAvailable} available, but this task requires ${totalPayable}.`,
          });
        }

        // add new task
        const taskDoc = {
          ...task,
          total_payable_amount: totalPayable,
          createdAt: new Date(),
          status: "open",
        };

        const result = await taskCollection.insertOne(taskDoc);
        res.send(result);
      } catch (error) {
        console.error("Task Creation Error:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // Get all tasks
    app.get("/tasks", async (req, res) => {
      try {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.max(1, parseInt(req.query.limit) || 6);
        const skip = (page - 1) * limit;

        // extract filter parameters
        const { search, status, minReward, maxReward, sortBy } = req.query;

        // build dynamic query object
        const query = {};

        // search query: match against task title or buyer name (case-insensitive)
        if (search) {
          query.$or = [
            { task_title: { $regex: search, $options: "i" } },
            { "buyer.name": { $regex: search, $options: "i" } }
          ];
        }

        // status filtering
        if (status) {
          query.status = status;
        }

        // reward/coin boundaries (ensure string inputs parse to true numbers)
        if (minReward || maxReward) {
          query.payable_amount = {};
          if (minReward) query.payable_amount.$gte = Number(minReward);
          if (maxReward) query.payable_amount.$lte = Number(maxReward);
        }

        // determine dynamic MongoDB sorting order rules
        let sortConfig = { createdAt: -1 }; // default: newest first
        if (sortBy === "reward_desc") {
          sortConfig = { payable_amount: -1 };
        } else if (sortBy === "reward_asc") {
          sortConfig = { payable_amount: 1 };
        } else if (sortBy === "deadline_asc") {
          sortConfig = { completion_date: 1 }; // closing soonest
        } else if (sortBy === "createdAt_desc") {
          sortConfig = { createdAt: -1 };
        }

        // query execution using an efficient parallel pipeline execution model
        const [tasks, totalCount] = await Promise.all([
          taskCollection
            .find(query)
            .sort(sortConfig)
            .skip(skip)
            .limit(limit)
            .toArray(),
          taskCollection.countDocuments(query)
        ]);

        const totalPages = Math.ceil(totalCount / limit);

        res.send({
          tasks,
          meta: {
            totalTasks: totalCount,
            totalPages: totalPages || 1,
            currentPage: page
          }
        });
      } catch (error) {
        console.error("Error fetching paginated tasks:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // Get tasks data by email for buyer
    app.get("/tasks/buyer/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      try {
        const query = { "buyer.email": email };
        const result = await taskCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch buyer tasks" });
      }
    });

    // Get a specific task by id and also check whether task is submitted
    app.get("/tasks/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };

      const task = await taskCollection.findOne(query);

      if (!task) return res.status(404).send({ message: "Task not found" });

      const existingSubmittedTask = await submittedTasksCollection.findOne({
        task_id: id,
        "worker.email": req.user.email,
      });
      res.send({
        ...task,
        submissionStatus: existingSubmittedTask
          ? existingSubmittedTask.status
          : null,
      });
    });

    // Update task info buyer
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

        // check required_workers
        if (required_workers !== undefined) {
          const newTotalWorkers = Number(required_workers);
          if (newTotalWorkers < activeSubmissions) {
            errors.push(
              `Total workers cannot be less than active submissions (${activeSubmissions})`,
            );
          } else {
            // Store the "remaining slots" in required_workers
            updateFields.required_workers = newTotalWorkers - activeSubmissions;

            // recalculate total payable amount
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

            // if workers weren't updated in this request, recalculate total based on existing total target
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

        // add on notifications after update task
        if (payable_amount || task_detail || submission_info) {
          const affectedWorkers = await submittedTasksCollection.distinct(
            "worker.email",
            { task_id: id },
          );
          for (const workerEmail of affectedWorkers) {
            await dispatchNotification({
              to_email: workerEmail,
              title: "Task Modified by Buyer",
              message: `The parameters for your submitted/tracked task "${task.task_title}" have been updated. Review the terms.`,
              type: "task_lifecycle",
              action_route: "/dashboard/worker-submissions",
            });
          }
        }

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

    // Delete the added task (Accessible by Buyer Owner or Admin)
    app.delete("/tasks/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      // requested user email from jwt
      const email = req.user?.email;

      if (!email) {
        return res
          .status(401)
          .send({ message: "Unauthorized: Missing user email" });
      }

      try {
        // fetch the user's role from database
        const user = await usersCollection.findOne({ email: email });
        const role = user?.role;

        // fetch the task to check ownership
        const task = await taskCollection.findOne({ _id: new ObjectId(id) });
        if (!task) {
          return res.status(404).send({ message: "Task not found" });
        }

        // check user is admin or added buyer himself
        const isAdmin = role === "admin";
        const isOwner = task.buyer.email === email;

        if (!isAdmin && !isOwner) {
          return res.status(403).send({
            message: "Forbidden: You don't have permission to delete this task",
          });
        }

        const pendingSubmissions = await submittedTasksCollection
          .find({ task_id: id, status: { $in: ["pending", "rejected"] } })
          .toArray();

        // update worker submissions related to this task
        await submittedTasksCollection.updateMany(
          {
            task_id: id,
            status: { $in: ["pending", "rejected"] },
          },
          {
            $set: {
              status: isAdmin ? "cancelled by admin" : "cancelled by buyer",
              cancelledAt: new Date(),
            },
          },
        );

        // delete the actual task
        await taskCollection.deleteOne({ _id: new ObjectId(id) });

        // dispatch system alerts to workers
        for (const sub of pendingSubmissions) {
          await dispatchNotification({
            to_email: sub.worker.email,
            title: isAdmin
              ? "Task Removed by Admin"
              : "Task Cancelled by Buyer",
            message: isAdmin
              ? `The task "${task.task_title}" was force-removed by administration for platform compliance violations.`
              : `The buyer has retracted the task campaign "${task.task_title}". Your submission has been dropped.`,
            type: "task_lifecycle",
            action_route: "/dashboard/worker-submissions",
          });
        }

        res.send({
          success: true,
          message: isAdmin
            ? "Task removed by Admin successfully. Worker submission history updated."
            : "Task removed successfully. Worker submission history preserved.",
        });
      } catch (error) {
        console.error("Delete Task Error:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // Save submitted_tasks on the database with patch i.e., update task workers
    app.post("/submitted-task", verifyToken, async (req, res) => {
      const { task_id, submission_details, worker_name } = req.body;
      const worker_email = req.user.email;

      try {
        // existing check for pending/approved submissions
        const activeSubmission = await submittedTasksCollection.findOne({
          task_id: task_id,
          "worker.email": worker_email,
          status: { $in: ["pending", "approved"] },
        });

        if (activeSubmission) {
          return res.status(400).send({
            message: "You already have a pending or approved submission.",
          });
        }

        // fetch the task to check slots and deadline
        const task = await taskCollection.findOne({
          _id: new ObjectId(task_id),
        });

        if (!task) {
          return res.status(404).send({ message: "Task not found." });
        }

        // deadline check in YYYY-MM-DD format
        const today = new Date().toISOString().slice(0, 10);
        const deadline = task.completion_date.slice(0, 10);

        if (today > deadline) {
          return res.status(400).send({
            message:
              "The deadline for this task has passed. Submissions are closed.",
          });
        }

        // check for task re-submission
        const previousSubmission = await submittedTasksCollection.findOne({
          task_id: task_id,
          "worker.email": worker_email,
          status: { $in: ["rejected", "in_review"] },
        });

        // check worker availability
        if (!previousSubmission && task.required_workers <= 0) {
          return res.status(400).send({ message: "No slots available" });
        }

        // create and upsert submission
        const newSubmission = {
          task_id: task_id,
          task_title: task.task_title,
          payable_amount: task.payable_amount,
          worker: { email: worker_email, name: worker_name },
          submission_details: submission_details,
          buyer: { name: task.buyer.name, email: task.buyer.email },
          current_date: today,
          submittedAt: new Date(),
          status: "pending",
        };

        const result = await submittedTasksCollection.updateOne(
          { task_id, "worker.email": worker_email },
          { $set: newSubmission },
          { upsert: true },
        );

        // only decrease slot for worker's first attempt
        if (!previousSubmission) {
          await taskCollection.updateOne(
            { _id: new ObjectId(task_id) },
            { $inc: { required_workers: -1 } },
          );
        }

        // dispatch buyer alerts for inbound work
        await dispatchNotification({
          to_email: task.buyer.email,
          title: previousSubmission
            ? "Task Re-submitted"
            : "New Task Submission Incoming",
          message: `${worker_name} has ${previousSubmission ? "revised and re-submitted" : "submitted work for"} your task: "${task.task_title}".`,
          type: "task_lifecycle",
          action_route: "/dashboard/buyer-home",
        });

        res.send(result);
      } catch (error) {
        console.error("Submission Error:", error);
        res.status(500).send({ message: "Failed to submit task" });
      }
    });

    // Get all submitted tasks for a specific worker
    app.get("/submitted-task/:email", verifyToken, async (req, res) => {
      try {
        const email = req.params.email;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 6;
        const skip = (page - 1) * limit;

        const query = { "worker.email": email };

        // get total count for metadata calculations
        const totalSubmissions = await submittedTasksCollection.countDocuments(query);
        const totalPages = Math.ceil(totalSubmissions / limit);

        // fetch the specific chunk of paginated data
        const submissions = await submittedTasksCollection
          .find(query)
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          submissions,
          meta: {
            totalSubmissions,
            totalPages,
            currentPage: page,
          },
        });
      } catch (error) {
        res.status(500).send({ message: "Internal Server Error", error });
      }
    });

    // Get all pending submissions for a specific buyer
    app.get("/submitted-task/buyer/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      try {
        if (req.user.email !== email) {
          return res.status(403).send({ message: "Forbidden" });
        }
        const result = await submittedTasksCollection
          .find({
            "buyer.email": email,
            status: { $in: ["pending", "in_review"] },
          })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch submissions" });
      }
    });

    // Update submitted task status
    app.patch("/submitted-task/:id/review", verifyToken, async (req, res) => {
      const id = req.params.id;
      const { action } = req.body;

      try {
        // validation of unknown status
        if (!["approved", "rejected", "in_review"].includes(action)) {
          return res.status(400).send({ message: "Invalid action" });
        }

        const submission = await submittedTasksCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!submission)
          return res.status(404).send({ message: "Submission not found" });

        // only the task's buyer can review
        if (submission.buyer.email !== req.user.email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        if (action === "in_review" && submission.status !== "pending") {
          return res.status(400).send({
            message:
              "This submission is already in review or has already been finalized.",
          });
        }

        if (!["pending", "in_review"].includes(submission.status)) {
          return res
            .status(400)
            .send({ message: "Submission already finalized" });
        }

        const updateFields = {
          status: action,
          reviewedAt: new Date(),
        };

        // update the submission status in the collection
        await submittedTasksCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateFields },
        );

        if (action === "rejected") {
          // refund the task slot
          await taskCollection.updateOne(
            { _id: new ObjectId(submission.task_id) },
            { $inc: { required_workers: 1 } },
          );

          // notify worker rejection (CRASH FIX: Removed the undefined feedback variable)
          await dispatchNotification({
            to_email: submission.worker.email,
            title: "Submission Declined",
            message: `Your work for "${submission.task_title}" was rejected.`,
            type: "task_lifecycle",
            action_route: "/dashboard/worker-submissions",
          });
        }

        if (action === "approved") {
          await usersCollection.updateOne(
            { email: submission.buyer.email },
            { $inc: { coins: -submission.payable_amount } },
          );

          // credit coins to the worker
          await usersCollection.updateOne(
            { email: submission.worker.email },
            { $inc: { coins: submission.payable_amount } },
          );

          await transactionsCollection.insertOne({
            receiver_email: submission.worker.email,
            sender_email: submission.buyer.email,
            amount: submission.payable_amount,
            type: "payout",
            task_id: submission.task_id,
            task_title: submission.task_title,
            status: "completed",
            timestamp: new Date(),
          });

          // notify worker's payout
          await dispatchNotification({
            to_email: submission.worker.email,
            title: "Task Approved! Payout Sent",
            message: `Excellent work! Your submission for "${submission.task_title}" was approved. ${submission.payable_amount} coins have been added to your vault.`,
            type: "payout",
            action_route: "/dashboard/worker-home",
          });

          // notify buyer's task approval
          await dispatchNotification({
            to_email: submission.buyer.email,
            title: "Task Approved & Payment Settled",
            message: `You have successfully approved the task submission for "${submission.task_title}" and transferred ${submission.payable_amount} coins to ${submission.worker.name || "the worker"}.`,
            type: "payment",
            action_route: "/dashboard/buyer-home",
          });
        }

        if (action === "in_review") {
          // notify worker's submission revisions
          await dispatchNotification({
            to_email: submission.worker.email,
            title: "Revision Requested",
            message: `The buyer requested changes on your work for "${submission.task_title}". Please review submission guidelines.`,
            type: "task_lifecycle",
            action_route: "/dashboard/my-submissions",
          });
          return res.send({ success: true, message: "Revision requested" });
        }

        res.send({ success: true });
      } catch (error) {
        console.error("Review error:", error);
        res.status(500).send({ message: "Failed to process review" });
      }
    });

    // Get worker's stats
    app.get("/worker-stats/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (req.user.email !== email) {
        return res.status(403).send({ message: "Forbidden Access" });
      }

      try {
        const stats = await submittedTasksCollection
          .aggregate([
            { $match: { "worker.email": email } },
            {
              $group: {
                _id: null,
                totalSubmissions: { $sum: 1 },
                totalPendingSubmissions: {
                  $sum: {
                    $cond: [
                      { $eq: ["$status", ["pending", "in_review"]] },
                      1,
                      0,
                    ],
                  },
                },
                // sum payable_amount ONLY for approved tasks
                totalEarnings: {
                  $sum: {
                    $cond: [
                      { $eq: ["$status", "approved"] },
                      "$payable_amount",
                      0,
                    ],
                  },
                },
              },
            },
            {
              $project: {
                _id: 0,
                totalSubmissions: 1,
                totalPendingSubmissions: 1,
                totalEarnings: 1,
              },
            },
          ])
          .toArray();

        const {
          totalSubmissions = 0,
          totalPendingSubmissions = 0,
          totalEarnings = 0,
        } = stats[0] || {};

        const totalEarningsDollar =
          totalEarnings > 0
            ? Math.floor((totalEarnings / WITHDRAW_COIN_TO_DOLLAR_RATE) * 100) /
              100
            : 0;
        res.send({
          totalSubmissions,
          totalPendingSubmissions,
          totalEarnings,
          totalEarningsDollar,
        });
      } catch (error) {
        console.error("Aggregation Error", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // Get buyer stats
    app.get("/buyer-stats/:email", verifyToken, async (req, res) => {
      const email = req.params.email;

      // check user is request their own stats
      if (req.user.email !== email) {
        return res.status(403).send({ message: "Forbidden Access" });
      }

      try {
        const [taskStats, paymentStats] = await Promise.all([
          taskCollection
            .aggregate([
              { $match: { "buyer.email": email } },
              {
                $group: {
                  _id: null,
                  totalTasks: { $sum: 1 },
                  totalPendingWorkers: { $sum: "$required_workers" },
                },
              },
              {
                $project: {
                  _id: 0,
                  totalTasks: 1,
                  totalPendingWorkers: 1,
                },
              },
            ])
            .toArray(),

          submittedTasksCollection
            .aggregate([
              { $match: { "buyer.email": email, status: "approved" } },
              {
                $group: {
                  _id: null,
                  totalPaymentsPaidCoins: { $sum: "$payable_amount" },
                },
              },
              {
                $project: {
                  _id: 0,
                  totalPaymentsPaidCoins: 1,
                },
              },
            ])
            .toArray(),
        ]);
        res.send({
          totalTasks: taskStats[0]?.totalTasks ?? 0,
          totalPendingWorkers: taskStats[0]?.totalPendingWorkers ?? 0,
          totalPaymentsPaidCoins: paymentStats[0]?.totalPaymentsPaidCoins ?? 0,
          totalPaymentsPaidDollar:
            Math.round(
              ((paymentStats[0]?.totalPaymentsPaidCoins ?? 0) /
                COIN_TO_DOLLAR_RATE) *
                100,
            ) / 100,
        });
      } catch (error) {
        console.error("Buyer stats error:", error);
        res.status(500).send({ message: "Failed to fetch buyer stats" });
      }
    });

    // Get admin stats
    app.get("/admin-stats", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const [userStats, paymentStats] = await Promise.all([
          // from users collection --> count workers, buyers, sum all coins
          usersCollection
            .aggregate([
              {
                $group: {
                  _id: null,
                  totalWorkers: {
                    $sum: { $cond: [{ $eq: ["$role", "worker"] }, 1, 0] },
                  },
                  totalBuyers: {
                    $sum: { $cond: [{ $eq: ["$role", "buyer"] }, 1, 0] },
                  },
                  totalCoins: { $sum: { $ifNull: ["$coins", 0] } },
                },
              },
              {
                $project: {
                  _id: 0,
                  totalWorkers: 1,
                  totalBuyers: 1,
                  totalCoins: 1,
                },
              },
            ])
            .toArray(),

          // from submitted_tasks --> sum payable_amount where approved
          submittedTasksCollection
            .aggregate([
              { $match: { status: "approved" } },
              {
                $group: {
                  _id: null,
                  totalApprovedCoins: { $sum: "$payable_amount" },
                },
              },
              {
                $project: {
                  _id: 0,
                  totalPaymentsCoins: "$totalApprovedCoins",
                },
              },
            ])
            .toArray(),
        ]);

        res.send({
          totalWorkers: userStats[0]?.totalWorkers ?? 0,
          totalBuyers: userStats[0]?.totalBuyers ?? 0,
          totalCoins: userStats[0]?.totalCoins ?? 0,
          totalPaymentsCoins: paymentStats[0]?.totalPaymentsCoins ?? 0,
          totalPaymentsUSD:
            Math.round(
              ((paymentStats[0]?.totalPaymentsCoins ?? 0) /
                COIN_TO_DOLLAR_RATE) *
                100,
            ) / 100,
        });
      } catch (error) {
        console.error("Admin stats error:", error);
        res.status(500).send({ message: "Failed to fetch admin stats" });
      }
    });

    // Withdraw coin request
    app.post("/withdrawals", verifyToken, async (req, res) => {
      const withdrawalData = req.body;
      const workerEmail = req.user.email;

      // use session for atomicity
      const session = client.startSession();

      try {
        if (withdrawalData.worker_email !== workerEmail) {
          return res.status(403).send({ message: "Forbidden Access" });
        }

        const {
          worker_name,
          withdrawal_coin,
          withdrawal_amount,
          payment_system,
          account_number,
        } = withdrawalData;

        // validation
        if (
          !worker_name ||
          !withdrawal_coin ||
          !payment_system ||
          !account_number
        ) {
          return res.status(400).send({ message: "All fields are required" });
        }

        const requestedCoins = Number(withdrawal_coin);
        const calculatedUSD = requestedCoins / WITHDRAW_COIN_TO_DOLLAR_RATE;

        if (requestedCoins < MIN_WITHDRAW_COINS) {
          return res.status(400).send({
            message: `Minimum withdrawal is ${MIN_WITHDRAW_COINS} coins.`,
          });
        }

        await session.withTransaction(async () => {
          const user = await usersCollection.findOne(
            { email: workerEmail },
            { session },
          );

          if (!user || user.coins < requestedCoins) {
            throw new Error("Insufficient balance or user not found");
          }

          const withdrawalDoc = {
            worker_email: workerEmail,
            worker_name,
            withdrawal_coin: requestedCoins,
            withdrawal_amount: calculatedUSD,
            payment_system,
            account_number,
            withdraw_date: new Date(),
            status: "pending",
          };

          // create withdrawal record
          const result = await withdrawalsCollection.insertOne(withdrawalDoc, {
            session,
          });

          // deduct coins from user
          await usersCollection.updateOne(
            { email: workerEmail },
            { $inc: { coins: -requestedCoins } },
            { session },
          );

          // create transaction ledger
          await transactionsCollection.insertOne(
            {
              receiver_email: workerEmail,
              amount: requestedCoins,
              usd_value: calculatedUSD,
              type: "withdrawal",
              status: "pending",
              description: `Withdrawal via ${payment_system}`,
              withdrawal_id: result.insertedId,
              timestamp: new Date(),
            },
            { session },
          );
        });

        // notification for withdrawal request
        await dispatchNotification({
          to_email: workerEmail,
          title: "Withdrawal Requested",
          message: `Your request to withdraw ${requestedCoins} coins ($${calculatedUSD.toFixed(2)}) is submitted and pending admin review.`,
          type: "financial",
          action_route: "/dashboard/worker-withdrawals",
        }); // passing session ensures it rolls back if the database transaction fails

        res.status(201).send({
          success: true,
          message: "Withdrawal request submitted successfully",
        });
      } catch (error) {
        console.error("Withdrawal Error:", error);
        const status =
          error.message === "Insufficient balance or user not found"
            ? 400
            : 500;
        res
          .status(status)
          .send({ message: error.message || "Failed to process withdrawal" });
      } finally {
        await session.endSession();
      }
    });

    // Get all pending withdrawals for admin
    app.get("/admin/withdrawals", verifyToken, verifyAdmin, async (req, res) => {
        const result = await withdrawalsCollection
          .find({ status: "pending" })
          .toArray();
        res.send(result);
      },
    );

    // Withdrawal approval route for admin
    app.patch("/admin/withdraw-process/:id",verifyToken, verifyAdmin, async (req, res) => {
        const id = req.params.id;
        const { action } = req.body; // 'approve' or 'reject'
        const filter = { _id: new ObjectId(id) };

        try {
          const request = await withdrawalsCollection.findOne(filter);
          if (!request)
            return res.status(404).send({ message: "Request not found" });

          // ignore if status is pending
          if (request.status !== "pending") {
            return res
              .status(400)
              .send({ message: `This request is already ${request.status}` });
          }

          if (action === "approve") {
            // update withdrawal status
            await withdrawalsCollection.updateOne(filter, {
              $set: { status: "approved" },
            });
            // mark transaction as completed
            await transactionsCollection.updateOne(
              { withdrawal_id: new ObjectId(id) },
              { $set: { status: "completed" } },
            );
            // dispatch success notification
            await dispatchNotification({
              to_email: request.worker_email,
              title: "Withdrawal Request Paid Out!",
              message: `Your financial withdrawal request for ${request.withdrawal_coin} coins ($${request.withdrawal_amount.toFixed(2)}) via ${request.payment_system} has been approved and dispatched.`,
              type: "withdrawal",
              action_route: "/dashboard/worker-home",
            });
            return res.send({
              success: true,
              message: "Withdrawal Approved & Paid",
            });
          }

          if (action === "reject") {
            // update withdrawal status
            await withdrawalsCollection.updateOne(filter, {
              $set: { status: "rejected" },
            });

            // refund coins
            await usersCollection.updateOne(
              { email: request.worker_email },
              { $inc: { coins: request.withdrawal_coin } },
            );

            // update status as rejected on transaction
            await transactionsCollection.updateOne(
              { withdrawal_id: new ObjectId(id) },
              { $set: { status: "rejected" } },
            );

            // dispatch refund notification
            await dispatchNotification({
              to_email: request.worker_email,
              title: "Withdrawal Request Declined",
              message: `Your withdrawal request for ${request.withdrawal_coin} coins was rejected. The entire balance has been safely refunded to your account profile.`,
              type: "withdrawal",
              action_route: "/dashboard/worker-home",
            });
            return res.send({
              success: true,
              message: "Withdrawal Rejected & Coins Refunded",
            });
          }

          res.status(400).send({ message: "Invalid action type" });
        } catch (error) {
          res
            .status(500)
            .send({ message: "Process failed", error: error.message });
        }
      },
    );

    // Fetch all coin purchase package options
    app.get("/packages", verifyToken, async (req, res) => {
      try {
        //.find() to get all packages and sort them by coin amount (ascending)
        const result = await packagesCollection
          .find()
          .sort({ coins: 1 })
          .toArray();

        res.send(result);
      } catch (error) {
        console.error("Error fetching packages:", error);
        res.status(500).send({ message: "Failed to load coin packages" });
      }
    });

    // Get user's daily and monthly purchase totals
    app.get("/user-purchase-stats", verifyToken, async (req, res) => {
      try {
        const email = req.user.email;

        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({
            message: "User not found",
          });
        }

        const usage = await getPurchaseUsage(email, user.timezone || "UTC");

        res.send({
          dailyPurchased: usage.dailyPurchased,
          monthlyPurchased: usage.monthlyPurchased,

          dailyRemaining: Math.max(DAILY_COIN_LIMIT - usage.dailyPurchased, 0),

          monthlyRemaining: Math.max(
            MONTHLY_COIN_LIMIT - usage.monthlyPurchased,
            0,
          ),

          dailyLimit: DAILY_COIN_LIMIT,
          monthlyLimit: MONTHLY_COIN_LIMIT,
        });
      } catch (error) {
        console.error(error);

        res.status(500).send({
          message: "Failed to load purchase stats",
        });
      }
    });

    // Process coin purchase with daily and monthly limit
    app.post("/purchase-coins", verifyToken, async (req, res) => {
      const { packageId } = req.body;
      const userEmail = req.user.email;

      if (!ObjectId.isValid(packageId)) {
        return res.status(400).send({ message: "Invalid Package ID" });
      }

      try {
        // fetch User and Package in parallel
        const [user, pkg] = await Promise.all([
          usersCollection.findOne({ email: userEmail }),
          packagesCollection.findOne({ _id: new ObjectId(packageId) }),
        ]);

        if (!user || !pkg) {
          return res.status(404).send({ message: "User or Package not found" });
        }

        // luxon for calculate time boundaries based on user's timezone
        const userTimezone = user.timezone;
        const userNow = DateTime.now().setZone(userTimezone);

        // get start of day and start of month as UTC date objects for db
        const startOfDay = userNow.startOf("day").toJSDate();
        const startOfMonth = userNow.startOf("month").toJSDate();

        // aggregate current usage from the start of the month
        const usage = await getPurchaseUsage(userEmail, user.timezone || "UTC");

        const daily = usage.dailyPurchased;
        const monthly = usage.monthlyPurchased;

        // check daily limit
        if (daily + pkg.coins > DAILY_COIN_LIMIT) {
          return res.status(429).send({
            success: false,
            type: "daily_limit",

            message: `Daily limit exceeded`,

            current: daily,
            limit: DAILY_COIN_LIMIT,
            remaining: DAILY_COIN_LIMIT - daily,
            attemptedPurchase: pkg.coins,
          });
        }

        if (monthly + pkg.coins > MONTHLY_COIN_LIMIT) {
          return res.status(429).send({
            success: false,
            type: "monthly_limit",

            message: `Monthly limit exceeded`,

            current: monthly,
            limit: MONTHLY_COIN_LIMIT,
            remaining: MONTHLY_COIN_LIMIT - monthly,
            attemptedPurchase: pkg.coins,
          });
        }
        // save transactions on collection
        const transactionDoc = {
          email: userEmail,
          type: "purchase",
          coins: pkg.coins,
          dollar_amount: pkg.price_usd,
          status: "completed",
          timestamp: new Date(),
        };

        await Promise.all([
          purchasesCollection.insertOne({
            ...transactionDoc,
            package_name: pkg.name,
          }),
          transactionsCollection.insertOne(transactionDoc),
          usersCollection.updateOne(
            { email: userEmail },
            { $inc: { coins: pkg.coins } }, // $inc is atomic on a single document
          ),
          dispatchNotification({
            to_email: userEmail,
            title: "Coins Purchased Successfully!",
            message: `Success! You bought the "${pkg.name}" package. ${pkg.coins} coins have been added to your balance.`,
            type: "financial",
            action_route: "/dashboard/buyer-home",
          }),
        ]);

        res.status(201).send({
          success: true,
          addedCoins: pkg.coins,
          message: "Purchase completed successfully",
        });
      } catch (error) {
        console.error("Purchase error:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // Fetches all approved payouts made by a specific buyer to workers
    app.get("/buyer-payments/:email", verifyToken, async (req, res) => {
      const email = req.params.email;

      try {
        if (req.user.email !== email) {
          return res.status(403).send({ message: "Forbidden Access" });
        }

        // query for approved submissions linked to this buyer
        const result = await submittedTasksCollection
          .find({
            "buyer.email": email,
            status: "approved",
          })
          .sort({ reviewedAt: -1 }) // Show most recent payouts first
          .toArray();

        res.send(result);
      } catch (error) {
        console.error("Error fetching buyer payment history:", error);
        res.status(500).send({ message: "Failed to fetch payment history" });
      }
    });

    // get a user's notification timeline (Newest first)
    app.get("/notifications/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (req.user.email !== email)
        return res.status(403).send({ message: "Forbidden Access" });

      try {
        const alerts = await notificationsCollection
          .find({ to_email: email })
          .sort({ timestamp: -1 })
          .limit(50) // Caps database cursor payload size
          .toArray();
        res.send(alerts);
      } catch (error) {
        res.status(500).send({ message: "Failed to load notifications" });
      }
    });

    // Atomic single read flag state mutation
    app.patch("/notifications/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      try {
        const target = await notificationsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!target)
          return res.status(404).send({ message: "Notification missing" });
        if (target.to_email !== req.user.email)
          return res.status(403).send({ message: "Forbidden" });

        await notificationsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { isRead: true } },
        );
        res.send({ success: true });
      } catch (error) {
        res
          .status(500)
          .send({ message: "Server error flagging event read status" });
      }
    });

    // Bulk read flag state mutation
    app.patch("/notifications/:email/read-all", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (req.user.email !== email)
        return res.status(403).send({ message: "Forbidden Access" });
      try {
        await notificationsCollection.updateMany(
          { to_email: email, isRead: false },
          { $set: { isRead: true } },
        );
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: "Failed to mark updates read" });
        }
      },
    );

    // Get Top 6 Workers based on maximum coins
    app.get("/top-workers", async (req, res) => {
      try {
        const result = await usersCollection
          // filter only workers
          .find({ role: "worker" })
          // sort by coins descending
          .sort({ coins: -1 })
          // restrict to top 6 results
          .limit(6)
          // project only required fields
          .project({
            name: 1,
            image: 1,
            coins: 1,
            _id: 1,
          })
          .toArray();

        res.send(result);
      } catch (error) {
        console.error("Error fetching top workers:", error);
        res.status(500).send({ message: "Failed to fetch top workers data" });
      }
    });


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
