const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
const stripe = require("stripe")(process.env.PAYMENT_SECRET_KEY);
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
// jwt
const jwt = require("jsonwebtoken");

// middleware
app.use(cors());
app.use(express.json());

const verifyJWT = (req, res, next) => {
  // console.log("hitting verify JWT");
  // console.log(req.headers.authorization);
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "unauthorized access" });
  }
  // Bearer token
  const token = authorization.split(" ")[1];
  // console.log("token inside verify JWT", token);
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded) => {
    if (error) {
      return res
        .status(403)
        .send({ error: true, message: "unauthorized access" });
    }
    req.decoded = decoded;
    next();
  });
};

// routes

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.rjusk2x.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const classesCollection = client.db("arts-adventure").collection("classes");
    const selectCourseCollection = client
      .db("arts-adventure")
      .collection("selectCourse");
    const usersCollection = client.db("arts-adventure").collection("users");
    const paymentCollection = client
      .db("arts-adventure")
      .collection("payments");

    // jwt related apis
    app.post("/jwt", (req, res) => {
      const user = req.body;
      console.log(user);
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token }); // token convert to obj
    });

    // warning: use verifyJWT before using verifyAdmin
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      if (user?.role !== "admin") {
        return res
          .status(403)
          .send({ error: true, message: "forbidden access" });
      }
      next();
    };

    // user related apis
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    app.post("/users", async (req, res) => {
      const user = req.body;
      // check if user already exists for google login
      const query = { email: user.email };
      const existingUser = await usersCollection.findOne(query);

      if (existingUser) {
        return res.send({ message: "User already exists" });
      }

      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    // security layer: verifyJWT
    // email same as token email
    // check admin
    app.get("/users/admin/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;

      if (req.decoded.email !== email) {
        return res.send({ admin: false });
      }

      const query = { email: email };
      const user = await usersCollection.findOne(query);
      // console.log(user);
      const result = { admin: user?.role === "admin" };
      res.send(result);
      // console.log(result);
    });

    app.get("/users/instructor/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;

      if (req.decoded.email !== email) {
        return res.send({ instructor: false });
      }

      const query = { email: email };
      const user = await usersCollection.findOne(query);
      console.log(user);
      const result = { instructor: user?.role === "instructor" };
      res.send(result);
      // console.log(result);
    });

    app.get("/users/student/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;

      if (req.decoded.email !== email) {
        return res.send({ student: false });
      }

      const query = { email: email };
      const user = await usersCollection.findOne(query);
      // console.log(user);
      const result = { student: user?.role === "student" };
      res.send(result);
      // console.log(result);
    });

    app.patch("/users/admin/:id", async (req, res) => {
      const id = req.params.id;
      // console.log(id);
      const query = { _id: new ObjectId(id) };
      const update = {
        $set: { role: "admin" },
      };
      const result = await usersCollection.updateOne(query, update);
      res.send(result);
    });

    app.patch("/users/instructor/:id", async (req, res) => {
      const id = req.params.id;
      // console.log(id);
      const query = { _id: new ObjectId(id) };
      const update = {
        $set: { role: "instructor" },
      };
      const result = await usersCollection.updateOne(query, update);
      res.send(result);
    });

    app.delete("/users/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });

    // classes related apis
    app.get("/classes", async (req, res) => {
      const result = await classesCollection.find().toArray();
      res.send(result);
    });

    app.get("/popularClasses", async (req, res) => {
      const query = { status: "approved" };
      const options = { sort: { enrolled: -1 } };
      const result = await classesCollection
        .find(query, options)
        .limit(6)
        .toArray();
      res.send(result);
    });

    // instructor related apis
    // Get Instructors from the database
    app.get("/instructors", async (req, res) => {
      const query = { role: "instructor" };
      const result = await usersCollection.find(query).toArray();
      res.send(result);
    });

    // course selection related apis
    app.get("/selectCourse", verifyJWT, async (req, res) => {
      const email = req.query.email;
      if (!email) {
        res.status(401).send("Unauthorized Access");
      }

      const decoded = req.decoded;
      // console.log("came back after verify", decoded);
      if (decoded.email !== req.query.email) {
        return res.status(403).send({ error: 1, message: "forbidden access" });
      }

      const query = { email: email };
      const result = await selectCourseCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/selectCourse", async (req, res) => {
      const item = req.body;
      // console.log(item);
      const result = await selectCourseCollection.insertOne(item);
      res.send(result);
    });

    // delete selectCourse
    app.delete("/selectCourse/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await selectCourseCollection.deleteOne(query);
      res.send(result);
    });

    // create payment intent
    app.post("/create-payment-intent", verifyJWT, async (req, res) => {
      const { price } = req.body;
      const amount = price * 100;
      console.log(price, amount);
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: "usd",
        payment_method_types: ["card"],
      });
      res.send({
        clientSecret: paymentIntent.client_secret,
      });
    });

    // payment related apis
    // app.post("/payments", verifyJWT, async (req, res) => {
    //   const payment = req.body;
    //   const insertResult = await paymentCollection.insertOne(payment);

    //   const selectCourseId = payment.selectCourseItems[0];
    //   console.log("payment", payment);
    //   const query = {
    //     _id: new ObjectId(selectCourseId),
    //   };
    //   const deleteResult = await selectCourseCollection.deleteOne(query);

    //   res.send({ insertResult, deleteResult });

    // });

    app.post("/payments", verifyJWT, async (req, res) => {
      const payment = req.body;
      const insertResult = await paymentCollection.insertOne(payment);

      const deleteQuery = {
        _id: new ObjectId(payment.selectedClassId),
      };
      const deleteResult = await selectCourseCollection.deleteOne(deleteQuery);

      const updateQuery = {
        _id: new ObjectId(payment.classId),
      };
      const updateResult = await classesCollection.updateOne(updateQuery, {
        $inc: { enrolled: 1 },
      });

      const updateSeatsQuery = {
        _id: new ObjectId(payment.classId),
      };
      const updateSeatsResult = await classesCollection.updateOne(
        updateSeatsQuery,
        {
          $inc: { available_seats: -1 },
        }
      );

      const classId = payment.classId;
      const query = { _id: new ObjectId(classId) };

      const classData = await classesCollection.findOne(query);
      const instructorEmail = classData.email;

      const updateInstructorQuery = { email: instructorEmail };

      // if instructor has no students field, create one
      const updateInstructorResult = await usersCollection.updateOne(
        updateInstructorQuery,
        {
          $inc: { students: 1 },
        }
      );

      res.send({
        insertResult,
        deleteResult,
        updateResult,
        updateSeatsResult,
        updateInstructorResult,
      });
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Welcome to Arts Adventure - Backend");
});

app.listen(port, () => {
  console.log(`Arts Adventure server running on port: ${port}`);
});
