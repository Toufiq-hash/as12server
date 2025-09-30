const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");
const dotenv = require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET);

const app = express();

app.use(cors({ origin: "*" }));
app.use(express.json());
app.use((req, res, next) => {
  next();
});

const uri = process.env.MONGODB_URI;
if (!uri) {
  process.exit(1);
}

const client = new MongoClient(uri, {
  connectTimeoutMS: 5000,
  serverSelectionTimeoutMS: 5000,
});

let usersCollection, mealsCollection, reviewsCollection, upcomingMealsCollection, ordersCollection, paymentsCollection;

async function connectToMongo() {
  if (!usersCollection) {
    let retries = 3;
    while (retries > 0) {
      try {
        await client.connect();
        const db = client.db("hostel");
        usersCollection = db.collection("users");
        mealsCollection = db.collection("meals");
        reviewsCollection = db.collection("reviews");
        upcomingMealsCollection = db.collection("upcomingMeals");
        ordersCollection = db.collection("orders");
        paymentsCollection = db.collection("payments");
        const collections = [usersCollection, mealsCollection, reviewsCollection, upcomingMealsCollection, ordersCollection, paymentsCollection];
        for (const collection of collections) {
          if (!collection) {
            throw new Error(`Collection ${collection} not initialized`);
          }
        }
        return client;
      } catch (err) {
        retries--;
        if (retries === 0) {
          throw new Error(`MongoDB connection failed after retries: ${err.message}`);
        }
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
  }
  return client;
}

async function startApp() {
  try {
    await connectToMongo();
  } catch (err) {
    process.exit(1);
  }
}
startApp();

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized access: No token provided" });
  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Forbidden access: Invalid token" });
    req.user = { email: decoded.email.toLowerCase() };
    next();
  });
};

const verifyAdmin = async (req, res, next) => {
  try {
    await connectToMongo();
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user || user.role !== "admin") return res.status(403).json({ message: "Admin access only" });
    next();
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

const restrictDuplicateReview = async (req, res, next) => {
  try {
    await connectToMongo();
    const { mealId, userEmail } = req.body;
    if (!ObjectId.isValid(mealId)) return res.status(400).json({ message: "Invalid meal ID format" });
    const exists = await reviewsCollection.findOne({ mealId, userEmail: userEmail.toLowerCase() });
    if (exists) return res.status(400).json({ message: "Duplicate review detected" });
    next();
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

const restrictDuplicateRequest = async (req, res, next) => {
  try {
    await connectToMongo();
    const { mealId } = req.body;
    const userEmail = req.user.email;
    if (!ObjectId.isValid(mealId)) return res.status(400).json({ message: "Invalid meal ID format" });
    const exists = await ordersCollection.findOne({ mealId, userEmail, status: { $in: ["pending", "paid"] } });
    if (exists) return res.status(400).json({ message: "Duplicate request detected" });
    next();
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

const isValidUrl = (url) => {
  try { new URL(url); return true; } catch { return false; }
};

app.post("/jwt", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });
  const token = jwt.sign({ email: email.toLowerCase() }, process.env.JWT_SECRET, { expiresIn: "70d" });
  res.json({ token });
});

app.post("/login", async (req, res) => {
  try {
    await connectToMongo();
    const { idToken, email } = req.body;
    if (!idToken || !email) return res.status(400).json({ message: "ID token and email required" });
    const normalizedEmail = email.toLowerCase();
    let user = await usersCollection.findOne({ email: normalizedEmail });
    if (!user) {
      const result = await usersCollection.insertOne({
        name: email.split("@")[0],
        email: normalizedEmail,
        photoURL: photoURL || null,
        role: "user",
        googleAuth: false,
        createdAt: new Date(),
      });
      user = { _id: result.insertedId, email: normalizedEmail };
    }
    const token = jwt.sign({ email: normalizedEmail }, process.env.JWT_SECRET, { expiresIn: "70d" });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/users", async (req, res) => {
  try {
    await connectToMongo();
    const user = req.body;
    if (!user?.email || !user?.name) {
      return res.status(400).json({ message: "Name and email are required" });
    }
    const exists = await usersCollection.findOne(
      { email: user.email.toLowerCase() },
      { collation: { locale: "en", strength: 2 } }
    );
    if (exists) {
      return res.status(409).json({ message: "User exists" });
    }
    const result = await usersCollection.insertOne({
      name: user.name,
      email: user.email.toLowerCase(),
      photoURL: user.photoURL || null,
      role: user.role || "user",
      googleAuth: user.googleAuth || false,
      createdAt: new Date(),
    });
    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const users = await usersCollection.find().toArray();
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/users/:email", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const user = await usersCollection.findOne(
      { email: req.params.email.toLowerCase() },
      { collation: { locale: "en", strength: 2 } }
    );
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/users/admin/:email", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const user = await usersCollection.findOne(
      { email: req.params.email.toLowerCase() },
      { collation: { locale: "en", strength: 2 } }
    );
    res.json({ isAdmin: user?.role === "admin" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/users/admin/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role: "admin" } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }
    const result = await usersCollection.deleteOne({
      _id: new ObjectId(req.params.id),
    });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/meals", async (req, res) => {
  try {
    await connectToMongo();
    if (!mealsCollection) {
      throw new Error("Meals collection not initialized");
    }
    const { category, minPrice, maxPrice, search, page = 1, limit = 6 } = req.query;
    const query = {};

    if (category && category !== "All") {
      query.category = category;
    }

    if (minPrice || maxPrice) {
      query.price = {};
      if (minPrice && !isNaN(Number(minPrice))) {
        query.price.$gte = Number(minPrice);
      } else if (minPrice) {
        throw new Error("Invalid minPrice");
      }
      if (maxPrice && !isNaN(Number(maxPrice))) {
        query.price.$lte = Number(maxPrice);
      } else if (maxPrice) {
        throw new Error("Invalid maxPrice");
      }
    }

    if (search) {
      query.title = { $regex: search, $options: "i" };
    }

    const pageNum = parseInt(page) || 1;
    const limitNum = parseInt(limit) || 6;
    const skip = (pageNum - 1) * limitNum;

    const meals = await mealsCollection
      .find(query)
      .skip(skip)
      .limit(limitNum)
      .toArray();

    const total = await mealsCollection.countDocuments(query);

    res.json({
      meals,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.post("/meals", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const meal = req.body;
    const requiredFields = ["title", "category", "price", "description", "ingredients"];
    const missingFields = requiredFields.filter((field) => !meal[field]);
    if (missingFields.length > 0) {
      return res.status(400).json({ message: `Missing required fields: ${missingFields.join(", ")}` });
    }
    meal.distributorName = meal.distributorName || "Hostel Kitchen";
    if (meal.photoUrl && !isValidUrl(meal.photoUrl)) {
      return res.status(400).json({ message: "Invalid photoUrl" });
    }
    meal.ingredients = Array.isArray(meal.ingredients) ? meal.ingredients : [];
    meal.price = Number(meal.price);
    meal.likedBy = meal.likedBy || [];
    meal.rating = meal.rating || 0;
    meal.reviews_count = meal.reviews_count || 0;
    meal.postTime = meal.postTime ? new Date(meal.postTime) : new Date();
    const result = await mealsCollection.insertOne(meal);
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/meals/stats", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const validMealIds = await mealsCollection
      .find({}, { projection: { _id: 1 } })
      .toArray()
      .then((meals) => meals.map((m) => m._id.toString()));

    const stats = await mealsCollection
      .aggregate([
        {
          $lookup: {
            from: "reviews",
            let: { mealId: "$_id" },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      { $eq: ["$mealId", { $toString: "$$mealId" }] },
                      { $regexMatch: { input: "$mealId", regex: /^[0-9a-fA-F]{24}$/ } },
                      { $in: ["$mealId", validMealIds] },
                    ],
                  },
                },
              },
            ],
            as: "reviews",
          },
        },
        {
          $addFields: {
            likes: { $size: { $ifNull: ["$likedBy", []] } },
          },
        },
        {
          $project: {
            _id: 1,
            title: 1,
            likes: 1,
            reviewCount: { $size: "$reviews" },
            rating: { $avg: "$reviews.rating" },
          },
        },
      ])
      .toArray();

    res.json(stats);
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ message: "Invalid meal ID format in database" });
    }
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.get("/meals/unserved", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const { search, page = 1, limit = 10 } = req.query;
    const pageNum = parseInt(page) || 1;
    const limitNum = parseInt(limit) || 10;
    const skip = (pageNum - 1) * limitNum;

    const validMealIds = await mealsCollection
      .find({}, { projection: { _id: 1 } })
      .toArray()
      .then((meals) => meals.map((m) => m._id.toString()));

    let matchStage = {
      status: { $in: ["pending", "paid"] },
      mealId: { $type: "string", $regex: /^[0-9a-fA-F]{24}$/, $in: validMealIds },
    };

    if (search) {
      const users = await usersCollection
        .find(
          {
            $or: [
              { name: { $regex: search, $options: "i" } },
              { email: { $regex: search, $options: "i" } },
            ],
          },
          { collation: { locale: "en", strength: 2 } }
        )
        .toArray();
      const userEmails = users.map((user) => user.email.toLowerCase());
      if (userEmails.length === 0) {
        return res.json({
          meals: [],
          total: 0,
          page: pageNum,
          limit: limitNum,
          totalPages: 0,
        });
      }
      matchStage.userEmail = { $in: userEmails };
    }

    const matchingOrdersCount = await ordersCollection.countDocuments(matchStage);
    if (matchingOrdersCount === 0) {
      return res.json({
        meals: [],
        total: 0,
        page: pageNum,
        limit: limitNum,
        totalPages: 0,
      });
    }

    const pipeline = [
      { $match: matchStage },
      {
        $lookup: {
          from: "meals",
          let: { mealId: { $toObjectId: "$mealId" } },
          pipeline: [
            {
              $match: {
                $expr: { $eq: ["$_id", "$$mealId"] },
              },
            },
          ],
          as: "mealData",
        },
      },
      { $unwind: { path: "$mealData", preserveNullAndEmptyArrays: true } },
      {
        $lookup: {
          from: "users",
          localField: "userEmail",
          foreignField: "email",
          as: "userData",
        },
      },
      {
        $unwind: {
          path: "$userData",
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          _id: 1,
          mealTitle: { $ifNull: ["$mealData.title", "Unknown Meal"] },
          userEmail: 1,
          userName: { $ifNull: ["$userData.name", "Unknown User"] },
          status: 1,
          price: 1,
        },
      },
      { $skip: skip },
      { $limit: limitNum },
    ];

    const unserved = await ordersCollection.aggregate(pipeline).toArray();
    res.json({
      meals: unserved,
      total: matchingOrdersCount,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(matchingOrdersCount / limitNum),
    });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ message: "Invalid meal ID format in database" });
    }
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/meals/:id", async (req, res) => {
  try {
    await connectToMongo();
    const mealId = req.params.id;
    if (!ObjectId.isValid(mealId)) {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }
    const meal = await mealsCollection.findOne({
      _id: new ObjectId(mealId),
    });
    if (!meal) {
      return res.status(404).json({ message: "Meal not found" });
    }
    const reviewsCount = await reviewsCollection.countDocuments({
      mealId: meal._id.toString(),
    });
    res.json({ ...meal, reviews_count: reviewsCount });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/meals/like/:id", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const userEmail = req.user.email;
    const mealId = req.params.id;

    if (!ObjectId.isValid(mealId)) {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }

    const meal = await mealsCollection.findOne({
      _id: new ObjectId(mealId),
    });
    if (!meal) return res.status(404).json({ message: "Meal not found" });

    const likedBy = Array.isArray(meal.likedBy) ? meal.likedBy : [];
    const alreadyLiked = likedBy.includes(userEmail);

    const update = alreadyLiked
      ? { $pull: { likedBy: userEmail } }
      : { $addToSet: { likedBy: userEmail } };

    const result = await mealsCollection.updateOne(
      { _id: new ObjectId(mealId) },
      update
    );

    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/my-likes", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const userEmail = req.query.email?.toLowerCase();
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    if (userEmail !== req.user.email) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const likedMeals = await mealsCollection
      .find({ likedBy: userEmail }, { collation: { locale: "en", strength: 2 } })
      .skip(skip)
      .limit(limit)
      .toArray();
    const total = await mealsCollection.countDocuments(
      { likedBy: userEmail },
      { collation: { locale: "en", strength: 2 } }
    );

    res.json({
      meals: likedMeals,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/admin/meals", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const { sortBy, sortOrder, page = 1, limit = 10 } = req.query;
    const pageNum = parseInt(page) || 1;
    const limitNum = parseInt(limit) || 10;
    const skip = (pageNum - 1) * limitNum;

    const validSortFields = ["likes", "reviews_count"];
    const sortField = validSortFields.includes(sortBy) ? sortBy : "title";
    const sortDirection = sortOrder === "desc" ? -1 : 1;

    const meals = await mealsCollection
      .aggregate([
        {
          $addFields: {
            likes: { $size: { $ifNull: ["$likedBy", []] } },
            reviews_count: { $ifNull: ["$reviews_count", 0] },
          },
        },
        {
          $sort: {
            [sortField]: sortDirection,
            title: 1,
          },
        },
        { $skip: skip },
        { $limit: limitNum },
        {
          $project: {
            _id: 1,
            title: 1,
            likes: 1,
            reviews_count: 1,
            rating: { $ifNull: ["$rating", 0] },
            distributorName: { $ifNull: ["$distributorName", "Unknown"] },
          },
        },
      ])
      .toArray();

    const total = await mealsCollection.countDocuments();

    res.json({
      meals,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/meals/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const mealId = req.params.id;
    if (!ObjectId.isValid(mealId)) {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }
    const result = await mealsCollection.deleteOne({
      _id: new ObjectId(mealId),
    });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Meal not found" });
    }
    await reviewsCollection.deleteMany({ mealId });
    await ordersCollection.deleteMany({ mealId });
    res.json({ success: true, deletedCount: result.deletedCount });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/meals/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const mealId = req.params.id;
    const updates = req.body;
    if (!ObjectId.isValid(mealId)) {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }
    const meal = await mealsCollection.findOne({
      _id: new ObjectId(mealId),
    });
    if (!meal) {
      return res.status(404).json({ message: "Meal not found" });
    }
    const allowedFields = ["title", "category", "price", "description", "ingredients", "distributorName", "photoUrl"];
    const updateFields = {};
    allowedFields.forEach((field) => {
      if (updates[field] !== undefined) {
        if (field === "price") {
          updateFields[field] = Number(updates[field]);
        } else if (field === "photoUrl" && updates[field] && !isValidUrl(updates[field])) {
          throw new Error("Invalid photoUrl");
        } else {
          updateFields[field] = updates[field];
        }
      }
    });
    if (Object.keys(updateFields).length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }
    const result = await mealsCollection.updateOne(
      { _id: new ObjectId(mealId) },
      { $set: updateFields }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Meal not found" });
    }
    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    if (err.message === "Invalid photoUrl") {
      return res.status(400).json({ message: "Invalid photoUrl" });
    }
    if (err.name === "BSONError") {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/meal-request", verifyJWT, restrictDuplicateRequest, async (req, res) => {
  try {
    await connectToMongo();
    const { mealId } = req.body;
    const userEmail = req.user.email;

    if (!mealId || !userEmail) {
      return res.status(400).json({ success: false, message: "mealId and userEmail are required" });
    }

    if (!ObjectId.isValid(mealId)) {
      return res.status(400).json({ success: false, message: "Invalid meal ID format" });
    }

    const mealExists = await mealsCollection.findOne({
      _id: new ObjectId(mealId),
      postTime: { $lte: new Date() },
    });
    if (!mealExists) {
      return res.status(404).json({ success: false, message: "Meal not found or not available" });
    }

    const newRequest = {
      mealId,
      userEmail,
      status: "pending",
      requestedAt: new Date(),
      price: mealExists.price,
    };

    const result = await ordersCollection.insertOne(newRequest);
    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ success: false, message: "Invalid meal ID format" });
    }
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/requested-meals", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const userEmail = req.query.email?.toLowerCase();
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    if (!userEmail || userEmail !== req.user.email) {
      return res.status(403).json({ success: false, message: "Forbidden: Email mismatch" });
    }

    const requests = await ordersCollection
      .find({ userEmail }, { collation: { locale: "en", strength: 2 } })
      .skip(skip)
      .limit(limit)
      .toArray();
    const total = await ordersCollection.countDocuments(
      { userEmail },
      { collation: { locale: "en", strength: 2 } }
    );

    const detailedRequests = await Promise.all(
      requests.map(async (reqItem) => {
        let meal = null;
        try {
          if (ObjectId.isValid(reqItem.mealId)) {
            meal = await mealsCollection.findOne({
              _id: new ObjectId(reqItem.mealId),
            });
          }
        } catch (err) {
        }
        return {
          ...reqItem,
          mealTitle: meal?.title || "Unknown Meal",
          mealDescription: meal?.description || "",
          mealPhotoUrl: meal?.photoUrl || "",
        };
      })
    );

    res.json({
      meals: detailedRequests,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.delete("/requested-meals/:id", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const requestId = req.params.id;
    const userEmail = req.user.email;

    if (!ObjectId.isValid(requestId)) {
      return res.status(400).json({ success: false, message: "Invalid request ID" });
    }

    const request = await ordersCollection.findOne({
      _id: new ObjectId(requestId),
    });
    if (!request) {
      return res.status(404).json({ success: false, message: "Request not found" });
    }

    if (request.userEmail.toLowerCase() !== userEmail) {
      return res.status(403).json({ success: false, message: "Forbidden: You can only delete your own requests" });
    }

    const result = await ordersCollection.deleteOne({
      _id: new ObjectId(requestId),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Request not found or already deleted" });
    }

    res.json({ success: true, deletedCount: result.deletedCount });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ success: false, message: "Invalid request ID" });
    }
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.patch("/meals/serve/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const orderId = req.params.id;

    if (!ObjectId.isValid(orderId)) {
      return res.status(400).json({ success: false, message: "Invalid order ID" });
    }

    const order = await ordersCollection.findOne({
      _id: new ObjectId(orderId),
    });
    if (!order) {
      return res.status(404).json({ success: false, message: "Order not found" });
    }

    if (!["pending", "paid"].includes(order.status)) {
      return res.status(400).json({ success: false, message: `Order cannot be served: current status is ${order.status}` });
    }

    if (!ObjectId.isValid(order.mealId)) {
      await ordersCollection.deleteOne({ _id: new ObjectId(orderId) });
      return res.status(400).json({ success: false, message: "Order removed due to invalid meal ID" });
    }

    const meal = await mealsCollection.findOne({
      _id: new ObjectId(order.mealId),
    });
    if (!meal) {
      await ordersCollection.deleteOne({ _id: new ObjectId(orderId) });
      return res.status(400).json({ success: false, message: "Order removed due to non-existent meal" });
    }

    const result = await ordersCollection.updateOne(
      { _id: new ObjectId(orderId) },
      { $set: { status: "delivered", servedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "Order not found" });
    }

    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ success: false, message: "Invalid order ID or meal ID" });
    }
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/admin/orders", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const orders = await ordersCollection.find().toArray();
    const detailedOrders = await Promise.all(
      orders.map(async (order) => {
        let meal = null;
        try {
          if (ObjectId.isValid(order.mealId)) {
            meal = await mealsCollection.findOne({
              _id: new ObjectId(order.mealId),
            });
          }
        } catch (err) {
        }
        const user = await usersCollection.findOne(
          { email: order.userEmail },
          { collation: { locale: "en", strength: 2 } }
        );
        return {
          ...order,
          mealTitle: meal?.title || "Unknown Meal",
          userName: user?.name || "Unknown User",
          price: order.price || meal?.price || 0,
          transactionId: order.transactionId || "N/A",
        };
      })
    );
    res.json(detailedOrders);
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/reviews", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const reviews = await reviewsCollection.find().toArray();
    const detailedReviews = await Promise.all(
      reviews.map(async (review) => {
        let meal = null;
        try {
          if (ObjectId.isValid(review.mealId)) {
            meal = await mealsCollection.findOne({
              _id: new ObjectId(review.mealId),
            });
          }
        } catch (err) {
        }
        return {
          ...review,
          mealTitle: meal?.title || "Unknown Meal",
          userEmail: review.userEmail || "Unknown User",
          likes: review.likes || 0,
        };
      })
    );
    res.json(detailedReviews);
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/reviews", verifyJWT, restrictDuplicateReview, async (req, res) => {
  try {
    await connectToMongo();
    const { mealId, userEmail, rating, comment } = req.body;
    if (!mealId || !userEmail || !rating || !comment) {
      return res.status(400).json({ success: false, message: "mealId, userEmail, rating, and comment are required" });
    }
    if (rating < 1 || rating > 5) {
      return res.status(400).json({ success: false, message: "Rating must be between 1 and 5" });
    }

    if (!ObjectId.isValid(mealId)) {
      return res.status(400).json({ success: false, message: "Invalid meal ID format" });
    }

    const mealExists = await mealsCollection.findOne({
      _id: new ObjectId(mealId),
    });
    if (!mealExists) {
      return res.status(404).json({ success: false, message: "Meal not found" });
    }

    const review = {
      mealId,
      userEmail: userEmail.toLowerCase(),
      rating: Number(rating),
      comment,
      createdAt: new Date(),
      likes: 0,
    };

    const result = await reviewsCollection.insertOne(review);

    const reviews = await reviewsCollection
      .aggregate([
        { $match: { mealId } },
        { $group: { _id: null, avgRating: { $avg: "$rating" }, count: { $sum: 1 } } },
      ])
      .toArray();
    const avgRating = reviews[0]?.avgRating || 0;
    const reviewsCount = reviews[0]?.count || 0;
    await mealsCollection.updateOne(
      { _id: new ObjectId(mealId) },
      { $set: { reviews_count: reviewsCount, rating: avgRating } }
    );

    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ success: false, message: "Invalid meal ID format" });
    }
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/reviews/meal/:mealId", async (req, res) => {
  try {
    await connectToMongo();
    const { mealId } = req.params;
    if (!ObjectId.isValid(mealId)) {
      return res.status(400).json({ success: false, message: "Invalid meal ID format" });
    }
    const mealExists = await mealsCollection.findOne({
      _id: new ObjectId(mealId),
    });
    if (!mealExists) {
      return res.status(404).json({ success: false, message: "Meal not found" });
    }
    const reviews = await reviewsCollection.find({ mealId }).toArray();
    res.json(reviews);
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ success: false, message: "Invalid meal ID format" });
    }
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.delete("/reviews/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: "Invalid review ID" });
    }
    const result = await reviewsCollection.deleteOne({
      _id: new ObjectId(req.params.id),
    });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Review not found" });
    }
    res.json({ success: true, deletedCount: result.deletedCount });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ success: false, message: "Invalid review ID" });
    }
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/my-profile", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const user = await usersCollection.findOne(
      { email: req.user.email },
      { collation: { locale: "en", strength: 2 } }
    );
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/upcoming-meals", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectToMongo();
    const meal = req.body;
    const requiredFields = ["title", "description", "photoUrl", "postTime"];
    const missingFields = requiredFields.filter((field) => !meal[field]);
    if (missingFields.length > 0) {
      return res.status(400).json({ message: `Missing required fields: ${missingFields.join(", ")}` });
    }
    if (meal.photoUrl && !isValidUrl(meal.photoUrl)) {
      return res.status(400).json({ message: "Invalid photoUrl" });
    }
    meal.postTime = new Date(meal.postTime);
    meal.likedBy = [];
    const result = await upcomingMealsCollection.insertOne(meal);
    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/upcoming-meals", async (req, res) => {
  try {
    await connectToMongo();
    const meals = await upcomingMealsCollection
      .find({ postTime: { $gt: new Date() } })
      .toArray();
    res.json(meals);
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.patch("/upcoming-meals/like/:id", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const { userEmail } = req.body;
    const mealId = req.params.id;

    if (!userEmail || userEmail.toLowerCase() !== req.user.email) {
      return res.status(403).json({ message: "Forbidden: Email mismatch" });
    }

    if (!ObjectId.isValid(mealId)) {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }

    const user = await usersCollection.findOne(
      { email: userEmail.toLowerCase() },
      { collation: { locale: "en", strength: 2 } }
    );
    if (!user || !["Silver", "Gold", "Platinum"].includes(user.badge)) {
      return res.status(403).json({ message: "Only premium users can like upcoming meals" });
    }

    const meal = await upcomingMealsCollection.findOne({
      _id: new ObjectId(mealId),
    });
    if (!meal) {
      return res.status(404).json({ message: "Meal not found" });
    }

    const likedBy = Array.isArray(meal.likedBy) ? meal.likedBy : [];
    const alreadyLiked = likedBy.includes(userEmail);

    if (alreadyLiked) {
      return res.status(400).json({ message: "You have already liked this meal" });
    }

    const result = await upcomingMealsCollection.updateOne(
      { _id: new ObjectId(mealId) },
      { $addToSet: { likedBy: userEmail } }
    );

    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    if (err.name === "BSONError") {
      return res.status(400).json({ message: "Invalid meal ID format" });
    }
    res.status(500).json({ message: "Server error" });
  }
});

const packageDetails = {
  silver: { name: "Silver", price: 1000, benefits: ["Like upcoming meals", "Priority support"] },
  gold: { name: "Gold", price: 2000, benefits: ["Like upcoming meals", "Priority support", "Exclusive content"] },
  platinum: { name: "Platinum", price: 3000, benefits: ["Like upcoming meals", "Priority support", "Exclusive content", "VIP events"] },
};

app.get("/packages", async (req, res) => {
  try {
    const packages = Object.values(packageDetails);
    res.json(packages);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/create-payment-intent", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const { amount, email } = req.body;
    if (!amount || !email || email.toLowerCase() !== req.user.email) {
      return res.status(400).json({ message: "Invalid amount or email" });
    }
    const amountInCents = parseInt(amount);
    if (amountInCents < 100) {
      return res.status(400).json({ message: "Amount must be at least $1.00" });
    }
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: "usd",
      payment_method_types: ["card"],
      metadata: { email },
    });
    res.json({ success: true, clientSecret: paymentIntent.client_secret });
  } catch (err) {
    res.status(500).json({ message: "Payment processing error", error: err.message });
  }
});

app.post("/confirm-payment", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const { packageName, transactionId, userEmail } = req.body;
    if (!packageName || !transactionId || !userEmail || userEmail.toLowerCase() !== req.user.email) {
      return res.status(400).json({ message: "Invalid payment details" });
    }
    if (!packageDetails[packageName.toLowerCase()]) {
      return res.status(400).json({ message: "Invalid package name", received: packageName });
    }
    const user = await usersCollection.findOne(
      { email: userEmail.toLowerCase() },
      { collation: { locale: "en", strength: 2 } }
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const payment = {
      userEmail: userEmail.toLowerCase(),
      packageName,
      transactionId,
      amount: packageDetails[packageName.toLowerCase()].price,
      date: new Date(),
    };
    const result = await paymentsCollection.insertOne(payment);
    const userUpdate = await usersCollection.updateOne(
      { email: userEmail.toLowerCase() },
      { $set: { badge: packageName } }
    );
    res.json({ success: true, insertedId: result.insertedId });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.get("/payments", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const userEmail = req.query.email?.toLowerCase();

    if (!userEmail || userEmail !== req.user.email) {
      return res.status(403).json({ message: "Forbidden: Email mismatch" });
    }

    const payments = await paymentsCollection
      .find({ userEmail }, { collation: { locale: "en", strength: 2 } })
      .sort({ date: -1 })
      .toArray();

    const total = await paymentsCollection.countDocuments(
      { userEmail },
      { collation: { locale: "en", strength: 2 } }
    );

    res.json({
      payments,
      total,
      page: 1,
      limit: payments.length,
      totalPages: 1,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.get("/my-reviews", verifyJWT, async (req, res) => {
  try {
    await connectToMongo();
    const userEmail = req.query.email?.toLowerCase();

    if (!userEmail || userEmail !== req.user.email) {
      return res.status(403).json({ message: "Forbidden: Email mismatch" });
    }

    const reviews = await reviewsCollection
      .find({ userEmail }, { collation: { locale: "en", strength: 2 } })
      .sort({ createdAt: -1 })
      .toArray();

    const detailedReviews = await Promise.all(
      reviews.map(async (review) => {
        let meal = null;
        try {
          if (ObjectId.isValid(review.mealId)) {
            meal = await mealsCollection.findOne({ _id: new ObjectId(review.mealId) });
          }
        } catch (err) {
        }
        return {
          ...review,
          mealTitle: meal?.title || "Unknown Meal",
        };
      })
    );

    const total = await reviewsCollection.countDocuments(
      { userEmail },
      { collation: { locale: "en", strength: 2 } }
    );

    res.json({
      reviews: detailedReviews,
      total,
      page: 1,
      limit: detailedReviews.length,
      totalPages: 1,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});




 
app.get("/", (req, res) => res.json("✅HostelMate Server is Running"));


app.use((err, req, res, next) => {
  res.status(500).json({ message: "Server error", error: err.message });
});

const port = process.env.PORT || 3000;
app.listen(port);







