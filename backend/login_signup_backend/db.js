const mongoose = require("mongoose");
require("dotenv").config();

const mongoUrl = process.env.mongoUrl;

mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true });

mongoose.connection.on("error", (err) => {
  console.log(`Error connecting to MongoDB: ${err}`);
});

mongoose.connection.on("open", () => {
  console.log(`Successfully Connected to MongoDB`);
});