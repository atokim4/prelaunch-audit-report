// Test fixture, written broken on purpose: the shape of a real repo (a booking API). The router is
// mounted with an inline require() after the app-wide JSON parser.
const express = require("express");

const app = express();

app.use(express.json());

app.use("/api/bookings", require("./routes/bookings"));
app.use("/api/webhooks", require("./routes/webhooks"));

module.exports = { app };
