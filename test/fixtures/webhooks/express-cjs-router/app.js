const express = require("express");
const { markPaid } = require("./billing.js");

const app = express();
const billing = express.Router();

app.use(express.json({ limit: "1mb" }));
app.use("/billing", billing);

billing.post("/webhook", async (req, res) => {
  const { type, data } = req.body;
  if (type === "checkout.session.completed") {
    await markPaid(String(data.object.client_reference_id));
  }
  res.json({ received: true });
});

app.post("/profile", (req, res) => {
  res.json({ name: req.body.name });
});

module.exports = { app };
