// Test fixture, written broken on purpose: the shape of a real repo (an events app's API). The app-wide
// JSON parser is added before the webhooks router is mounted, in a different file from the route.
import express from "express";
import webhooksRouter from "./routes/webhooks.js";
import ordersRouter from "./routes/orders.js";

export const app = express();

app.use(express.json());

app.use("/orders", ordersRouter);
app.use("/webhooks", webhooksRouter);
