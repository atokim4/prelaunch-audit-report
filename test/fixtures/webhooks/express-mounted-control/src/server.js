// Control: the webhooks router is mounted before the app-wide JSON parser, so it gets the raw body.
import express from "express";
import webhooksRouter from "./routes/webhooks.js";
import ordersRouter from "./routes/orders.js";

export const app = express();

app.use("/webhooks", webhooksRouter);

app.use(express.json());

app.use("/orders", ordersRouter);
