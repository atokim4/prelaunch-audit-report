import express from "express";

const router = express.Router();

router.post("/", (req, res) => {
  res.json({ parsed: typeof req.body === "object" && !Buffer.isBuffer(req.body), item: req.body?.item ?? null });
});

export default router;
