const express = require("express");
const cors = require("cors");

const app = express();

const allowedOrigins = (process.env.RESUME_ALLOWED_ORIGINS || "http://localhost:5173,https://resume.lanzar.me")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("CORS origin not allowed"));
  },
  credentials: true
}));
app.use(express.json());

app.get("/health",(req,res)=>{
    res.json({
        status:"ok",
        service:"LANZAR Resume"
    });
});

const PORT=process.env.PORT||3001;

app.listen(PORT,()=>{
    console.log(`Server running on ${PORT}`);
});
