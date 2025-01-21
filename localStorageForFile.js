const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const app = express();
const ClamScan = require("clamscan");
const sanitize = require("sanitize-filename");
app.use(express.json());

const MAX_STORAGE = 100 * 1024 * 1024;

const uploadFolder = () => {
  if (!fs.existsSync("uploads")) {
    fs.mkdirSync("uploads");
  }
};

const getFileSize = (folder) => {
  const files = fs.readdirSync(folder);
  const totalSize = 0;
  files.forEach((file) => {
    const filePath = path.join(folder, file);
    totalSize += fs.statSync(filePath).size;
  });
  return totalSize;
};

const clamScan = new ClamScan().init({
  removeInfected: true,
  debugMode: true,
});

const allowedTypes = ["image/jpeg", "image/png", "image/gif"];

const fileFilter = (req, file, cb) => {
  if (allowedTypes.includes(file.mimetype)) {
    return cb(null, true);
  }
  cb(
    new Error("Invalid file type. Only JPEG, PNG, and GIF are allowed"),
    false
  );
};

uploadFolder();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads");
  },
  filename: function (req, file, cb) {
    const sanitizeFileName = sanitize(file.originalname);
    cb(null, Date.now() + "-" + sanitizeFileName);
  },
});
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 4 * 1024 * 1024,
  },
  fileFilter: fileFilter,
});
app.use("/uploads", express.static("uploads"));
app.post("/uploads", upload.array("files", 5), async (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ message: "No files Uploaded" });
  }
  const folderSize = getFolderSize("uploads");
  if (folderSize + req.file.size > MAX_STORAGE) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ message: "Storage quota exceeded" });
  }
  try {
    for (const file of req.files) {
      const scannedResult = await clamScan.scanFile(file.path);
      if (scannedResult.isInfected) {
        fs.unlinkSync(file.path);
        return res
          .status(400)
          .json({ message: "Files are infected with malware" });
      }
    }
    res
      .status(201)
      .json({ message: "File Uploaded SuccessFully", files: req.files });
  } catch (err) {
    res.status(500).json({ message: `Error scanning files: ${err.message}` });
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: `Multer error: ${err.message}` });
  }
  res.status(500).json({ message: `Error: ${err.message}` });
});

app.get("/files/:filename", (req, res) => {
  const filePath = path.join(__dirname, "uploads", req.params.filename);

  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).send("File not found.");
  }
});

app.listen(3000, () => {
  console.log("server is rumming on http://localhost:3000");
});
