const jwt = require("jsonwebtoken");
const blacklist = require("../utils/blacklist");

function auth(req, res, next) {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
        return res.status(401).json({ msg: "No token" });
    }

    if (blacklist.includes(token)) {
        return res.status(401).json({ msg: "Logged out token" });
    }

    try {
        const verified = jwt.verify(token, "secretkey");
        req.user = verified;
        next();
    } catch {
        res.status(400).json({ msg: "Invalid token" });
    }
}

module.exports = auth;