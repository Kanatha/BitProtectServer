const bcrypt = require("bcrypt");
const express = require("express");
const { Client } = require("pg");

const app = express();

app.use(express.json());

const client = new Client({
  port: 5432,
  host: "127.0.0.1",
  database: "bitprotect",
  user: "admin",
  password: "admin",
});

client.connect().then(() => {
  console.log("connected to db");
});

const comparePassword = async (username, receivedPassword) => {
  try {
    // Query the database for the stored hashed password
    const query = "SELECT hashed_password FROM users WHERE username = $1";
    const res = await client.query(query, [username]);

    if (res.rows.length === 0) {
      console.log("User not found");
      return false;
    }

    // Extract the stored hashed password from the result
    const storedHash = res.rows[0].hashed_password;

    // Compare the received password with the stored hash
    const match = await bcrypt.compare(receivedPassword, storedHash);

    if (match) {
      console.log("Password is correct!");
      return true;
    } else {
      console.log("Incorrect password");
      return false;
    }
  } catch (error) {
    console.error("Error comparing password:", error);
    return false;
  }
};

async function storePassword(username, password) {
  try {
    // Hash the password before storing it
    const saltRounds = 10; // Number of rounds to generate the salt
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert the hashed password into the database
    const query =
      "INSERT INTO users (username, hashed_password) VALUES ($1, $2)";
    const values = [username, hashedPassword];

    await client.query(query, values);
    console.log("Password stored successfully!");
  } catch (error) {
    console.error("Error storing password:", error);
  }
}

async function getKeys(username) {
  const query =
    'SELECT k.key, k.iv, k.note FROM "keys" k JOIN "users" u ON k.user_id = u.id WHERE u.username = $1;';
  const res = await client.query(query, [username]);

  if (res.rows === 0) {
    return null;
  } else {
    return res.rows;
  }
}

async function getId(uuid) {
  const query = "SELECT id FROM users WHERE uuid = $1;";
  const res = await client.query(query, [uuid]);

  if (res.rows.length === 0) {
    console.log("break");
    return null;
  } else {
    return res.rows[0].id;
  }
}

async function insertKey(uuid, key, iv, note) {
  const userId = await getId(uuid);
  console.log("ID IS: " + userId);
  if (userId === null) {
    return false;
  } else {
    const query =
      'INSERT INTO "keys" (user_id, key, iv, note) VALUES ($1, $2, $3, $4);';
    client.query(query, [userId, key, iv, note]);
  }
}

async function getUuid(username) {
  const query = "SELECT uuid FROM users WHERE username = $1";
  const res = await client.query(query, [username]);

  if ((await res).rows.length === 0) {
    return null;
  } else {
    return res.rows[0].uuid;
  }
}

app.post("/auth", async (req, res) => {
  const dataRes = req.body;
  console.log(dataRes);

  if (
    Object.keys(dataRes).length === 2 &&
    dataRes.username &&
    dataRes.password
  ) {
    const match = await comparePassword(dataRes.username, dataRes.password);

    if (match === true) {
      const keys = await getKeys(dataRes.username);
      const username = dataRes.username;
      const uuid = await getUuid(username);
      console.log(keys);

      const formattedData = keys.map((key) => ({
        key: key.key,
        iv: key.iv,
        note: key.note,
      }));

      res.status(200).json({
        username,
        uuid,
        keys: formattedData,
      });
    } else {
      res.status(400).send("Bad Request");
    }
  } else {
    res.status(400).send("Bad Request");
  }
});

app.post("/getkeys", async (req, res) => {
  dataRes = req.body;
  if (Object.keys(dataRes).length === 1 && dataRes.username) {
    const keys = await getKeys(dataRes.username);
    const username = dataRes.username;
    const uuid = await getUuid(username);
    if (keys.length === 0) {
      res.status(400).send("Bad Request");
    } else {
      console.log(keys);

      console.log(keys);

      const formattedData = keys.map((key) => ({
        key: key.key,
        iv: key.iv,
        note: key.note,
      }));

      res.status(200).json({
        username,
        uuid,
        keys: formattedData,
      });
    }
  } else {
    res.status(400).send("Bad Request");
  }
});

app.post("/insertkey", async (req, res) => {
  const data = req.body;
  console.log(req.body);

  if (
    Object.keys(data).length === 4 &&
    data.uuid &&
    data.key &&
    data.iv &&
    data.note
  ) {
    insertKey(data.uuid, data.key, data.iv, data.note);
    res.status(200).send();
  } else {
    res.status(400).send("Bad Request");
  }
});

app.post("/createuser", async (req, res) => {
  const data = req.body;
  console.log(req.body);

  if (Object.keys(data).length === 2 && data.username && data.password) {
    await storePassword(data.username, data.password);
    res.status(200).send();
  } else {
    res.status(400).send("Bad Request");
  }
});

app.listen(3000, () => {
  console.log("server running at 3000");
});
