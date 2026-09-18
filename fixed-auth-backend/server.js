import "dotenv/config";

//Imports the Express.js framework, which provides routing, middleware management, and HTTP utility methods to build APIs and web applications.
import express from "express";

//Implements Cross-Origin Resource Sharing (CORS) middleware. It sets specific HTTP headers instructing browsers to permit external front-end applications (like a React app on a different port) to access this server's resources.
import cors from "cors";

//Middleware that parses the Cookie header on incoming HTTP requests and populates req.cookies with an object keyed by the cookie names, making it easier to read session IDs or auth tokens.
import cookieParser from "cookie-parser";

//A library for hashing passwords using the bcrypt algorithm. It automatically generates a "salt" (random data) and hashes the password multiple times to mitigate brute-force and rainbow-table attacks.
import bcrypt from "bcrypt";

//An implementation of JSON Web Tokens used for stateless authentication. It allows the server to cryptographically sign a payload (like a user ID) and verify it on subsequent requests without needing to query a session database.
import jwt from "jsonwebtoken";

//A collection of 15 smaller middleware functions that secure the Express app by setting various HTTP response headers (such as Content-Security-Policy and X-Frame-Options) to prevent vulnerabilities like Cross-Site Scripting (XSS) and clickjacking.
import helmet from "helmet";

//Middleware used to limit repeated requests to public APIs. It tracks IP addresses and blocks them temporarily if they exceed a set threshold, serving as a basic defense against Denial of Service (DoS) and brute-force attacks.
import rateLimit from "express-rate-limit";

import { PrismaClient } from "@prisma/client";

//A separate folder of instructions specifically for handling anything teachers can do in your app (like adding grades or updating classes). Imports an Express router instance from a local file containing the specific endpoint handlers (GET, POST, PUT, DELETE) related to teacher resources, keeping the codebase modular.
import teacherRouter from "./teacherRoutes.js";

//Imports an Express router instance from a local file containing the specific API endpoint handlers related to student resources.
import studentRouter from "./studentRoutes.js";

const prisma = new PrismaClient();

//express() function that gives you a server object. We store that object inside app. Now app can be used to configure your backend
const app = express();

//Allow requests from my configured frontend and allow credentials such as cookies.
// app.use() - Registers middleware. Middleware is code that runs during the request → response process.
app.use(cors({ origin: process.env.FRONTEND_ORIGIN, credentials: true }));

//Whenever a request comes with Content-Type: application/json, automatically parse it and store it in req.body as a JavaScript object
app.use(express.json());

//A cookie is small data stored by the browser and associated with a website. The browser can send that cookie back to your backend with requests.
//cookieParser() - It reads cookies from incoming requests and makes them easily available through req.cookies
app.use(cookieParser());
app.use(helmet());

// mount teacher routes (ESM import)
app.use(teacherRouter);
app.use("/api", studentRouter);

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);
// Login endpoints

app.post("/login", async (req, res) => {
  try {
    // console.log(req);
    const { email, password } = req.body;
    // find user in DB
    /*
      findUnique()
      findUnique() → strictly requires a unique field (e.g., id, email).
    */
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      /* 
        status(401) refers to the HTTP status code 401 Unauthorized.
        It means:
        The client (like your browser or frontend app) made a request to the server, but the server says “you are not authorized to access this resource.”
        Usually it happens when:
        No authentication credentials (like token, username/password) are provided.
        Credentials are missing or invalid (wrong password, expired token, etc.).
      */
      return res.status(401).json({ error: "Invalid email" });
    }

    // compare password
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid password" });
    }

    //generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      },
    );

    /*
      A cookie is a small piece of data that a server sends to the browser.
      The browser stores it and automatically sends it back with every request to the same server.
      Cookies are often used for authentication, sessions, and tracking.

      HttpOnly is a flag you can set on a cookie.
      When enabled:
      The cookie cannot be accessed using JavaScript (document.cookie).
      Only the browser → server HTTP requests can carry it.
      This protects against XSS (Cross-Site Scripting) attacks where malicious JavaScript might try to steal tokens.

      Why Store Token in Cookie After Login?
      You need to persist the login state so the user doesn’t have to re-login on every page refresh.

      Conclusion 
      We store the token in a HttpOnly cookie after login because it’s safer against XSS than localStorage and ensures the backend automatically receives the authentication proof with every request.
    */

    // Store token in cookie
    res.cookie("token", token, {
      httpOnly: true, // prevents JavaScript from accessing cookie
      secure: false, // true in production with HTTPS
      sameSite: "strict",
    });

    res.json({ message: "Login Succesful!" }); // send JSON Response
  } catch (error) {
    console.error(error);
    /* 
      status(500) means your server is returning HTTP status code 500, which stands for Internal Server Error.
      Meaning:
      It indicates something went wrong on the server side, not the client side.
      The server couldn’t complete the request due to an unexpected error (e.g., crash, unhandled exception, database failure, etc.).
      Think of 500 as: “The client made a valid request, but the server failed to handle it properly.”
    */
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// logout and listen
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout Successfully." });
});

app.listen(4000, () => {
  console.log("Server running on http://localhost:4000");
});
