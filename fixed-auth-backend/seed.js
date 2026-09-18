// This loads secret settings (like database passwords or API keys) from a hidden file (usually named .env) into code. It keeps sensitive information secure and out of plain sight.
import "dotenv/config";

// This brings in the blueprint/class for a tool called Prisma. Think of Prisma as a friendly translator that makes it easy for JavaScript code to talk to your database.
import { PrismaClient } from "@prisma/client";

//This brings in a specific security function called hash. It is used to scramble user passwords into completely unreadable text before saving them.
import { hash } from "bcrypt";

//This actually activates the database translator imported in the second line. It creates a ready-to-use db connection and saves it in the prisma variable, so I can use it to fetch or save data in the rest of your file. new PrismaClient() is Actual object created from that blueprint
const prisma = new PrismaClient();

//This specific block of code is typically used to "seed" a database, meaning it automatically ensures a default admin account exists when the application starts.
// The async keyword defines an asynchronous function. It allows to use the await keyword inside, which tells JavaScript to pause and wait for time-consuming tasks (like saving to a database) to finish before moving to the next line.
async function main() {
  // This is how Node.js accesses the secret values loaded by dotenv. process.env holds environment variables, allowing to use the email and password without hardcoding them directly into the script.
  const email = process.env.ADMIN_EMAIL;
  const plainPassword = process.env.ADMIN_PASSWORD;

  // This uses the security tool to scramble the password. The 10 represents the "salt rounds," instructing the algorithm to process the data 10 times, making the hash highly resistant to cracking attempts.
  const passwordHash = hash(plainPassword, 10);
  // upsert is a powerful database command that combines "update" and "insert". It checks the database for the where condition (the email). If the user already exists, it applies the update block (which is empty {} here, so it does nothing). If the user does not exist, it uses the create block to make the new account.
  const user = await prisma.user.upsert({
    where: { email },
    update: {}, // do nothing if exists
    create: {
      email,
      passwordHash,
    },
  });

  console.log("User Created/Exists", user);
}

//This is the trigger. It actually starts the asynchronous function
main()
  //The safety net. Because main() is an async function, it operates using something called a "Promise". If anything goes wrong inside main() (like a network issue or missing environment variable), the code stops what it's doing and jumps straight into this block.
  .catch((err) => {
    //Prints the exact error details to your terminal
    console.error(err);
    //Forcefully stops Node.js application. The 1 is an exit code that tells the server's operating system, "I am shutting down because an error occurred" (a 0 would mean a normal, successful shutdown).
    process.exit(1);
  })

  //This block is guaranteed to run no matter what happens—whether main() succeeds perfectly or fails and triggers the .catch block.
  .finally(async () => {
    //Politely closes the connection to database, freeing up memory and network resources.
    await prisma.$disconnect();
  });
