import bcrypt from "bcrypt";
import prisma from "../lib/prisma.js";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
  const { username, email, password } = req.body;

  try {
    //encrypt passowrd
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    //create new user and save to database
    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });
    console.log(newUser);
    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "failed to create user" });
  }
};
export const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    //check if user exist
    const user = await prisma.user.findUnique({
      where: { username },
    });
    if (!user) return res.status(401).json({ message: "invalid credentials!" });
    //if password correct

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(401).json({ message: "invalid credentials!" });

    //generate cookie toker and send to the user

    // res.setHeader("Set-Cookie", "test=" + "myValue").json("success!");
    const age = 1000 * 60 * 60 * 24 * 7;
    const token = jwt.sign(
      {
        id: user.id,
      },
      process.env.JWT_SECRET_KEY,
      { expiresIn: age }
    );

    res
      .cookie("token", token, {
        httpOnly: true,
        // secure: true,
        maxAge: age,
      })
      .status(200)
      .json({ message: "Login successful!" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "failed to login!" });
  }
};

export const logout = (req, res) => {
  res
    .clearCookie("token")
    .status(200)
    .json({ message: "logout successfully!" });
};
