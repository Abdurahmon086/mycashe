// app/users/actions.js
"use server";

import { signJwt } from "@/lib/jwt";
import dbConnect from "@/lib/mongodb";
import User from "@/models/User";
import { IUserDB } from "@/types";
import bcrypt from "bcryptjs";
import { cookies } from "next/headers";

export async function createUser(data: IUserDB) {
  try {
    await dbConnect();

    const existing = await User.findOne({ email: data.email });
    if (existing) {
      return { status: 400, data: null, message: "Email already exists" };
    }

    const hashedPassword = await bcrypt.hash(data.password, 10);

    const user = await User.create({
      ...data,
      password: hashedPassword,
    });

    const token = signJwt({ userId: user._id, email: user.email });

    (await cookies()).set("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    });

    return { status: 200, data: { user, token }, message: "User created successfully" };
  } catch (error) {
    return { status: 500, data: null, message: "Error creating user" };
  }
}

export async function loginUser(email: string, password: string) {
  try {
    await dbConnect();
    const user = await User.findOne({ email });
    if (!user) {
      return { status: 401, data: null, message: "Invalid credentials" };
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return { status: 401, data: null, message: "Invalid credentials" };
    }

    const token = signJwt({ userId: user._id, email: user.email });
    
    (await cookies()).set("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    });

    return { status: 200, data: { user, token }, message: "Login successful" };
  } catch (error) {
    return { status: 500, data: null, message: "Error logging in" };
  }
}

export async function getUsers() {
  try {
    await dbConnect();
    const users = await User.find();
    return { status: 200, data: users, message: "Users fetched successfully" };
  } catch (error) {
    return { status: 500, data: null, message: "Error getting users" };
  }
}

export async function getUser(id: string) {
  try {
    await dbConnect();
    const user = await User.findById(id);
    return { status: 200, data: user, message: "User fetched successfully" };
  } catch (error) {
    return { status: 500, data: null, message: "Error getting user" };
  }
}
