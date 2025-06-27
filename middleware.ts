import { verifyJwt } from "@/lib/jwt";
import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // /auth sahifalariga middleware ishlamasin
  if (pathname.startsWith("/auth")) {
    return NextResponse.next();
  }

  const token = request.cookies.get("token")?.value;

  const payload = verifyJwt(token || "");

  if (!payload) {
    const loginUrl = new URL("/auth/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!auth).*)"],
};
