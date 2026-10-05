import { NextRequest, NextResponse } from "next/server";
import { jwtVerify } from "jose";
import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";

const ADMIN_COOKIE = "efix_admin";
const PARTNER_COOKIE = "efix_partner";
const DEV_PARTNER_AUTH_SECRET =
  "efix-local-development-partner-secret-20260527";

function authSecret(secret: string | undefined, devSecret?: string): string | undefined {
  if (!secret && devSecret && process.env.NODE_ENV !== "production") {
    return devSecret;
  }
  return secret;
}

async function isValidJwt(
  token: string | undefined,
  secret: string | undefined,
  validate?: (payload: Record<string, unknown>) => boolean,
): Promise<boolean> {
  if (!token || !secret || secret.length < 32) return false;
  try {
    const { payload } = await jwtVerify(
      token,
      new TextEncoder().encode(secret),
      { algorithms: ["HS256"] },
    );
    if (validate && !validate(payload as Record<string, unknown>)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * 一般向けストアの一時非公開スイッチ。true の間、CLOSED_STOREFRONT_PATHS は「準備中」(503)を返す。
 * 卸(/partner, /wholesale)・請求書払い(/pay)・管理画面・webhook・購入済み顧客向け
 * (/account, /orders/cancel, /success)・特商法等の表記ページは対象外。
 * 再公開するときは false に戻してデプロイする。
 */
const IS_STOREFRONT_CLOSED = true;
const CLOSED_STOREFRONT_PATHS = ["/", "/order", "/coverage", "/sign-up", "/api/checkout"];

const STOREFRONT_CLOSED_HTML = `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>ただいま準備中です | E-FIX</title>
<style>
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #fff; color: #1f2937; font-family: -apple-system, BlinkMacSystemFont, "Hiragino Sans", "Noto Sans JP", sans-serif; }
  main { padding: 16px; text-align: center; }
  h1 { margin: 0 0 16px; font-size: 22px; font-weight: 600; }
  p { margin: 0 0 40px; font-size: 15px; line-height: 1.9; color: #6b7280; }
  a { font-size: 13px; color: #2563eb; text-decoration: none; }
</style>
</head>
<body>
<main>
  <h1>ただいま準備中です</h1>
  <p>現在、当サイトは一時的に公開を停止しています。<br>再開までしばらくお待ちください。</p>
  <a href="/partner/login">販売店の方はこちら</a>
</main>
</body>
</html>`;

function storefrontClosedResponse(request: NextRequest): NextResponse | null {
  if (!IS_STOREFRONT_CLOSED) return null;
  const { pathname } = request.nextUrl;
  const isClosedPath = CLOSED_STOREFRONT_PATHS.some(
    (closedPath) =>
      pathname === closedPath ||
      (closedPath !== "/" && pathname.startsWith(`${closedPath}/`)),
  );
  if (!isClosedPath) return null;

  const headers = { "Retry-After": "86400", "Cache-Control": "no-store" };
  if (pathname.startsWith("/api/")) {
    return NextResponse.json(
      { error: "ただいま準備中です" },
      { status: 503, headers },
    );
  }
  return new NextResponse(STOREFRONT_CLOSED_HTML, {
    status: 503,
    headers: { ...headers, "Content-Type": "text/html; charset=utf-8" },
  });
}

const isClerkAccountRoute = createRouteMatcher(["/account(.*)", "/api/account(.*)"]);

/**
 * 既存の admin/partner Cookie(JWT)認証ロジック。1文字も挙動を変えていない。
 * Clerk 導入前は `middleware` としてそのままエクスポートされていた関数の中身。
 * admin/partner/distributor 以外の pathname では常に NextResponse.next() を返す
 * (=何もしない)ので、Clerk 側の処理を妨げない。
 */
async function legacyAdminPartnerRouting(
  request: NextRequest,
): Promise<NextResponse> {
  const { pathname } = request.nextUrl;

  // Legacy distributor URLs are consolidated into the partner area.
  if (pathname === "/distributor" || pathname === "/distributor/login") {
    const url = request.nextUrl.clone();
    url.pathname = pathname.endsWith("/login") ? "/partner/login" : "/partner";
    return NextResponse.redirect(url);
  }

  const isAdminLoginApi =
    pathname === "/api/admin/login" ||
    (process.env.NODE_ENV !== "production" &&
      pathname === "/api/admin/dev-login");

  if (pathname.startsWith("/admin/login") || isAdminLoginApi) {
    return NextResponse.next();
  }
  if (pathname.startsWith("/admin") || pathname.startsWith("/api/admin")) {
    const token = request.cookies.get(ADMIN_COOKIE)?.value;
    if (await isValidJwt(token, process.env.ADMIN_AUTH_SECRET)) {
      return NextResponse.next();
    }
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const url = request.nextUrl.clone();
    url.pathname = "/admin/login";
    url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }

  if (
    pathname.startsWith("/partner/login") ||
    pathname === "/api/partner/login"
  ) {
    return NextResponse.next();
  }
  if (pathname.startsWith("/partner") || pathname.startsWith("/api/partner")) {
    const token = request.cookies.get(PARTNER_COOKIE)?.value;
    const valid = await isValidJwt(
      token,
      authSecret(process.env.PARTNER_AUTH_SECRET, DEV_PARTNER_AUTH_SECRET),
      (p) =>
        typeof p.partnerId === "string" &&
        (p.tier === "wholesale" || p.tier === "distributor"),
    );
    if (valid) return NextResponse.next();

    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const url = request.nextUrl.clone();
    url.pathname = "/partner/login";
    url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

/**
 * Clerk (顧客向け認証) と既存の admin/partner Cookie 認証を同一 middleware で共存させる。
 * clerkMiddleware のハンドラ内で legacyAdminPartnerRouting をそのまま呼び出すことで、
 * admin/partner/distributor の挙動を完全に維持しつつ、Clerk のセッション処理を全ルートに適用する。
 * /account 配下のみ auth.protect() でログイン必須にする(他のルートは全て公開のまま)。
 */
export default clerkMiddleware(async (auth, request) => {
  const closedResponse = storefrontClosedResponse(request);
  if (closedResponse) return closedResponse;

  if (isClerkAccountRoute(request)) {
    await auth.protect();
  }
  return legacyAdminPartnerRouting(request);
});

export const config = {
  matcher: [
    // Clerk 公式推奨マッチャー: 静的ファイル(拡張子付きURL)と _next を除く全ルートで実行。
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    "/(api|trpc)(.*)",
  ],
};
