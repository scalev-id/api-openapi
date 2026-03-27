import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const DEFAULT_NEXUS_DIR = "/Users/aarroisi/Projects/nexus";

const PUBLIC_ROUTE_PATTERNS = [
  /^\/v2\/public\//,
  /^\/v2\/email-tracking\//,
  /^\/v2\/.*\/public\//,
  /^\/v2\/test$/,
  /^\/v2\/test-error$/,
  /^\/v2\/oauth\/application$/,
  /^\/v2\/oauth\/token$/,
  /^\/v2\/oauth\/revoke$/,
  /^\/v2\/oauth\/introspect$/,
  /^\/v2\/orders\/public/,
  /^\/v2\/order\/public/,
  /^\/v2\/orders\/search-courier-service$/,
  /^\/v2\/orders\/search-warehouse$/,
  /^\/v2\/order\/search-courier-service$/,
  /^\/v2\/order\/search-warehouse$/,
  /^\/v2\/customers\/token\//,
  /^\/v2\/customers\/forget-password$/,
  /^\/v2\/customers\/save-password$/,
  /^\/v2\/customers\/auth\/otp\//,
  /^\/v2\/customers\/jwt\//,
  /^\/v2\/auth\/register$/,
  /^\/v2\/auth\/reset-password$/,
  /^\/v2\/auth\/save-password$/,
  /^\/v2\/auth\/activation$/,
  /^\/v2\/auth\/finish-creation$/,
  /^\/v2\/auth\/jwt\/refresh$/,
  /^\/v2\/auth\/jwt\/blacklist$/,
  /^\/v2\/auth\/otp\//,
  /^\/v2\/auth\/exchange$/,
  /^\/v2\/users\/log[-_]in$/,
  /^\/v2\/business\/enabled-epayments$/,
  /^\/v2\/businesses\/enabled-payments\/public$/,
  /^\/v2\/business(?:es)?\/transactions\/(?!download$)[^/]+$/,
  /^\/v2\/business(?:es)?\/by-origin\/?$/,
  /^\/v2\/business(?:es)?\/public-files$/,
  /^\/v2\/fb-event/,
  /^\/v2\/tiktok-event$/,
  /^\/v2\/kwai-event$/,
  /^\/v2\/update-fb-custom-audience$/,
  /^\/v2\/pages\/public/,
  /^\/v2\/pages\/public-v2\//,
  /^\/v2\/pages\/products\/public-v2\//,
  /^\/v2\/pages\/bundle-price-options\/public-v2\//,
  /^\/v2\/pages\/checkout\/public-v2\//,
  /^\/v2\/page\/public/,
  /^\/v2\/page\/public-v2\//,
  /^\/v2\/page\/product\/public-v2\//,
  /^\/v2\/page\/bundle-price-option\/public-v2\//,
  /^\/v2\/page\/checkout\/public-v2\//,
  /^\/v2\/custom-domains\/lookup\/?$/,
  /^\/v2\/custom-domain-lookup\/?$/,
  /^\/v2\/affiliate-codes\//,
  /^\/v2\/affiliate-variables$/,
  /^\/v2\/aff-code\//,
  /^\/v2\/aff-variables$/,
  /^\/v2\/locations\/public/,
  /^\/v2\/location(?:\/|$)/,
  /^\/v2\/discount-codes\/check$/,
  /^\/v2\/check-discount-code$/
];

const IGNORED_ROUTE_METHODS = new Set();

// Runtime still exposes this older plural-root path, but router history shows the
// newer canonical name is `/businesses/all-payment-methods`.
const MANUAL_ALIAS_PAIRS = [
  {
    oldVerb: "GET",
    oldPath: "/v2/businesses/all-epayment-methods",
    newVerb: "GET",
    newPath: "/v2/businesses/all-payment-methods"
  }
];

const TAG_RULES = [
  { pattern: /^\/v2\/ads\//, tag: "Ads" },
  { pattern: /^\/v2\/affiliated-businesses/, tag: "Affiliated Businesses" },
  { pattern: /^\/v2\/affiliate-transactions/, tag: "Affiliate Transactions" },
  { pattern: /^\/v2\/auth\//, tag: "User Account" },
  { pattern: /^\/v2\/birdsend-integrations/, tag: "Birdsend Integrations" },
  { pattern: /^\/v2\/bundles/, tag: "Bundles" },
  { pattern: /^\/v2\/business-subscriptions/, tag: "Business Subscriptions" },
  { pattern: /^\/v2\/business-users/, tag: "Business Users" },
  { pattern: /^\/v2\/businesses\/api-keys/, tag: "Business API Keys" },
  { pattern: /^\/v2\/businesses\/applications/, tag: "OAuth Applications" },
  { pattern: /^\/v2\/businesses\/authorized-applications/, tag: "Authorized Applications" },
  { pattern: /^\/v2\/businesses\/current\/verification-payment/, tag: "Verification Payments" },
  { pattern: /^\/v2\/businesses\/oauth/, tag: "OAuth Billing" },
  { pattern: /^\/v2\/businesses\/ses-credits/, tag: "SES Credits" },
  { pattern: /^\/v2\/businesses\/chatbot-credits/, tag: "Chatbot Credits" },
  { pattern: /^\/v2\/businesses\/volts/, tag: "Volts" },
  { pattern: /^\/v2\/businesses\/fb/, tag: "Meta" },
  { pattern: /^\/v2\/businesses\/waba/, tag: "WhatsApp" },
  { pattern: /^\/v2\/businesses/, tag: "Businesses" },
  { pattern: /^\/v2\/channels/, tag: "Channels" },
  { pattern: /^\/v2\/chatbot\//, tag: "Chatbot" },
  { pattern: /^\/v2\/chatbot-credits/, tag: "Chatbot Credits" },
  { pattern: /^\/v2\/couriers/, tag: "Couriers" },
  { pattern: /^\/v2\/courier-aggregators/, tag: "Courier Aggregators" },
  { pattern: /^\/v2\/course-contents/, tag: "Course Contents" },
  { pattern: /^\/v2\/course-sections/, tag: "Course Sections" },
  { pattern: /^\/v2\/catalog\//, tag: "Customers" },
  { pattern: /^\/v2\/custom-domains/, tag: "Custom Domains" },
  { pattern: /^\/v2\/customers\/me/, tag: "Customers" },
  { pattern: /^\/v2\/customers/, tag: "Customers" },
  { pattern: /^\/v2\/discount-codes/, tag: "Discount Codes" },
  { pattern: /^\/v2\/entitlements/, tag: "Entitlements" },
  { pattern: /^\/v2\/(?:fb|kwai|tiktok)-(?:pixels|standard-events)/, tag: "GTM" },
  { pattern: /^\/v2\/financial-entities/, tag: "Financial Entities" },
  { pattern: /^\/v2\/gtm/, tag: "GTM" },
  { pattern: /^\/v2\/inventories/, tag: "Inventory" },
  { pattern: /^\/v2\/inventory/, tag: "Inventory" },
  { pattern: /^\/v2\/item-labels/, tag: "Item Labels" },
  { pattern: /^\/v2\/licenses/, tag: "Licenses" },
  { pattern: /^\/v2\/locations/, tag: "Locations" },
  { pattern: /^\/v2\/mailketing-integrations/, tag: "Mailketing Integrations" },
  { pattern: /^\/v2\/monthly-invoices/, tag: "Monthly Invoices" },
  { pattern: /^\/v2\/moota-integrations/, tag: "Moota Integrations" },
  { pattern: /^\/v2\/my-reseller-sales/, tag: "Reseller Sales" },
  { pattern: /^\/v2\/notifications/, tag: "Notifications" },
  { pattern: /^\/v2\/oauth\/billing/, tag: "OAuth Billing" },
  { pattern: /^\/v2\/oauth\/authorize/, tag: "OAuth Applications" },
  { pattern: /^\/v2\/order/, tag: "Orders" },
  { pattern: /^\/v2\/orders/, tag: "Orders" },
  { pattern: /^\/v2\/pages/, tag: "Pages" },
  { pattern: /^\/v2\/(?:my-affiliate-orders|my-partners|my-partnerships|partnership-marketplace|partnerships)/, tag: "Partnerships" },
  { pattern: /^\/v2\/partnership-requests/, tag: "Partnership Requests" },
  { pattern: /^\/v2\/payment-accounts/, tag: "Payment Accounts" },
  { pattern: /^\/v2\/payout-channels/, tag: "Payout Channels" },
  { pattern: /^\/v2\/pg-accounts/, tag: "Payment Gateway Accounts" },
  { pattern: /^\/v2\/products/, tag: "Products" },
  { pattern: /^\/v2\/promos/, tag: "Promotions" },
  { pattern: /^\/v2\/role-permission-templates/, tag: "Roles" },
  { pattern: /^\/v2\/roles/, tag: "Roles" },
  { pattern: /^\/v2\/ses\/credits/, tag: "SES Credits" },
  { pattern: /^\/v2\/ses\//, tag: "Email Broadcasts" },
  { pattern: /^\/v2\/shipments\//, tag: "Shipments" },
  { pattern: /^\/v2\/shipping-costs/, tag: "Shipping" },
  { pattern: /^\/v2\/stores/, tag: "Stores" },
  { pattern: /^\/v2\/subscription-(?:items|orders)/, tag: "Subscriptions" },
  { pattern: /^\/v2\/team-members/, tag: "Team Members" },
  { pattern: /^\/v2\/users\/me/, tag: "User Account" },
  { pattern: /^\/v2\/variants/, tag: "Variants" },
  { pattern: /^\/v2\/volts/, tag: "Volts" },
  { pattern: /^\/v2\/wakaka/, tag: "Wakaka" },
  { pattern: /^\/v2\/warehouse-partners/, tag: "Warehouse Partners" },
  { pattern: /^\/v2\/warehouses/, tag: "Warehouses" },
  { pattern: /^\/v2\/whatsapp-integrations/, tag: "WhatsApp" }
];

function readFile(filepath) {
  return fs.readFileSync(filepath, "utf8");
}

export function getNexusDir() {
  return process.env.NEXUS_DIR || DEFAULT_NEXUS_DIR;
}

export function normalizeRoutePath(routePath) {
  return routePath.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, "{$1}");
}

export function pathToSegments(routePath) {
  return routePath.split("/").filter(Boolean);
}

export function humanizeToken(token) {
  return token
    .replace(/[{}]/g, "")
    .replace(/-/g, " ")
    .replace(/_/g, " ")
    .trim();
}

export function titleize(text) {
  const WORD_OVERRIDES = {
    api: "API",
    bm: "BM",
    birdsend: "Birdsend",
    discourse: "Discourse",
    fb: "Facebook",
    fcm: "FCM",
    gtm: "GTM",
    id: "ID",
    ipaymu: "iPaymu",
    kyc: "KYC",
    kwai: "Kwai",
    mailketing: "Mailketing",
    mfa: "MFA",
    moota: "Moota",
    oauth: "OAuth",
    otp: "OTP",
    pg: "PG",
    productlift: "Productlift",
    qr: "QR",
    readme: "ReadMe",
    ses: "SES",
    sso: "SSO",
    tenant: "Tenant",
    tiktok: "TikTok",
    totp: "TOTP",
    uuid: "UUID",
    wakaka: "Wakaka",
    waba: "WABA",
    whatsapp: "WhatsApp",
    xendit: "Xendit",
    xp: "XP"
  };

  return text
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => {
      const normalized = word.toLowerCase();
      return WORD_OVERRIDES[normalized] || word.charAt(0).toUpperCase() + word.slice(1);
    })
    .join(" ");
}

export function inferTag(routePath) {
  const match = TAG_RULES.find((rule) => rule.pattern.test(routePath));
  return match ? match.tag : "Authenticated API";
}

export function isPublicRoute(routePath) {
  if (routePath === "/v2/catalog/{custom_domain}/cart/merge") {
    return false;
  }

  if (routePath.startsWith("/v2/webhooks/")) {
    return true;
  }

  if (routePath.startsWith("/v2/catalog/")) {
    return true;
  }

  return PUBLIC_ROUTE_PATTERNS.some((pattern) => pattern.test(routePath));
}

export function loadAliasPairs(nexusDir = getNexusDir()) {
  const aliasPath = path.join(nexusDir, "docs", "v2_endpoint_aliases.md");
  const lines = readFile(aliasPath).split("\n");
  const aliasPairs = [];

  for (const line of lines) {
    const match = line.match(
      /^-\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/\S+)\s+->\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/\S+)/
    );

    if (!match) {
      continue;
    }

    const [, oldVerb, oldPath, newVerb, newPath] = match;

    aliasPairs.push({
      oldVerb,
      oldPath: `/v2${normalizeRoutePath(oldPath)}`,
      newVerb,
      newPath: `/v2${normalizeRoutePath(newPath)}`
    });
  }

  return [...aliasPairs, ...MANUAL_ALIAS_PAIRS];
}

export function loadAliasLookup(nexusDir = getNexusDir()) {
  const aliasPairs = loadAliasPairs(nexusDir);
  const aliasMethods = new Set();
  const aliasPaths = new Set();

  for (const pair of aliasPairs) {
    aliasMethods.add(`${pair.oldVerb} ${pair.oldPath}`);
    aliasPaths.add(pair.oldPath);
  }

  return { aliasPairs, aliasMethods, aliasPaths };
}

export function listControllerModules(nexusDir = getNexusDir()) {
  const controllerDir = path.join(nexusDir, "lib", "scalev_api_web", "controllers");
  const moduleMap = new Map();
  const stack = [controllerDir];

  while (stack.length > 0) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });

    for (const entry of entries) {
      const absolutePath = path.join(current, entry.name);

      if (entry.isDirectory()) {
        stack.push(absolutePath);
        continue;
      }

      if (!entry.isFile() || !entry.name.endsWith(".ex")) {
        continue;
      }

      const source = readFile(absolutePath);
      const match = source.match(/defmodule\s+([A-Za-z0-9_.]+)\s+do/);

      if (match) {
        moduleMap.set(match[1], { filepath: absolutePath, source });
      }
    }
  }

  return moduleMap;
}

function parseActionList(actionSource) {
  return Array.from(actionSource.matchAll(/:([A-Za-z0-9_!?]+)/g)).map((match) => match[1]);
}

export function loadControllerAuthMap(nexusDir = getNexusDir()) {
  const moduleMap = listControllerModules(nexusDir);
  const authMap = new Map();

  for (const [moduleName, moduleInfo] of moduleMap.entries()) {
    const actionMap = new Map();
    const source = moduleInfo.source;
    const regex =
      /plug\s+Authorize,\s*(:allow|"[^"]+")\s*when\s+action\s+in\s*(\[[\s\S]*?\])/gm;

    let match;
    while ((match = regex.exec(source))) {
      const rawScope = match[1];
      const actions = parseActionList(match[2]);
      const scope = rawScope === ":allow" ? ":allow" : rawScope.slice(1, -1);

      for (const action of actions) {
        const existing = actionMap.get(action);

        if (!existing) {
          actionMap.set(action, scope);
          continue;
        }

        if (existing === ":allow" && scope !== ":allow") {
          actionMap.set(action, scope);
        }
      }
    }

    authMap.set(moduleName, {
      ...moduleInfo,
      actionScopes: actionMap
    });
  }

  return authMap;
}

function extractFunctionBody(source, action) {
  const regex = new RegExp(
    String.raw`^[ \t]{2}def(?:p)?\s+${action}\s*\([\s\S]*?(?=^[ \t]{2}def(?:p)?\s+(?!${action}\b)[A-Za-z0-9_!?]+|\nend\s*$)`,
    "gm"
  );
  const matches = [...source.matchAll(regex)].map((match) => match[0]);
  return matches.join("\n");
}

export function loadRouteManifest(nexusDir = getNexusDir()) {
  const output = execFileSync("mix", ["phx.routes"], {
    cwd: nexusDir,
    encoding: "utf8",
    env: process.env
  });

  const { aliasMethods } = loadAliasLookup(nexusDir);
  const controllerAuthMap = loadControllerAuthMap(nexusDir);
  const routes = [];

  for (const line of output.split("\n")) {
    const match = line.match(
      /^\s*(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/v2\S+)\s+([A-Za-z0-9_.]+)\s+:([A-Za-z0-9_!?]+)\s*$/
    );

    if (!match) {
      continue;
    }

    const [, method, rawPath, controllerModule, action] = match;
    const openApiPath = normalizeRoutePath(rawPath);

    if (
      aliasMethods.has(`${method} ${openApiPath}`) ||
      isPublicRoute(openApiPath) ||
      IGNORED_ROUTE_METHODS.has(`${method} ${openApiPath}`)
    ) {
      continue;
    }

    const controllerInfo = controllerAuthMap.get(controllerModule);
    const source = controllerInfo?.source || "";
    const actionBody = extractFunctionBody(source, action);
    const scope = controllerInfo?.actionScopes.get(action) || null;

    routes.push({
      method,
      path: openApiPath,
      controllerModule,
      controllerName: controllerModule.split(".").at(-1),
      action,
      operationId: `${controllerModule}.${action}`,
      scope,
      actionBody
    });
  }

  return routes;
}

export function classifyRouteKind(route) {
  if (route.path.startsWith("/v2/catalog/")) {
    return "customer";
  }

  if (route.path.startsWith("/v2/customers/me/")) {
    return "customer";
  }

  if (route.path === "/v2/customers/me") {
    return "customer";
  }

  if (route.path.startsWith("/v2/oauth/billing/")) {
    return "oauth_only";
  }

  if (route.path.startsWith("/v2/users/me/") || route.path === "/v2/users/me") {
    return "user";
  }

  if (route.path === "/v2/auth/token" || route.path === "/v2/auth/sso/discourse") {
    return "user";
  }

  if (route.path.startsWith("/v2/auth/jwt/")) {
    return "user";
  }

  return "business";
}

export function inferSuccessStatus(route) {
  if (/send_resp\(\s*conn,\s*:no_content/i.test(route.actionBody)) {
    return 204;
  }

  if (/put_status\(\s*:created\s*\)/i.test(route.actionBody)) {
    return 201;
  }

  return 200;
}

export function inferResponseKind(route) {
  if (/\/download(?:\/|$)/.test(route.path) || /download/.test(route.action)) {
    return "binary";
  }

  if (/render\(\s*conn,\s*:raw_data\b/.test(route.actionBody)) {
    return "value";
  }

  if (
    /\/count$/.test(route.path) ||
    /\/(?:order-)?statistics(?:\/|$)/.test(route.path) ||
    route.action === "show_count" ||
    route.action === "show_applications_count" ||
    route.action === "list_business_affiliated_count" ||
    route.action === "count"
  ) {
    return "object";
  }

  if (
    route.action === "delete" ||
    inferSuccessStatus(route) === 204 ||
    /render\(\s*conn,\s*:blank_200\s*\)|render\(\s*:blank_200\s*\)/.test(route.actionBody)
  ) {
    return "blank";
  }

  if (route.method === "GET" && (route.action.startsWith("show") || route.action === "me")) {
    return "object";
  }

  if (route.method === "GET" && route.action.startsWith("get_")) {
    if (/\{[^}]+\}$/.test(route.path)) {
      return "object";
    }

    const literalSegments = pathToSegments(route.path)
      .slice(1)
      .filter((segment) => !segment.startsWith("{"));
    const lastLiteral = literalSegments.at(-1) || "";
    const looksPlural =
      lastLiteral.length > 0 &&
      singularizeWord(lastLiteral) !== lastLiteral &&
      !lastLiteral.endsWith("ss");

    return looksPlural ? "list" : "object";
  }

  if (
    route.method === "GET" &&
    (route.action.startsWith("index") ||
      route.action.startsWith("list") ||
      (/\/count$/.test(route.path) === false &&
        !/\{[^}]+\}$/.test(route.path) &&
        !/\/(count|download|metrics|summary-table|chart|top-performance|actions)$/.test(
          route.path
        )))
  ) {
    return "list";
  }

  return "object";
}

function singularizeWord(word) {
  const SINGULAR_WORD_OVERRIDES = {
    businesses: "business",
    licenses: "license"
  };

  if (SINGULAR_WORD_OVERRIDES[word]) {
    return SINGULAR_WORD_OVERRIDES[word];
  }

  if (word === "warehouses") {
    return "warehouse";
  }

  if (/(us|is)$/.test(word)) {
    return word;
  }

  if (word.endsWith("ies")) {
    return `${word.slice(0, -3)}y`;
  }

  if (word.endsWith("ses")) {
    return word.slice(0, -2);
  }

  if (word.endsWith("s") && !word.endsWith("ss")) {
    return word.slice(0, -1);
  }

  return word;
}

const RESOURCE_NAME_OVERRIDES = {
  "ad-account-top-ups": "ad account top ups",
  adaccounts: "ad accounts",
  adcreatives: "ad creatives",
  adsets: "ad sets",
  "all-epayment-methods": "all e-payment methods",
  "all-payment-methods": "all payment methods",
  authorize: "authorization request",
  "api-keys": "API keys",
  "authorized-applications": "authorized applications",
  "balance-history": "balance history",
  "blocked-ips": "blocked IPs",
  bpo: "bundle price option",
  bu: "business user",
  cbm: "child business manager",
  "child-bm": "child business manager",
  customaudiences: "custom audiences",
  "fcm-subscription": "FCM subscription",
  fcm: "FCM subscription",
  fb: "Facebook",
  gtm: "GTM",
  "machine-api-logs": "machine API logs",
  mfa: "MFA",
  "oauth-billing": "OAuth billing",
  "page-displays": "displays",
  "pg-accounts": "payment gateway accounts",
  "qr-code": "QR code",
  "request-response-logs": "request-response logs",
  "required-kyc-docs": "required KYC documents",
  "synced-adaccounts": "synced ad accounts",
  totp: "TOTP",
  waba: "WhatsApp business account"
};

function humanizeResourceToken(token) {
  return RESOURCE_NAME_OVERRIDES[token] || humanizeToken(token);
}

function buildResourcePhrase(route) {
  const segments = pathToSegments(route.path).slice(1);
  const normalizedSegments = segments.map((segment, index) => {
    if (
      !segment.startsWith("{") &&
      typeof segments[index + 1] === "string" &&
      segments[index + 1].startsWith("{")
    ) {
      return singularizeWord(segment);
    }

    return segment;
  });
  const literalSegments = normalizedSegments.filter((segment) => !segment.startsWith("{"));

  if (literalSegments.length === 0) {
    return "resource";
  }

  let usable = [...literalSegments];
  const terminalActions = new Set([
    "complete",
    "count",
    "course",
    "dataset",
    "delete",
    "download",
    "rotate",
    "sync",
    "sync-metrics",
    "preview-items",
    "check-settlement",
    "check-action",
    "cancel",
    "resume",
    "disable",
    "enable",
    "duplicate",
    "manage-link",
    "refresh-access-token",
    "regenerate-secret",
    "release",
    "approve",
    "ban",
    "deny",
    "initiate",
    "leave",
    "login",
    "preview",
    "purchase",
    "qr-code",
    "regenerate",
    "register",
    "register-phone",
    "reject",
    "retry-apply-spend-cap",
    "send-messages",
    "switch-business-role",
    "switch-to-xp-managed",
    "switch-to-xp-owned",
    "top-performance",
    "unban",
    "upload-logo",
    "upload-avatar",
    "upload-media",
    "update-metadata",
    "confirm-email",
    "close",
    "check-status",
    "finalize",
    "generate"
  ]);

  while (usable.length > 1 && terminalActions.has(usable.at(-1))) {
    usable = usable.slice(0, -1);
  }

  let lastRetainedLiteralIndex = -1;
  if (usable.length > 0) {
    let retainedLiteralCount = 0;
    for (const [index, segment] of segments.entries()) {
      if (segment.startsWith("{")) {
        continue;
      }

      retainedLiteralCount += 1;
      if (retainedLiteralCount === usable.length) {
        lastRetainedLiteralIndex = index;
        break;
      }
    }
  }

  const hasTrailingIdentifierContext =
    lastRetainedLiteralIndex >= 0 &&
    segments.slice(lastRetainedLiteralIndex + 1).some((segment) => segment.startsWith("{"));

  if (usable[0] === "businesses" && usable[1] === "current") {
    usable = ["current-business", ...usable.slice(2)];
  } else if (usable[0] === "business-users" && usable[1] === "me") {
    usable = ["current-business-user", ...usable.slice(2)];
  } else if (usable[0] === "businesses") {
    usable = ["business", ...usable.slice(1)];
  } else if (usable[0] === "users" && usable[1] === "me") {
    usable = ["current-user", ...usable.slice(2)];
  } else if (usable[0] === "customers" && usable[1] === "me") {
    usable = ["current-customer", ...usable.slice(2)];
  }

  if ((/\{[^}]+\}$/.test(route.path) || hasTrailingIdentifierContext) && usable.length > 0) {
    usable[usable.length - 1] = singularizeWord(usable.at(-1));
  }

  if (route.method === "POST" && usable.length > 0) {
    usable[usable.length - 1] = singularizeWord(usable.at(-1));
  }

  return usable
    .map(humanizeResourceToken)
    .join(" ")
    .replace(/\b([A-Za-z]+)\s+\1\b/gi, "$1");
}

function buildActionPhrase(route) {
  const segments = pathToSegments(route.path).slice(1);
  const lastLiteral = [...segments].reverse().find((segment) => !segment.startsWith("{"));
  return lastLiteral ? humanizeToken(lastLiteral) : humanizeToken(route.action);
}

export function inferSummary(route) {
  const resource = buildResourcePhrase(route);
  const titledResource = titleize(resource);
  const actionPhrase = buildActionPhrase(route);
  const literalSegments = pathToSegments(route.path)
    .slice(1)
    .filter((segment) => !segment.startsWith("{"));
  const lastLiteral = literalSegments.at(-1) || "";
  const looksPlural =
    lastLiteral.length > 0 &&
    singularizeWord(lastLiteral) !== lastLiteral &&
    !lastLiteral.endsWith("ss");
  const actionVerbRules = [
    ["create", "Create"],
    ["insert", "Create"],
    ["register", "Register"],
    ["approve", "Approve"],
    ["save_", "Save"],
    ["submit", "Submit"],
    ["resend", "Resend"],
    ["send", "Send"],
    ["upload", "Upload"],
    ["sync", "Sync"],
    ["duplicate", "Duplicate"],
    ["refresh", "Refresh"],
    ["finalize", "Finalize"],
    ["rotate", "Rotate"],
    ["generate", "Generate"],
    ["trigger", "Trigger"],
    ["check", "Check"],
    ["login", "Login"],
    ["merge", "Merge"],
    ["complete", "Complete"],
    ["disable", "Disable"],
    ["initiate", "Initiate"],
    ["cancel", "Cancel"],
    ["resume", "Resume"],
    ["reactivate", "Reactivate"],
    ["revoke", "Revoke"],
    ["preview", "Preview"],
    ["release", "Release"],
    ["switch", "Switch"],
    ["confirm", "Confirm"]
  ];

  if (route.method === "GET") {
    if (/\/count$/.test(route.path) || route.action.startsWith("count")) {
      return `Count ${titledResource}`;
    }

    if (/\/download(?:\/|$)/.test(route.path) || route.action.includes("download")) {
      return `Download ${titledResource}`;
    }

    if (route.action.startsWith("show") || route.action === "me" || /\{[^}]+\}$/.test(route.path)) {
      return `Get ${titledResource}`;
    }

    if (route.action.startsWith("index") || route.action.startsWith("list")) {
      return `List ${titledResource}`;
    }

    if (route.action.startsWith("get_")) {
      return looksPlural ? `List ${titledResource}` : `Get ${titledResource}`;
    }

    return looksPlural ? `List ${titledResource}` : `Get ${titledResource}`;
  }

  if (route.method === "POST") {
    if (route.action === "update" || route.action.startsWith("update_")) {
      return `Update ${titledResource}`;
    }

    for (const [prefix, verb] of actionVerbRules) {
      if (route.action.startsWith(prefix)) {
        return `${verb} ${titledResource}`;
      }
    }

    return `${titleize(actionPhrase)} ${titledResource}`.replace(/\s+/g, " ").trim();
  }

  if (route.method === "PATCH" || route.method === "PUT") {
    if (route.action === "update" || route.action.startsWith("update_")) {
      return `Update ${titledResource}`;
    }

    return `${titleize(actionPhrase)} ${titledResource}`.replace(/\s+/g, " ").trim();
  }

  if (route.method === "DELETE") {
    return `Delete ${titledResource}`;
  }

  return `${titleize(humanizeToken(route.action))} ${titledResource}`.replace(/\s+/g, " ").trim();
}

export function inferDescription(route) {
  const actor = supportsCustomerUserOAuth(route)
    ? "authenticated customer or LMS user"
    : classifyRouteKind(route) === "customer"
      ? "authenticated customer"
      : classifyRouteKind(route) === "oauth_only"
        ? "authenticated OAuth application"
      : classifyRouteKind(route) === "user"
        ? "authenticated user"
        : "authenticated business";

  const summary = inferSummary(route);

  if (route.method === "GET") {
    if (summary.startsWith("List ")) {
      return `Returns ${naturalizePhrase(summary.slice(5), "the")} for the ${actor}.`;
    }

    if (summary.startsWith("Get ")) {
      return `Returns ${naturalizePhrase(summary.slice(4), "the")} for the ${actor}.`;
    }

    if (summary.startsWith("Count ")) {
      return `Returns a count of ${naturalizePhrase(summary.slice(6))} for the ${actor}.`;
    }

    if (summary.startsWith("Download ")) {
      return `Downloads ${naturalizePhrase(summary.slice(9))} for the ${actor}.`;
    }

    return `${summary} for the ${actor}.`;
  }

  for (const [prefix, verb, article] of [
    ["Create ", "Creates", "a"],
    ["Update ", "Updates", "the"],
    ["Delete ", "Deletes", "the"],
    ["Cancel ", "Cancels", "the"],
    ["Resume ", "Resumes", "the"],
    ["Approve ", "Approves", "the"],
    ["Send ", "Sends", null],
    ["Upload ", "Uploads", null],
    ["Sync ", "Synchronizes", null],
    ["Refresh ", "Refreshes", null],
    ["Finalize ", "Finalizes", null],
    ["Complete ", "Completes", null],
    ["Disable ", "Disables", null],
    ["Enable ", "Enables", null],
    ["Register ", "Registers", null],
    ["Switch ", "Switches", "the"],
    ["Confirm ", "Confirms", "the"],
    ["Preview ", "Previews", null],
    ["Merge ", "Merges", null],
    ["Mark ", "Marks", "the"],
    ["Check ", "Checks", "the"],
    ["Release ", "Releases", "the"],
    ["Set ", "Sets", "the"],
    ["Resend ", "Resends", null],
    ["Calculate ", "Calculates", null]
  ]) {
    if (summary.startsWith(prefix)) {
      return `${verb} ${naturalizePhrase(summary.slice(prefix.length), article)} for the ${actor}.`;
    }
  }

  return `${summary} for the ${actor}.`;
}

function naturalizePhrase(text, article = null) {
  const wordOverrides = {
    api: "API",
    discourse: "Discourse",
    facebook: "Facebook",
    fcm: "FCM",
    gtm: "GTM",
    id: "ID",
    ipaymu: "iPaymu",
    mfa: "MFA",
    oauth: "OAuth",
    qr: "QR",
    readme: "ReadMe",
    ses: "SES",
    sso: "SSO",
    tiktok: "TikTok",
    totp: "TOTP",
    uuid: "UUID",
    waba: "WABA",
    whatsapp: "WhatsApp",
    xendit: "Xendit",
    xp: "XP"
  };

  const normalized = text
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => {
      const prefix = word.match(/^[^A-Za-z0-9]*/)?.[0] || "";
      const suffix = word.match(/[^A-Za-z0-9]*$/)?.[0] || "";
      const core = word.slice(prefix.length, word.length - suffix.length);

      if (!core) {
        return word;
      }

      const override = wordOverrides[core.toLowerCase()];
      return `${prefix}${override || core.toLowerCase()}${suffix}`;
    })
    .join(" ");

  if (!article || /^(a|an|the)\b/i.test(normalized)) {
    return normalized;
  }

  if (article === "a") {
    return `${/^[aeiou]/i.test(normalized) ? "an" : "a"} ${normalized}`;
  }

  return `${article} ${normalized}`;
}

export function inferSecurity(route) {
  const kind = classifyRouteKind(route);
  const hasOAuthScope = Boolean(route.scope && route.scope !== ":allow");
  const oauthRequirement = hasOAuthScope ? { oauth2: [route.scope] } : { oauth2: [] };

  if (kind === "oauth_only") {
    return [oauthRequirement];
  }

  if (kind === "customer" || kind === "user") {
    return [{ bearerApiKey: [] }];
  }

  if (hasOAuthScope) {
    return [{ bearerApiKey: [] }, oauthRequirement];
  }

  return [{ bearerApiKey: [] }];
}

function supportsCustomerUserOAuth(route) {
  if (route.method !== "GET") {
    return false;
  }

  return [
    /^\/v2\/customers\/me$/,
    /^\/v2\/customers\/me\/orders$/,
    /^\/v2\/customers\/me\/order-statistics$/,
    /^\/v2\/customers\/me\/variants$/,
    /^\/v2\/customers\/me\/variants\/\{uuid\}\/course$/,
    /^\/v2\/customers\/me\/course-sections\/\{uuid\}$/,
    /^\/v2\/customers\/me\/course-contents\/\{uuid\}$/
  ].some((pattern) => pattern.test(route.path));
}

export function inferConsumes(route) {
  if (!["POST", "PATCH", "PUT"].includes(route.method)) {
    return null;
  }

  if (
    /upload|avatar|logo|files/.test(route.path) ||
    /upload|avatar|logo/.test(route.action)
  ) {
    return "multipart/form-data";
  }

  return "application/json";
}

export function buildPathParameters(routePath) {
  const segments = pathToSegments(routePath);
  const integerParameterNames = new Set([
    "affiliate_transaction_id",
    "billing_tag_id",
    "birdsend_integration_id",
    "bu_id",
    "bundle_id",
    "business_customer_id",
    "email_broadcast_id",
    "item_id",
    "mailketing_integration_id",
    "notification_id",
    "product_id",
    "store_id",
    "team_member_id",
    "variant_id",
    "warehouse_id"
  ]);
  const stringParameterNames = new Set([
    "account_id",
    "ad_id",
    "adset_id",
    "campaign_id",
    "chat_id",
    "custom_domain",
    "device_id",
    "pg_reference_id",
    "request_id",
    "secret",
    "type",
    "unique_id",
    "wa_user_id",
    "waba_unique_id",
    "wamid"
  ]);
  const uuidPathPatterns = [
    /^\/v2\/subscription-items\/\{id\}(?:\/|$)/,
    /^\/v2\/subscriptions\/\{id\}(?:\/|$)/,
    /^\/v2\/customers\/me\/subscription-items\/\{id\}(?:\/|$)/,
    /^\/v2\/customers\/me\/subscriptions\/\{id\}(?:\/|$)/,
    /^\/v2\/businesses\/oauth-billing\/(?:charges|reservations|settlements)\/\{id\}(?:\/|$)/
  ];

  return Array.from(routePath.matchAll(/\{([^}]+)\}/g)).map((match) => {
    const name = match[1];
    const segmentIndex = segments.findIndex((segment) => segment === `{${name}}`);
    const previousLiteral = [...segments.slice(0, segmentIndex)].reverse().find((segment) => {
      return !segment.startsWith("{");
    });
    const inferredResource = previousLiteral
      ? humanizeResourceToken(singularizeWord(previousLiteral))
      : humanizeResourceToken(name.replace(/_id$|_uuid$|_slug$/g, ""));
    const cleanedResource = inferredResource
      .replace(/^my\s+/, "")
      .replace(/^current\s+/, "")
      .trim();
    let description = `${titleize(humanizeToken(name))} path parameter`;

    if (name === "id") {
      description = `ID of the ${cleanedResource}`;
    } else if (name === "bu_id") {
      description = "ID of the business user";
    } else if (name === "custom_domain") {
      description = "Storefront custom domain or hostname used to resolve the catalog.";
    } else if (name === "waba_unique_id") {
      description = "Unique ID of the WhatsApp Business Account";
    } else if (name === "wa_user_id") {
      description = "WhatsApp user ID";
    } else if (name === "wamid") {
      description = "WhatsApp message ID";
    } else if (name === "uuid") {
      description = `UUID of the ${cleanedResource}`;
    } else if (name === "unique_id") {
      description = `Unique ID of the ${cleanedResource}`;
    } else if (name === "type" && routePath.startsWith("/v2/orders/download/")) {
      description = "Order export type";
    } else if (name === "secret" && routePath.startsWith("/v2/partnership-marketplace/")) {
      description = "Marketplace secret for the partnership offer";
    } else if (name === "page_id" && routePath.startsWith("/v2/businesses/fb/pages/")) {
      description = "Facebook page ID";
    } else if (name.endsWith("_id")) {
      description = `ID of the ${humanizeResourceToken(name.slice(0, -3))}`;
    } else if (name.endsWith("_uuid")) {
      description = `UUID of the ${humanizeResourceToken(name.slice(0, -5))}`;
    } else if (name.endsWith("_slug")) {
      description = `Slug of the ${humanizeResourceToken(name.slice(0, -5))}`;
    }

    const schema =
      name === "uuid" ||
      name.endsWith("_uuid") ||
      uuidPathPatterns.some((pattern) => pattern.test(routePath))
        ? {
            type: "string",
            format: "uuid"
          }
        : name === "page_id" && routePath.startsWith("/v2/businesses/fb/pages/")
          ? {
              type: "string"
            }
        : !stringParameterNames.has(name) &&
            (integerParameterNames.has(name) || name === "id" || name.endsWith("_id"))
          ? {
              type: "integer"
            }
          : {
              type: "string"
            };

    return {
      name,
      in: "path",
      required: true,
      description,
      schema
    };
  });
}

export function responseMayBeForbidden(route) {
  return classifyRouteKind(route) === "business" || classifyRouteKind(route) === "oauth_only";
}

export function responseMayBeNotFound(route) {
  return (
    /\{[^}]+\}/.test(route.path) ||
    ["DELETE", "PATCH", "PUT"].includes(route.method) ||
    /:not_found\b/.test(route.actionBody)
  );
}

export function sortRoutes(routes) {
  return [...routes].sort((left, right) => {
    const pathCompare = left.path.localeCompare(right.path);
    if (pathCompare !== 0) {
      return pathCompare;
    }

    const order = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    return order.indexOf(left.method) - order.indexOf(right.method);
  });
}
