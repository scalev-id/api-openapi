import fs from "node:fs";
import path from "node:path";
import { parseDocument } from "yaml";
import {
  getNexusDir,
  loadAliasLookup,
  loadRouteManifest,
  sortRoutes
} from "./nexus-auth-routes.mjs";

const rootDir = path.resolve(import.meta.dirname, "..");
const specPath = path.join(rootDir, "specs/v2/openapi.yaml");

function loadSpecOperations() {
  const document = parseDocument(fs.readFileSync(specPath, "utf8"));
  const paths = document.get("paths");
  const operations = new Set();
  const documentedAliasPaths = new Set();
  const { aliasPaths } = loadAliasLookup(getNexusDir());

  for (const item of paths.items) {
    const routePath = String(item.key);
    const routeDefinition = item.value;

    if (aliasPaths.has(routePath)) {
      documentedAliasPaths.add(routePath);
    }

    for (const opItem of routeDefinition.items) {
      operations.add(`${String(opItem.key).toUpperCase()} ${routePath}`);
    }
  }

  return { operations, documentedAliasPaths };
}

const routeManifest = loadRouteManifest(getNexusDir());
const { operations, documentedAliasPaths } = loadSpecOperations();
const routeManifestSet = new Set(routeManifest.map((route) => `${route.method} ${route.path}`));
const missingRoutes = sortRoutes(
  routeManifest.filter((route) => !operations.has(`${route.method} ${route.path}`))
);

const unexpectedDocMethods = [...operations]
  .filter((entry) => entry.includes(" /v2"))
  .filter((entry) => !routeManifestSet.has(entry));

console.log(`canonical_authenticated_route_methods ${routeManifest.length}`);
console.log(`missing_route_methods ${missingRoutes.length}`);
console.log(`documented_alias_paths ${documentedAliasPaths.size}`);
console.log(`unexpected_documented_methods ${unexpectedDocMethods.length}`);

if (missingRoutes.length > 0) {
  console.log("\nMissing route methods:");
  for (const route of missingRoutes) {
    console.log(`${route.method} ${route.path} -> ${route.controllerModule}.${route.action}`);
  }
}

if (documentedAliasPaths.size > 0) {
  console.log("\nDocumented alias paths:");
  for (const aliasPath of [...documentedAliasPaths].sort()) {
    console.log(aliasPath);
  }
}

if (unexpectedDocMethods.length > 0) {
  console.log("\nUnexpected documented route methods:");
  for (const entry of unexpectedDocMethods.sort()) {
    console.log(entry);
  }
}

if (
  missingRoutes.length > 0 ||
  documentedAliasPaths.size > 0 ||
  unexpectedDocMethods.length > 0
) {
  process.exitCode = 1;
}
