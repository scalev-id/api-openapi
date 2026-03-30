import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parse } from "yaml";

const rootDir = path.resolve(import.meta.dirname, "..");
const yamlPath = path.join(rootDir, "specs/v3/openapi.yaml");
const distDir = path.join(rootDir, "dist");
const distSpecDir = path.join(distDir, "specs/v3");
const distYamlPath = path.join(distSpecDir, "openapi.yaml");
const distJsonPath = path.join(distSpecDir, "openapi.json");
const noJekyllPath = path.join(distDir, ".nojekyll");

const yamlSource = fs.readFileSync(yamlPath, "utf8");
const spec = parse(yamlSource);

fs.rmSync(distDir, { recursive: true, force: true });
fs.mkdirSync(distSpecDir, { recursive: true });

fs.copyFileSync(yamlPath, distYamlPath);
fs.writeFileSync(distJsonPath, `${JSON.stringify(spec, null, 2)}\n`);
fs.writeFileSync(noJekyllPath, "");

execFileSync(
  "npx",
  [
    "redocly",
    "build-docs",
    "specs/v3/openapi.yaml",
    "--output",
    "dist/index.html",
  ],
  {
    cwd: rootDir,
    stdio: "inherit",
  },
);
