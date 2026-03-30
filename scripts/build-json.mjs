import fs from "node:fs";
import path from "node:path";
import { parse } from "yaml";

const rootDir = path.resolve(import.meta.dirname, "..");
const yamlPath = path.join(rootDir, "specs/v3/openapi.yaml");
const jsonPath = path.join(rootDir, "specs/v3/openapi.json");

const yamlSource = fs.readFileSync(yamlPath, "utf8");
const spec = parse(yamlSource);

fs.writeFileSync(jsonPath, `${JSON.stringify(spec, null, 2)}\n`);
