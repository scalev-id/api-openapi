import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parse, stringify } from "yaml";
import {
  buildPathParameters,
  classifyRouteKind,
  getNexusDir,
  inferConsumes,
  inferDescription,
  inferResponseKind,
  inferSecurity,
  inferSuccessStatus,
  inferSummary,
  inferTag,
  isPublicRoute,
  listControllerModules,
  loadAliasLookup,
  loadRouteManifest,
  responseMayBeForbidden,
  responseMayBeNotFound,
  sortRoutes,
  titleize
} from "./nexus-auth-routes.mjs";

const rootDir = path.resolve(import.meta.dirname, "..");
const specPath = path.join(rootDir, "specs/v2/openapi.yaml");
const nexusDir = getNexusDir();
const controllerModuleMap = listControllerModules(nexusDir);
const GENERATED_DESCRIPTION_RE =
  /This endpoint (returns data|performs the requested action) for the authenticated/;

function ensureObject(parent, key) {
  if (!parent[key] || typeof parent[key] !== "object" || Array.isArray(parent[key])) {
    parent[key] = {};
  }

  return parent[key];
}

function stableValue(value) {
  if (Array.isArray(value)) {
    return value.map(stableValue);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, nestedValue]) => nestedValue !== undefined)
        .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey))
        .map(([nestedKey, nestedValue]) => [nestedKey, stableValue(nestedValue)])
    );
  }

  return value;
}

function loadHeadSpec() {
  try {
    const contents = execFileSync("git", ["show", "HEAD:specs/v2/openapi.yaml"], {
      cwd: rootDir,
      encoding: "utf8",
      env: process.env,
      maxBuffer: 50 * 1024 * 1024
    });
    return parse(contents);
  } catch {
    return null;
  }
}

function restoreCorruptedSelfRefSchemas(spec) {
  const headSpec = loadHeadSpec();
  const headSchemas = headSpec?.components?.schemas;
  const schemas = spec.components?.schemas;

  if (!headSchemas || !schemas) {
    return;
  }

  for (const [schemaName, schema] of Object.entries(schemas)) {
    if (schema?.$ref !== `#/components/schemas/${schemaName}`) {
      continue;
    }

    const headSchema = headSchemas[schemaName];
    if (!headSchema || headSchema.$ref === `#/components/schemas/${schemaName}`) {
      continue;
    }

    schemas[schemaName] = headSchema;
  }
}

function canonicalize(value) {
  return JSON.stringify(stableValue(value));
}

function canonicalizeOmittingKeys(value, omittedKeys) {
  const omit = new Set(omittedKeys);

  const walk = (current) => {
    if (Array.isArray(current)) {
      return current.map(walk);
    }

    if (current && typeof current === "object") {
      return Object.fromEntries(
        Object.entries(current)
          .filter(([key, nestedValue]) => nestedValue !== undefined && !omit.has(key))
          .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey))
          .map(([key, nestedValue]) => [key, walk(nestedValue)])
      );
    }

    return current;
  };

  return JSON.stringify(walk(value));
}

function setSchema(schemas, name, schema) {
  schemas[name] = schema;
}

function setResponseComponent(responses, name, description, schemaRef) {
  responses[name] = {
    description,
    content: {
      "application/json": {
        schema: { $ref: schemaRef }
      }
    }
  };
}

function buildSchemaRefRequestBody(schemaRef, description, required = false, contentType = "application/json") {
  return {
    required,
    description,
    content: {
      [contentType]: {
        schema: {
          $ref: schemaRef
        }
      }
    }
  };
}

function extractSchemaComponentName(schemaRef) {
  return schemaRef?.match(/^#\/components\/schemas\/(.+)$/)?.[1] || null;
}

function componentize(text) {
  return String(text || "")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((word) => titleize(word))
    .join("");
}

function uniqueComponentName(existingNames, baseName) {
  let candidate = baseName;
  let index = 2;

  while (existingNames.has(candidate)) {
    candidate = `${baseName}${index}`;
    index += 1;
  }

  existingNames.add(candidate);
  return candidate;
}

function toPascalCase(text) {
  return text
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}

function extractPathParamNames(routePath) {
  return Array.from(routePath.matchAll(/\{([^}]+)\}/g)).map((match) => match[1]);
}

function buildInferredRequestSchemaName(route) {
  const operationKey = route.operationId.split(".").slice(-2).join(" ");
  return `Inferred${toPascalCase(operationKey)}Request`;
}

function countDelimiterDelta(text) {
  let delta = 0;

  for (const char of text) {
    if (["(", "{", "["].includes(char)) {
      delta += 1;
    } else if ([")", "}", "]"].includes(char)) {
      delta -= 1;
    }
  }

  return delta;
}

function extractFunctionHeaders(actionBody) {
  const headers = [];
  const lines = actionBody.split("\n");
  let currentHeader = null;
  let delimiterDepth = 0;

  for (const line of lines) {
    if (currentHeader === null) {
      if (/^[ \t]{2}def(?:p)?\s+[A-Za-z0-9_!?]+\s*\(/.test(line)) {
        currentHeader = line;
        delimiterDepth = countDelimiterDelta(line);

        if (delimiterDepth <= 0 && /\bdo\s*$/.test(line.trim())) {
          headers.push(currentHeader);
          currentHeader = null;
        }
      }

      continue;
    }

    currentHeader = `${currentHeader}\n${line}`;
    delimiterDepth += countDelimiterDelta(line);

    if (delimiterDepth <= 0 && /\bdo\s*$/.test(line.trim())) {
      headers.push(currentHeader);
      currentHeader = null;
    }
  }

  return headers;
}

function inferRequestFieldSchema(route, fieldName, contentType) {
  const normalized = fieldName.toLowerCase();

  if (
    contentType === "multipart/form-data" &&
    (normalized === "file" || /(file|avatar|logo|image|document|audio|video|media)$/.test(normalized))
  ) {
    return {
      type: "string",
      format: "binary"
    };
  }

  if (
    normalized.startsWith("is_") ||
    normalized.startsWith("has_") ||
    normalized.endsWith("_enabled") ||
    normalized.endsWith("_active") ||
    normalized.endsWith("_verified")
  ) {
    return { type: "boolean" };
  }

  if (/_ids$/.test(normalized)) {
    return {
      type: "array",
      items: {
        oneOf: [{ type: "integer" }, { type: "string" }]
      }
    };
  }

  if (/_id$/.test(normalized) || normalized === "template_id") {
    return {
      oneOf: [{ type: "integer" }, { type: "string" }]
    };
  }

  if (/(quantity|page|page_size|limit|offset|count)$/.test(normalized)) {
    return { type: "integer" };
  }

  if (/(amount|price|subtotal|total|progress|percentage|rate)$/.test(normalized)) {
    return { type: "number" };
  }

  if (normalized.endsWith("_at")) {
    return {
      type: "string",
      format: "date-time"
    };
  }

  if (
    /(params|metadata|payload|context|values|components|filters|attrs|settings|options|data)$/.test(
      normalized
    )
  ) {
    return {
      type: "object",
      additionalProperties: { $ref: "#/components/schemas/GenericValue" }
    };
  }

  return { $ref: "#/components/schemas/GenericValue" };
}

function shouldAllowAdditionalRequestProperties(route, propertyNames, contentType) {
  if (contentType === "multipart/form-data" || propertyNames.size === 0) {
    return true;
  }

  if (
    [
      /^\/v2\/ads\/custom-metrics$/,
      /^\/v2\/ads\/views(?:\/|$)/,
      /^\/v2\/businesses\/fb(?:\/|$)/,
      /^\/v2\/businesses\/waba(?:\/|$)/,
      /^\/v2\/businesses\/payout$/,
      /^\/v2\/businesses\/xp-payout$/,
      /^\/v2\/businesses\/xp-upload-file$/,
      /^\/v2\/chatbot-credits(?:\/|$)/,
      /^\/v2\/chatbot\/analyze-conversation$/,
      /^\/v2\/customers\/upload$/,
      /^\/v2\/inventories\/flow$/,
      /^\/v2\/partnership-marketplace\/\{secret\}\/request$/,
      /^\/v2\/partnership-requests\/\{id\}\//,
      /^\/v2\/products\/\{product_id\}\/partnership\/check-changes$/,
      /^\/v2\/variants\/\{variant_id\}\/digital-product-files$/,
      /^\/v2\/variants\/\{variant_id\}\/course-section-orders$/,
      /^\/v2\/course-sections\/\{section_uuid\}\/course-content-orders$/,
      /^\/v2\/volts\/preview$/
    ].some((pattern) => pattern.test(route.path))
  ) {
    return true;
  }

  return [...propertyNames].some((name) =>
    /(?:^|_)(metadata|payload|context|params|settings|options|values|attrs|data)$/.test(
      name.toLowerCase()
    )
  );
}

function inferRequestSchema(route, contentType) {
  const pathParamNames = new Set(extractPathParamNames(route.path));
  const propertyNames = new Set();
  const headerKeySets = [];

  for (const header of extractFunctionHeaders(route.actionBody)) {
    const headerKeys = Array.from(header.matchAll(/"([A-Za-z0-9_]+)"\s*=>/g))
      .map((keyMatch) => keyMatch[1])
      .filter((name) => !pathParamNames.has(name));

    if (headerKeys.length > 0) {
      headerKeySets.push(new Set(headerKeys));
    }

    for (const name of headerKeys) {
      propertyNames.add(name);
    }
  }

  for (const regex of [/params\[\s*"([^"]+)"\s*\]/g, /Map\.get\(\s*params\s*,\s*"([^"]+)"/g]) {
    for (const match of route.actionBody.matchAll(regex)) {
      const name = match[1];
      if (!pathParamNames.has(name)) {
        propertyNames.add(name);
      }
    }
  }

  const required =
    headerKeySets.length === 0
      ? []
      : [...headerKeySets[0]].filter((name) =>
          headerKeySets.every((keySet) => keySet.has(name))
        );

  const properties = Object.fromEntries(
    [...propertyNames]
      .sort((left, right) => left.localeCompare(right))
      .map((fieldName) => [fieldName, inferRequestFieldSchema(route, fieldName, contentType)])
  );
  const allowAdditionalProperties = shouldAllowAdditionalRequestProperties(
    route,
    propertyNames,
    contentType
  );

  return {
    type: "object",
    additionalProperties: allowAdditionalProperties
      ? { $ref: "#/components/schemas/GenericValue" }
      : false,
    ...(required.length > 0 ? { required } : {}),
    ...(Object.keys(properties).length > 0 ? { properties } : {})
  };
}

function ensureInferredRequestSchema(spec, route, contentType, schema = inferRequestSchema(route, contentType)) {
  const schemas = ensureObject(ensureObject(spec, "components"), "schemas");
  const schemaName = buildInferredRequestSchemaName(route);

  setSchema(schemas, schemaName, schema);

  return {
    schemaRef: `#/components/schemas/${schemaName}`,
    required: Array.isArray(schema.required) && schema.required.length > 0
  };
}

function extractFunctionClausesFromSource(source, functionName) {
  const regex = new RegExp(
    String.raw`^[ \t]{2}def(?:p)?\s+${functionName}\s*\([\s\S]*?(?=^[ \t]{2}def(?:p)?\s+|\nend\s*$)`,
    "gm"
  );
  return Array.from(source.matchAll(regex)).map((match) => match[0]);
}

function pickBestFunctionClause(clauses) {
  return (
    clauses.find((clause) => /BaseJSON\.|Jason\.OrderedObject\.new/.test(clause)) ||
    clauses.find((clause) => /\[\s*[\s\S]*?:/.test(clause) || /%\{\s*[\s\S]*?=>/.test(clause)) ||
    clauses[0] ||
    ""
  );
}

function extractAliasMap(source) {
  const aliasMap = new Map();

  for (const match of source.matchAll(/^[ \t]*alias\s+([A-Za-z0-9_.{},\s]+?)(?:,\s*as:\s*([A-Za-z0-9_]+))?\s*$/gm)) {
    const [, rawAliasExpression, explicitAlias] = match;
    const aliasExpression = rawAliasExpression.trim();

    if (aliasExpression.includes("{")) {
      const groupedMatch = aliasExpression.match(/^([A-Za-z0-9_.]+)\.\{(.+)\}$/);
      if (!groupedMatch) {
        continue;
      }

      const [, prefix, entries] = groupedMatch;
      for (const entry of entries.split(",").map((item) => item.trim()).filter(Boolean)) {
        const fullModule = `${prefix}.${entry}`;
        aliasMap.set(entry, fullModule);
      }
      continue;
    }

    const fullModule = aliasExpression;
    const aliasName = explicitAlias || fullModule.split(".").at(-1);
    aliasMap.set(aliasName, fullModule);
  }

  return aliasMap;
}

function resolveModuleReference(source, moduleRef, controllerModule) {
  if (!moduleRef) {
    return null;
  }

  if (moduleRef.startsWith("ScalevApi")) {
    return moduleRef;
  }

  const aliasMap = extractAliasMap(source);

  if (!moduleRef.includes(".")) {
    if (aliasMap.has(moduleRef)) {
      return aliasMap.get(moduleRef);
    }

    const controllerNamespace = controllerModule.split(".").slice(0, -1).join(".");
    return `${controllerNamespace}.${moduleRef}`;
  }

  const [rootAlias, ...rest] = moduleRef.split(".");
  if (aliasMap.has(rootAlias)) {
    return [aliasMap.get(rootAlias), ...rest].join(".");
  }

  return moduleRef;
}

function extractHelperCallNames(actionBody) {
  const helperNames = new Set();

  for (const match of actionBody.matchAll(/\b([a-z][A-Za-z0-9_!?]*)\(\s*conn\b/g)) {
    const helperName = match[1];
    if (!["render", "put_view", "put_status", "send_resp"].includes(helperName)) {
      helperNames.add(helperName);
    }
  }

  return [...helperNames];
}

function findRenderContext(actionBody, controllerSource, controllerModule, visitedHelpers = new Set()) {
  const matches = new Set();

  for (const regex of [/render\(\s*conn\s*,\s*:([A-Za-z0-9_!?]+)/g, /\|>\s*render\(\s*:([A-Za-z0-9_!?]+)/g]) {
    for (const match of actionBody.matchAll(regex)) {
      matches.add(match[1]);
    }
  }

  const explicitViewModule = actionBody.match(/put_view\(\s*([A-Za-z0-9_.]+)\s*\)/)?.[1] || null;
  const viewModule = resolveModuleReference(
    controllerSource,
    explicitViewModule,
    controllerModule
  );
  const candidates = [...matches].filter((name) => name !== "blank_200");

  if (candidates.length > 0) {
    return {
      renderName: candidates.length === 1 ? candidates[0] : candidates[0],
      viewModule
    };
  }

  const jsonMatch = actionBody.match(/json\(\s*conn\s*,\s*([A-Za-z0-9_.]+)\.([A-Za-z0-9_!?]+)\(/);
  if (jsonMatch) {
    return {
      renderName: jsonMatch[2],
      viewModule: resolveModuleReference(controllerSource, jsonMatch[1], controllerModule)
    };
  }

  for (const helperName of extractHelperCallNames(actionBody)) {
    if (visitedHelpers.has(helperName)) {
      continue;
    }

    visitedHelpers.add(helperName);
    const helperClause = pickBestFunctionClause(
      extractFunctionClausesFromSource(controllerSource, helperName)
    );

    if (!helperClause) {
      continue;
    }

    const nestedContext = findRenderContext(
      helperClause,
      controllerSource,
      controllerModule,
      visitedHelpers
    );
    if (nestedContext.renderName || nestedContext.viewModule) {
      return {
        renderName: nestedContext.renderName,
        viewModule: viewModule || nestedContext.viewModule || null
      };
    }
  }

  return { renderName: null, viewModule };
}

function extractRenderName(actionBody, controllerSource = "", controllerModule = "") {
  return findRenderContext(actionBody, controllerSource, controllerModule).renderName;
}

function inferViewModule(route) {
  const controllerSource = controllerModuleMap.get(route.controllerModule)?.source || "";
  const context = findRenderContext(route.actionBody, controllerSource, route.controllerModule);

  if (context.viewModule) {
    return context.viewModule;
  }

  return route.controllerModule.replace(/Controller$/, "JSON");
}

function extractAssignedExpression(body, variableName) {
  const regex = new RegExp(
    String.raw`\b${variableName}\s*=\s*([\s\S]*?)(?=^\s*[A-Za-z_][A-Za-z0-9_]*\s*=|^\s*[A-Z][A-Za-z0-9_.]*\(|^\s*BaseJSON\.|^\s*conn\b|\n\s*end\s*$)`,
    "m"
  );
  return body.match(regex)?.[1]?.trim() || null;
}

function extractLiteralBody(expression, openChar, closeChar) {
  const startIndex = expression.indexOf(openChar);
  if (startIndex === -1) {
    return null;
  }

  let depth = 0;
  for (let index = startIndex; index < expression.length; index += 1) {
    const char = expression[index];
    if (char === openChar) {
      depth += 1;
    } else if (char === closeChar) {
      depth -= 1;
      if (depth === 0) {
        return expression.slice(startIndex + 1, index);
      }
    }
  }

  return null;
}

function extractLiteralPairs(expression) {
  const orderedObjectBody = extractLiteralBody(expression, "[", "]");
  if (orderedObjectBody !== null) {
    return orderedObjectBody
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => line.replace(/,$/, ""))
      .map((line) => {
        const match = line.match(/^(?:"([^"]+)"|([A-Za-z0-9_!?]+))\s*(?:=>|:)\s*(.+)$/);
        if (!match) {
          return null;
        }

        return {
          key: match[1] || match[2],
          expression: match[3].trim()
        };
      })
      .filter(Boolean);
  }

  const mapBody = extractLiteralBody(expression, "{", "}");
  if (mapBody !== null) {
    return mapBody
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => line.replace(/,$/, ""))
      .map((line) => {
        const match = line.match(/^(?:"([^"]+)"|([A-Za-z0-9_!?]+))\s*(?:=>|:)\s*(.+)$/);
        if (!match) {
          return null;
        }

        return {
          key: match[1] || match[2],
          expression: match[3].trim()
        };
      })
      .filter(Boolean);
  }

  return null;
}

function inferResponseIdSchema(fieldName, expression, contextName) {
  const normalized = fieldName.toLowerCase();
  const stringIdFields = new Set([
    "client_id",
    "request_id",
    "secret",
    "reference_id",
    "unique_id",
    "waba_unique_id",
    "wa_user_id",
    "wamid"
  ]);

  if (stringIdFields.has(normalized) || normalized.endsWith("_uuid")) {
    return normalized.endsWith("_uuid")
      ? { type: "string", format: "uuid" }
      : { type: "string" };
  }

  if (
    /oauth_billing|machine_api_log/i.test(contextName) ||
    /UUIDv7|Ecto\.UUID|request_id/.test(expression)
  ) {
    return { type: "string" };
  }

  return { oneOf: [{ type: "integer" }, { type: "string" }] };
}

function inferResponseFieldSchema(viewSource, fieldName, expression, contextName, visited = new Set()) {
  const normalized = fieldName.toLowerCase();
  const nestedHelperMatch =
    expression.match(/\|\>\s*([A-Za-z0-9_!?]+)\(\)\s*$/) ||
    expression.match(/\b([A-Za-z0-9_!?]+)\([^)]*\)\s*$/);

  if (nestedHelperMatch) {
    const schema = inferResponseHelperSchema(viewSource, nestedHelperMatch[1], visited);
    if (schema) {
      return schema;
    }
  }

  const arrayHelperMatch =
    expression.match(/Enum\.map\([^,]+,\s*&([A-Za-z0-9_!?]+)\/1\)/) ||
    expression.match(/\|>\s*Enum\.map\(&([A-Za-z0-9_!?]+)\/1\)/) ||
    expression.match(/Enum\.map\([^,]+,\s*fn\s+[A-Za-z_][A-Za-z0-9_]*\s*->\s*([A-Za-z0-9_!?]+)\([^)]*\)\s*end\)/);

  if (arrayHelperMatch) {
    const items = inferResponseHelperSchema(viewSource, arrayHelperMatch[1], visited) || {
      $ref: "#/components/schemas/GenericValue"
    };
    return {
      type: "array",
      items
    };
  }

  if (expression.includes("|| %{}") || expression.startsWith("%{") || normalized === "metadata") {
    return {
      type: "object",
      additionalProperties: true
    };
  }

  if (
    expression.includes("|| []") ||
    /(events|scopes|tags|templates|ips|urls|vas|statuses)$/.test(normalized)
  ) {
    return {
      type: "array",
      items: { type: "string" }
    };
  }

  if (
    normalized.startsWith("is_") ||
    normalized.startsWith("has_") ||
    normalized.endsWith("_enabled") ||
    normalized.endsWith("_verified") ||
    normalized.endsWith("_available") ||
    /\btrue\b|\bfalse\b/.test(expression)
  ) {
    return { type: "boolean" };
  }

  if (
    normalized.endsWith("_at") ||
    normalized.includes("timestamp") ||
    ["created", "updated", "inserted_at", "updated_at", "expires_at"].includes(normalized)
  ) {
    return {
      type: "string",
      format: "date-time"
    };
  }

  if (normalized === "id" || normalized.endsWith("_id") || normalized.endsWith("_uuid")) {
    return inferResponseIdSchema(fieldName, expression, contextName);
  }

  if (
    /render_currency|Decimal/.test(expression) ||
    ["pending_balance", "available_balance", "amount", "balance_before", "balance_after"].includes(
      normalized
    )
  ) {
    return { type: "string" };
  }

  if (
    /(count|total|page|page_size|price|fee|bps|quantity|balance|progress|status_code)$/.test(
      normalized
    )
  ) {
    return { type: "integer" };
  }

  if (normalized === "status" && /status/.test(expression)) {
    return { type: "string" };
  }

  return { type: "string", nullable: true };
}

function inferObjectSchemaFromExpression(viewSource, expression, contextName, visited = new Set()) {
  const pairs = extractLiteralPairs(expression);
  if (!pairs || pairs.length === 0) {
    return null;
  }

  return {
    type: "object",
    properties: Object.fromEntries(
      pairs.map((pair) => [
        pair.key,
        inferResponseFieldSchema(viewSource, pair.key, pair.expression, contextName, visited)
      ])
    )
  };
}

function inferResponseHelperSchema(viewSource, helperName, visited = new Set()) {
  if (visited.has(helperName)) {
    return { $ref: "#/components/schemas/GenericObject" };
  }

  visited.add(helperName);
  const clause = pickBestFunctionClause(extractFunctionClausesFromSource(viewSource, helperName));
  if (!clause) {
    visited.delete(helperName);
    return null;
  }

  const schema = inferObjectSchemaFromExpression(viewSource, clause, helperName, visited);
  visited.delete(helperName);
  return schema;
}

function extractRawDataExpressions(actionBody) {
  const expressions = [];

  for (const match of actionBody.matchAll(/(?:render\(\s*conn\s*,\s*:raw_data\b|\|>\s*render\(\s*:raw_data\b)/g)) {
    const renderBlock = actionBody.slice(match.index);
    const dataMatch = renderBlock.match(/\bdata:\s*/);

    if (!dataMatch) {
      continue;
    }

    const expression = renderBlock
      .slice(dataMatch.index + dataMatch[0].length)
      .trimStart();

    if (expression.startsWith("%{")) {
      const literalBody = extractLiteralBody(expression, "{", "}");
      if (literalBody !== null) {
        expressions.push(`%{${literalBody}}`);
      }
      continue;
    }

    if (expression.startsWith("[")) {
      const literalBody = extractLiteralBody(expression, "[", "]");
      if (literalBody !== null) {
        expressions.push(`[${literalBody}]`);
      }
    }
  }

  return expressions;
}

function mergeObjectSchemas(schemas) {
  if (schemas.length === 0) {
    return null;
  }

  if (schemas.length === 1) {
    return schemas[0];
  }

  if (!schemas.every((schema) => schema?.type === "object" && schema.properties)) {
    return {
      oneOf: schemas
    };
  }

  const mergedProperties = {};

  for (const schema of schemas) {
    for (const [propertyName, propertySchema] of Object.entries(schema.properties || {})) {
      const existing = mergedProperties[propertyName];
      if (!existing) {
        mergedProperties[propertyName] = propertySchema;
        continue;
      }

      if (canonicalize(existing) === canonicalize(propertySchema)) {
        continue;
      }

      const oneOf = existing.oneOf ? [...existing.oneOf] : [existing];
      if (!oneOf.some((entry) => canonicalize(entry) === canonicalize(propertySchema))) {
        oneOf.push(propertySchema);
      }

      mergedProperties[propertyName] = { oneOf };
    }
  }

  return {
    type: "object",
    properties: mergedProperties
  };
}

function inferResponseDataSchemaFromRawData(route) {
  const schemas = extractRawDataExpressions(route.actionBody)
    .map((expression) =>
      inferObjectSchemaFromExpression("", expression, route.action, new Set())
    )
    .filter(Boolean);

  return mergeObjectSchemas(schemas);
}

function inferResponseDataSchemaFromView(route) {
  const controllerSource = controllerModuleMap.get(route.controllerModule)?.source || "";
  const viewModule = inferViewModule(route);
  const viewSource = controllerModuleMap.get(viewModule)?.source;
  const renderName = extractRenderName(route.actionBody, controllerSource, route.controllerModule);

  if (!viewSource || !renderName) {
    return null;
  }

  const renderClause = pickBestFunctionClause(extractFunctionClausesFromSource(viewSource, renderName));
  if (!renderClause) {
    return null;
  }

  const paginatedHelperMatch =
    renderClause.match(/Enum\.map\([^,]+,\s*&([A-Za-z0-9_!?]+)\/1\)\s*\|>\s*BaseJSON\.paginated_response\((%?\{[\s\S]*?\})?/) ||
    renderClause.match(/\|>\s*Enum\.map\(&([A-Za-z0-9_!?]+)\/1\)\s*\|>\s*BaseJSON\.paginated_response\((%?\{[\s\S]*?\})?/) ||
    renderClause.match(/Enum\.map\([^,]+,\s*fn\s+[A-Za-z_][A-Za-z0-9_]*\s*->\s*([A-Za-z0-9_!?]+)\([^)]*\)\s*end\)\s*\|>\s*BaseJSON\.paginated_response\((%?\{[\s\S]*?\})?/);

  if (paginatedHelperMatch) {
    const helperSchema =
      inferResponseHelperSchema(viewSource, paginatedHelperMatch[1], new Set()) ||
      { $ref: "#/components/schemas/GenericObject" };
    const wrapperPairs = extractLiteralPairs(paginatedHelperMatch[2] || "%{}") || [];
    const wrapperProperties = {
      results: {
        type: "array",
        items: helperSchema
      }
    };

    for (const pair of wrapperPairs) {
      wrapperProperties[pair.key] = inferResponseFieldSchema(
        viewSource,
        pair.key,
        pair.expression,
        renderName,
        new Set()
      );
    }

    return {
      type: "object",
      properties: wrapperProperties
    };
  }

  const arrayHelperMatch =
    renderClause.match(/Enum\.map\([^,]+,\s*&([A-Za-z0-9_!?]+)\/1\)\s*\|>\s*BaseJSON\.response\(/) ||
    renderClause.match(/\|>\s*Enum\.map\(&([A-Za-z0-9_!?]+)\/1\)\s*\|>\s*BaseJSON\.response\(/) ||
    renderClause.match(/Enum\.map\([^,]+,\s*fn\s+[A-Za-z_][A-Za-z0-9_]*\s*->\s*([A-Za-z0-9_!?]+)\([^)]*\)\s*end\)\s*\|>\s*BaseJSON\.response\(/);

  if (arrayHelperMatch) {
    return {
      type: "array",
      items:
        inferResponseHelperSchema(viewSource, arrayHelperMatch[1], new Set()) || {
          $ref: "#/components/schemas/GenericObject"
        }
    };
  }

  const objectPipeMatch = renderClause.match(/\b\w+\s*\|>\s*([A-Za-z0-9_!?]+)\([^)]*\)\s*\|>\s*BaseJSON\.response\(/);
  if (objectPipeMatch) {
    const helperSchema = inferResponseHelperSchema(viewSource, objectPipeMatch[1], new Set());
    if (helperSchema) {
      return helperSchema;
    }
  }

  const directLiteralSchema = inferObjectSchemaFromExpression(viewSource, renderClause, renderName, new Set());
  if (directLiteralSchema) {
    return directLiteralSchema;
  }

  const variableResponseMatch = renderClause.match(/BaseJSON\.response\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/);
  if (variableResponseMatch) {
    const assignedExpression = extractAssignedExpression(renderClause, variableResponseMatch[1]);
    if (assignedExpression) {
      const assignedArrayHelper =
        assignedExpression.match(/Enum\.map\([^,]+,\s*&([A-Za-z0-9_!?]+)\/1\)/) ||
        assignedExpression.match(/Enum\.map\([^,]+,\s*fn\s+[A-Za-z_][A-Za-z0-9_]*\s*->\s*([A-Za-z0-9_!?]+)\([^)]*\)\s*end\)/) ||
        assignedExpression.match(/Enum\.map\([^,]+,\s*fn\s+[A-Za-z_][A-Za-z0-9_]*\s*->\s*(%\{[\s\S]*?\})\s*end/);

      if (assignedArrayHelper?.[1] && !assignedArrayHelper[1].startsWith("%{")) {
        const helperSchema = inferResponseHelperSchema(viewSource, assignedArrayHelper[1], new Set());
        if (helperSchema) {
          return {
            type: "array",
            items: helperSchema
          };
        }
      }

      if (assignedArrayHelper?.[1]?.startsWith("%{")) {
        const itemSchema = inferObjectSchemaFromExpression(
          viewSource,
          assignedArrayHelper[1],
          renderName,
          new Set()
        );
        if (itemSchema) {
          return {
            type: "array",
            items: itemSchema
          };
        }
      }

      const assignedObjectSchema = inferObjectSchemaFromExpression(
        viewSource,
        assignedExpression,
        renderName,
        new Set()
      );
      if (assignedObjectSchema) {
        return assignedObjectSchema;
      }
    }
  }

  return null;
}

function buildInferredResponseSchemaName(route) {
  const operationKey = route.operationId.split(".").slice(-2).join(" ");
  return `Inferred${toPascalCase(operationKey)}Response`;
}

function ensureInferredResponseComponent(spec, route, dataSchema) {
  if (!dataSchema) {
    return null;
  }

  const schemas = ensureObject(ensureObject(spec, "components"), "schemas");
  const responses = ensureObject(ensureObject(spec, "components"), "responses");
  const responseSchemaName = buildInferredResponseSchemaName(route);

  setSchema(schemas, responseSchemaName, {
    type: "object",
    properties: {
      code: { type: "integer", example: inferSuccessStatus(route) },
      status: { type: "string", example: "Success" },
      data: dataSchema
    }
  });

  setResponseComponent(responses, responseSchemaName, "Success", `#/components/schemas/${responseSchemaName}`);

  return `#/components/responses/${responseSchemaName}`;
}

function routeProbablyHasNoRequestBody(route, schema) {
  if (schema.properties && Object.keys(schema.properties).length > 0) {
    return false;
  }

  const bodyWithoutHeader = route.actionBody.replace(/^[\s\S]*?\bdo\b/, "");

  if (/^[ \t]{2}def(?:p)?\s+[A-Za-z0-9_!?]+\s*\([^,]+,\s*_params\b/m.test(route.actionBody)) {
    return true;
  }

  return !/\bparams\b/.test(bodyWithoutHeader);
}

function ensureSharedComponents(spec) {
  const components = ensureObject(spec, "components");
  const responses = ensureObject(components, "responses");
  const schemas = ensureObject(components, "schemas");

  setSchema(schemas, "GenericObject", {
    type: "object",
    additionalProperties: true,
    description: "Best-effort object schema for authenticated Nexus API payloads."
  });

  setSchema(schemas, "GenericValue", {
    description: "Best-effort JSON value schema for authenticated Nexus API payloads."
  });

  setSchema(schemas, "GenericResultsPage", {
    type: "object",
    description: "Best-effort paginated collection wrapper.",
    additionalProperties: true,
    properties: {
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/GenericObject" }
      },
      has_next: { type: "boolean" },
      last_id: {
        oneOf: [{ type: "string" }, { type: "integer" }]
      },
      page_size: { type: "integer" }
    }
  });

  setSchema(schemas, "GenericSuccessObjectResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/GenericObject" }
    }
  });

  setSchema(schemas, "GenericSuccessDataResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/GenericValue" }
    }
  });

  setSchema(schemas, "SuccessMessageResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      message: { type: "string" }
    }
  });

  setSchema(schemas, "GenericSuccessListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/GenericResultsPage" }
    }
  });

  setSchema(schemas, "GenericCreatedObjectResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 201 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/GenericObject" }
    }
  });

  setSchema(schemas, "PaymentRequiredError", {
    type: "object",
    properties: {
      code: { type: "integer", example: 402 },
      status: { type: "string", example: "Payment Required" },
      error: { type: "string" }
    }
  });

  setSchema(schemas, "WabaTemplateMessageBatchRequest", {
    type: "object",
    required: ["template_id", "file", "component_values"],
    properties: {
      template_id: {
        description: "WhatsApp template ID to send.",
        oneOf: [{ type: "string" }, { type: "integer" }]
      },
      file: {
        type: "string",
        format: "binary",
        description: "CSV file containing at least `name` and `phone` columns."
      },
      component_values: {
        type: "string",
        description: "JSON-encoded component values for the selected template."
      },
      is_prevent_duplicate: {
        type: "boolean",
        description: "Prevents sending to the same recipient more than once in the batch."
      },
      is_prevent_multiple_in_period: {
        type: "boolean",
        description: "Prevents sending multiple messages within the configured duplicate-protection period."
      }
    }
  });

  setSchema(schemas, "WabaMediaUploadRequest", {
    type: "object",
    required: ["file"],
    properties: {
      file: {
        type: "string",
        format: "binary",
        description: "JPEG or PNG media file to upload to the WhatsApp Business Account."
      }
    }
  });

  setSchema(schemas, "WabaAccountUpdateRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      store_id: {
        description: "Store ID to associate with the WhatsApp Business Account.",
        type: "integer",
        nullable: true
      },
      runtime_owner: {
        description: "Runtime owner that should handle the WhatsApp Business Account.",
        type: "string",
        enum: ["nexus_internal", "waylev_bot"],
        nullable: true
      }
    }
  });

  setSchema(schemas, "WabaCustomerTemplateMessageRequest", {
    type: "object",
    required: ["template_id"],
    additionalProperties: false,
    properties: {
      template_id: {
        description: "WhatsApp template ID to send to the customer.",
        oneOf: [{ type: "integer" }, { type: "string" }]
      },
      file: {
        type: "string",
        format: "binary",
        description: "Optional JPEG or PNG header image attachment for the template."
      },
      components_param: {
        type: "object",
        additionalProperties: { $ref: "#/components/schemas/GenericValue" },
        description:
          "Optional template component payload, including indexed body, header, footer, and button params."
      }
    }
  });

  setSchema(schemas, "UserOtpRequest", {
    type: "object",
    required: ["otp_purpose"],
    properties: {
      otp_purpose: {
        type: "string",
        description: "Purpose identifier for the OTP that should be sent.",
        enum: [
          "login",
          "affiliate_payout",
          "business_payout",
          "change_business_owner",
          "change_payout_target"
        ]
      }
    }
  });

  setSchema(schemas, "CustomerSetNewPasswordRequest", {
    type: "object",
    required: ["password"],
    properties: {
      password: {
        type: "string",
        description: "New password to assign to the authenticated customer."
      }
    }
  });

  setSchema(schemas, "CustomerCourseContentProgressRequest", {
    type: "object",
    required: ["progress"],
    properties: {
      progress: {
        type: "integer",
        description: "Integer progress value to record for the current customer."
      }
    }
  });

  setSchema(schemas, "SesCreditAmount", {
    description: "SES credit quantity, provided as an integer or a numeric string.",
    oneOf: [
      {
        type: "integer",
        minimum: 1
      },
      {
        type: "string",
        pattern: "^[0-9]+$"
      }
    ]
  });

  setSchema(schemas, "SesCreditsCreditRequest", {
    type: "object",
    required: ["credit"],
    properties: {
      credit: {
        $ref: "#/components/schemas/SesCreditAmount"
      }
    }
  });

  setSchema(schemas, "BusinessFileUploadInitRequest", {
    type: "object",
    required: ["filename", "content_type", "content_length"],
    properties: {
      filename: {
        type: "string",
        description: "Original filename for the upload."
      },
      content_type: {
        type: "string",
        description: "MIME type that will be used for the uploaded file."
      },
      content_length: {
        oneOf: [{ type: "integer" }, { type: "string" }],
        description: "Expected file size in bytes."
      }
    }
  });

  setSchema(schemas, "OAuthAuthorizationFormPayload", {
    type: "object",
    properties: {
      application: { $ref: "#/components/schemas/GenericObject" },
      redirect_uri: { type: "string", format: "uri" },
      state: { type: "string" },
      session_id: { type: "string" },
      is_reconnect: { type: "boolean" },
      current_approved_billing_tags: {
        type: "array",
        items: { $ref: "#/components/schemas/GenericObject" }
      }
    }
  });

  setSchema(schemas, "OAuthAuthorizationFormResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/OAuthAuthorizationFormPayload" }
    }
  });

  setSchema(schemas, "OAuthAuthorizeApproveRequest", {
    type: "object",
    required: [
      "client_id",
      "redirect_uri",
      "approved_scopes",
      "approved_webhook_status",
      "approved_webhook_events",
      "state",
      "session_id"
    ],
    properties: {
      client_id: { type: "string" },
      redirect_uri: { type: "string", format: "uri" },
      approved_scopes: {
        description: "Space-delimited string or array of scopes approved by the user.",
        oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }]
      },
      approved_webhook_status: {
        type: "string",
        enum: ["active", "inactive"]
      },
      approved_webhook_events: {
        description: "Space-delimited string or array of approved webhook event names.",
        oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }]
      },
      approved_billing_tags: {
        description: "Space-delimited string or array of approved billing tag names.",
        oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }]
      },
      state: { type: "string" },
      session_id: { type: "string" }
    }
  });

  setSchema(schemas, "SubscriptionVariantOptionsResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/SubscriptionVariantOptions" }
    }
  });

  setSchema(schemas, "NotificationUnreadCountPayload", {
    type: "object",
    properties: {
      unread_count: {
        type: "integer",
        description: "Number of unread notifications for the authenticated business."
      }
    }
  });

  setSchema(schemas, "NotificationUnreadCountResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/NotificationUnreadCountPayload" }
    }
  });

  setSchema(schemas, "StoreCourierServiceRemovalRequest", {
    type: "object",
    required: ["courier_service_ids"],
    properties: {
      courier_service_ids: {
        description: "List of courier service IDs to dissociate from the store.",
        type: "array",
        items: { type: "integer" }
      }
    }
  });

  setSchema(schemas, "StorePaymentMethodRemovalRequest", {
    type: "object",
    properties: {
      payment_account_id: {
        description: "Payment account ID to remove from the store.",
        type: "integer"
      },
      payment_method: {
        description: "Order payment method to dissociate from the store.",
        type: "string"
      },
      sub_payment_method: {
        description: "Sub-payment method code to dissociate from the store.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "CreateEmailIdentityRequest", {
    type: "object",
    required: ["email", "name"],
    properties: {
      email: {
        description: "Domain to verify for SES sending, for example `custom-domain.com`.",
        type: "string"
      },
      name: {
        description: "Display name for the identity.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "CustomerCartItem", {
    type: "object",
    properties: {
      id: { type: "integer" },
      variant_id: { type: "integer" },
      quantity: { type: "integer" },
      variant_name: { type: "string" },
      product_name: { type: "string" },
      product_slug: { type: "string" },
      sku: { type: "string" },
      price: { oneOf: [{ type: "number" }, { type: "string" }] },
      currency: { type: "string" },
      weight: { oneOf: [{ type: "number" }, { type: "string" }] },
      image: { type: "string" },
      line_subtotal: { oneOf: [{ type: "number" }, { type: "string" }] },
      available: { type: "boolean" },
      available_qty: { type: "integer" },
      created_at: { type: "string", format: "date-time" }
    }
  });

  setSchema(schemas, "CustomerCart", {
    type: "object",
    properties: {
      id: { type: "integer" },
      status: { type: "string" },
      item_count: { type: "integer" },
      total: { oneOf: [{ type: "number" }, { type: "string" }] },
      expires_at: { type: "string", format: "date-time" },
      items: {
        type: "array",
        items: { $ref: "#/components/schemas/CustomerCartItem" }
      },
      created_at: { type: "string", format: "date-time" },
      last_updated_at: { type: "string", format: "date-time" }
    }
  });

  setSchema(schemas, "CustomerCartResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/CustomerCart" }
    }
  });

  setSchema(schemas, "CustomerTagListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: {
        type: "array",
        description: "Distinct tag names currently assigned to customers in the authenticated business.",
        items: { type: "string" }
      }
    }
  });

  setSchema(schemas, "CurrentCustomerCheckoutPageAddress", {
    type: "object",
    properties: {
      id: { type: "integer" },
      name: { type: "string" },
      phone: { type: "string" },
      email: { type: "string", format: "email" },
      address: { type: "string" },
      postal_code: { type: "string" },
      location_id: { type: "integer" },
      location: {
        type: "object",
        nullable: true,
        properties: {
          id: { type: "integer" },
          name: { type: "string" }
        }
      }
    }
  });

  setSchema(schemas, "CurrentCustomerCheckoutPageDisplay", {
    type: "object",
    properties: {
      meta: { $ref: "#/components/schemas/GenericObject" },
      header: { $ref: "#/components/schemas/GenericObject" },
      banner: { $ref: "#/components/schemas/GenericObject" },
      general: { $ref: "#/components/schemas/GenericObject" },
      sidebar: {
        oneOf: [
          { $ref: "#/components/schemas/GenericObject" },
          {
            type: "array",
            items: { $ref: "#/components/schemas/GenericObject" }
          }
        ]
      },
      main: {
        type: "array",
        items: { $ref: "#/components/schemas/GenericObject" }
      },
      gtm: {
        type: "object",
        nullable: true,
        additionalProperties: true
      },
      fb_pixels: {
        type: "array",
        items: { $ref: "#/components/schemas/GenericObject" }
      },
      tiktok_pixels: {
        type: "array",
        items: { $ref: "#/components/schemas/GenericObject" }
      },
      kwai_client_pixels: {
        type: "array",
        items: { $ref: "#/components/schemas/GenericObject" }
      },
      kwai_server_pixels: {
        type: "array",
        items: { $ref: "#/components/schemas/GenericObject" }
      }
    }
  });

  setSchema(schemas, "CurrentCustomerCheckoutPage", {
    type: "object",
    properties: {
      is_active: { type: "boolean" },
      is_published: { type: "boolean" },
      is_product_page: { type: "boolean" },
      is_checkout_page: { type: "boolean" },
      business_id: { type: "integer" },
      client_analytics_config: { type: "string" },
      current_page_display: {
        $ref: "#/components/schemas/CurrentCustomerCheckoutPageDisplay"
      },
      window_object: { $ref: "#/components/schemas/GenericObject" },
      customer_addresses: {
        type: "array",
        items: { $ref: "#/components/schemas/CurrentCustomerCheckoutPageAddress" }
      }
    }
  });

  setSchema(schemas, "CurrentCustomerCheckoutPageResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: {
        type: "object",
        properties: {
          page: { $ref: "#/components/schemas/CurrentCustomerCheckoutPage" }
        }
      }
    }
  });

  setSchema(schemas, "CustomerCartCheckoutRequest", {
    type: "object",
    required: ["payment_method"],
    additionalProperties: false,
    properties: {
      payment_method: { type: "string" },
      metadata: {
        type: "object",
        additionalProperties: { $ref: "#/components/schemas/GenericValue" }
      }
    }
  });

  setSchema(schemas, "CustomerCartCheckoutResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 201 },
      status: { type: "string", example: "Success" },
      data: {
        type: "object",
        properties: {
          order_id: { type: "string" },
          order_secret_slug: { type: "string" },
          status: { type: "string" },
          payment_method: { type: "string" },
          created_at: { type: "string", format: "date-time" }
        }
      }
    }
  });

  setSchema(schemas, "CustomerCartItemAddRequest", {
    type: "object",
    required: ["variant_id"],
    properties: {
      variant_id: {
        description: "Variant ID to add to the customer's cart.",
        type: "integer"
      },
      quantity: {
        description: "Quantity to add. Defaults to 1 when omitted.",
        type: "integer",
        minimum: 1
      }
    }
  });

  setSchema(schemas, "CustomerCartItemUpdateRequest", {
    type: "object",
    required: ["quantity"],
    properties: {
      quantity: {
        description: "Updated quantity for the cart item.",
        type: "integer",
        minimum: 1
      }
    }
  });

  setSchema(schemas, "CheckoutAddressLocation", {
    type: "object",
    nullable: true,
    properties: {
      id: { type: "integer" },
      subdistrict_name: { type: "string" },
      city_name: { type: "string" },
      province_name: { type: "string" }
    }
  });

  setSchema(schemas, "CheckoutAddress", {
    type: "object",
    properties: {
      id: { type: "integer" },
      name: { type: "string" },
      phone: { type: "string" },
      email: { type: "string" },
      address: { type: "string" },
      postal_code: { type: "string" },
      notes: { type: "string" },
      location: {
        $ref: "#/components/schemas/CheckoutAddressLocation"
      }
    }
  });

  setSchema(schemas, "CheckoutAddressesResponse", {
    type: "object",
    properties: {
      data: {
        type: "array",
        items: { $ref: "#/components/schemas/CheckoutAddress" }
      }
    }
  });

  setSchema(schemas, "CheckoutShippingOptionsRequest", {
    type: "object",
    required: ["location_id", "payment_method", "postal_code"],
    additionalProperties: false,
    properties: {
      location_id: {
        description: "Destination location ID for rate lookup.",
        oneOf: [{ type: "integer" }, { type: "string" }]
      },
      postal_code: {
        description: "Destination postal code.",
        type: "string"
      },
      payment_method: {
        description: "Checkout payment method that may affect available shipping options.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "CheckoutShippingOption", {
    type: "object",
    properties: {
      courier_service_id: { type: "integer" },
      courier_code: { type: "string" },
      service_code: { type: "string" },
      name: { type: "string" },
      cost: { oneOf: [{ type: "number" }, { type: "string" }] },
      etd: { type: "string" },
      is_cod: { type: "boolean" },
      warehouse_unique_id: { type: "string" },
      courier_aggregator_code: { type: "string" }
    }
  });

  setSchema(schemas, "CheckoutShippingOptionsResponse", {
    type: "object",
    properties: {
      data: {
        type: "array",
        items: { $ref: "#/components/schemas/CheckoutShippingOption" }
      }
    }
  });

  setSchema(schemas, "CheckoutPaymentAccount", {
    type: "object",
    properties: {
      id: { type: "integer" },
      method: { type: "string" },
      account_number: { type: "string" },
      account_holder: { type: "string" },
      financial_entity_code: { type: "string" },
      financial_entity_name: { type: "string" }
    }
  });

  setSchema(schemas, "CheckoutPaymentMethodsPayload", {
    type: "object",
    properties: {
      payment_methods: {
        type: "array",
        items: { type: "string" }
      },
      xendit_va_bank_codes: {
        type: "array",
        items: { type: "string" }
      },
      payment_accounts: {
        type: "array",
        items: { $ref: "#/components/schemas/CheckoutPaymentAccount" }
      }
    }
  });

  setSchema(schemas, "CheckoutPaymentMethodsResponse", {
    type: "object",
    properties: {
      data: {
        $ref: "#/components/schemas/CheckoutPaymentMethodsPayload"
      }
    }
  });

  setSchema(schemas, "CheckoutSummaryRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      shipping_cost: { oneOf: [{ type: "integer" }, { type: "string" }] },
      courier_service_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      payment_method: { type: "string" }
    }
  });

  setSchema(schemas, "CheckoutSummaryPayload", {
    type: "object",
    properties: {
      product_price: { type: "string" },
      shipping_cost: { type: "string" },
      other_income: { type: "string" },
      other_income_name: { type: "string" },
      gross_revenue: { type: "string" }
    }
  });

  setSchema(schemas, "CheckoutSummaryResponse", {
    type: "object",
    properties: {
      data: { $ref: "#/components/schemas/CheckoutSummaryPayload" }
    }
  });

  setSchema(schemas, "CheckoutConfirmRequest", {
    type: "object",
    required: ["payment_method"],
    additionalProperties: false,
    properties: {
      payment_method: { type: "string" },
      address_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      address: { type: "string" },
      location_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      postal_code: { type: "string" },
      metadata: {
        type: "object",
        additionalProperties: { $ref: "#/components/schemas/GenericValue" }
      }
    }
  });

  setSchema(schemas, "CheckoutConfirmPayload", {
    type: "object",
    properties: {
      order_id: { type: "string" },
      secret_slug: { type: "string" },
      status: { type: "string" }
    }
  });

  setSchema(schemas, "CheckoutConfirmResponse", {
    type: "object",
    properties: {
      data: { $ref: "#/components/schemas/CheckoutConfirmPayload" }
    }
  });

  setSchema(schemas, "PasswordConfirmationRequest", {
    type: "object",
    required: ["password"],
    properties: {
      password: {
        description: "Current account password used to confirm the requested action.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "TokenConfirmationRequest", {
    type: "object",
    required: ["token"],
    properties: {
      token: {
        description: "Confirmation token for the requested email verification action.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "LeaveBusinessRequest", {
    $ref: "#/components/schemas/PasswordConfirmationRequest"
  });

  setSchema(schemas, "SwitchBusinessRoleRequest", {
    type: "object",
    required: ["business_role", "model_name"],
    properties: {
      model_name: {
        description: "Business capability model to switch, for example `InventoryFlow`.",
        type: "string"
      },
      business_role: {
        description: "Target business role for the selected model.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "SetCurrentUserPasswordRequest", {
    type: "object",
    required: ["current_password", "new_password"],
    properties: {
      current_password: {
        description: "Current password for the authenticated user.",
        type: "string"
      },
      new_password: {
        description: "New password to store for the authenticated user.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "UserUpdateRequest", {
    type: "object",
    description: "Editable profile fields for the authenticated user.",
    properties: {
      fullname: { type: "string", minLength: 3 },
      phone: { type: "string" },
      temp_email: { type: "string", format: "email" },
      last_email_change_at: { type: "string", format: "date-time" },
      email_change_verified_at: { type: "string", format: "date-time" },
      telegram_chat_id: { type: "string" }
    }
  });

  setSchema(schemas, "UserFcmSubscriptionRequest", {
    type: "object",
    required: ["device_id", "token"],
    properties: {
      device_id: {
        type: "string",
        description: "Stable device identifier used to upsert the push subscription."
      },
      token: {
        type: "string",
        description: "Firebase Cloud Messaging token for the device."
      }
    }
  });

  setSchema(schemas, "ChangeBusinessOwnershipRequest", {
    type: "object",
    required: ["email", "otp"],
    properties: {
      email: {
        description: "Email address of the user who will become the new business owner.",
        type: "string"
      },
      otp: {
        description: "One-time password used to confirm the ownership transfer.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "CreateSsoAuthorizationCodeRequest", {
    type: "object",
    required: ["client_id", "code_challenge", "redirect_uri"],
    additionalProperties: false,
    properties: {
      client_id: {
        description: "OAuth client identifier.",
        type: "string"
      },
      code_challenge: {
        description: "PKCE code challenge derived from the client code verifier.",
        type: "string"
      },
      redirect_uri: {
        description: "Redirect URI registered for the OAuth client.",
        type: "string",
        format: "uri"
      },
      state: {
        description: "Optional state value echoed back with the authorization code response.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "SsoAuthorizationCodePayload", {
    type: "object",
    properties: {
      code: { type: "string" },
      state: { type: "string", nullable: true },
      redirect_uri: { type: "string", format: "uri" },
      expires_in: { type: "integer" }
    }
  });

  setSchema(schemas, "SsoAuthorizationCodeResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/SsoAuthorizationCodePayload" }
    }
  });

  setSchema(schemas, "JwtAccessTokenPayload", {
    type: "object",
    required: ["access"],
    properties: {
      access: {
        type: "string",
        description: "JWT access token."
      }
    }
  });

  const businessApiKeyBaseProperties = {
    name: {
      description: "Display name for the API key.",
      type: "string"
    },
    description: {
      description: "Optional description for the API key.",
      type: "string"
    },
    expires_at: {
      description: "Optional expiration timestamp for the API key.",
      type: "string",
      format: "date-time",
      nullable: true
    }
  };

  setSchema(schemas, "CreateBusinessApiKeyRequest", {
    description:
      "Payload used to create either a full-access secret key or a restricted key with explicit scopes.",
    oneOf: [
      {
        type: "object",
        required: ["name"],
        additionalProperties: false,
        properties: {
          ...businessApiKeyBaseProperties,
          key_type: {
            description: "API key type. When omitted, Nexus creates a secret key.",
            type: "string",
            enum: ["secret"]
          },
          scopes: {
            description: "Scopes are ignored for secret keys and should be omitted or empty.",
            type: "array",
            maxItems: 0,
            items: {
              type: "string"
            }
          }
        }
      },
      {
        type: "object",
        required: ["name", "key_type", "scopes"],
        additionalProperties: false,
        properties: {
          ...businessApiKeyBaseProperties,
          key_type: {
            description: "Restricted keys may only access the scopes listed in `scopes`.",
            type: "string",
            enum: ["restricted"]
          },
          scopes: {
            description: "Scopes explicitly granted to the restricted API key.",
            type: "array",
            minItems: 1,
            items: {
              type: "string"
            }
          }
        }
      }
    ]
  });

  setSchema(schemas, "BusinessApiKeyScopeCatalog", {
    type: "object",
    description: "Map of API key scope identifiers to the human-readable description shown in Nexus.",
    additionalProperties: {
      type: "string"
    }
  });

  setSchema(schemas, "BusinessApiKeyScopeCatalogResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessApiKeyScopeCatalog" }
    }
  });

  setSchema(schemas, "DiscourseSsoRequest", {
    type: "object",
    required: ["sso", "sig"],
    additionalProperties: false,
    properties: {
      sso: {
        type: "string",
        description: "Base64-encoded Discourse SSO payload received from the Discourse login redirect."
      },
      sig: {
        type: "string",
        description: "HMAC signature sent by Discourse for the incoming SSO payload."
      }
    }
  });

  setSchema(schemas, "SwitchCurrentUserBusinessRequest", {
    type: "object",
    required: ["business_id"],
    additionalProperties: false,
    properties: {
      business_id: {
        description: "Business ID to load as the authenticated user's current business context.",
        oneOf: [{ type: "integer" }, { type: "string" }]
      }
    }
  });

  setSchema(schemas, "CompleteCurrentUserTotpSetupRequest", {
    type: "object",
    required: ["secret", "code"],
    additionalProperties: false,
    properties: {
      secret: {
        type: "string",
        description: "TOTP secret issued during the initiate step."
      },
      code: {
        type: "string",
        description: "Current authenticator-app verification code for the supplied secret."
      }
    }
  });

  setSchema(schemas, "DisableCurrentUserTotpRequest", {
    type: "object",
    required: ["password", "totp_code"],
    additionalProperties: false,
    properties: {
      password: {
        type: "string",
        description: "Current account password used to confirm the MFA disable action."
      },
      totp_code: {
        type: "string",
        description: "Current TOTP code or backup code."
      }
    }
  });

  setSchema(schemas, "RegenerateCurrentUserBackupCodesRequest", {
    type: "object",
    required: ["totp_code"],
    additionalProperties: false,
    properties: {
      totp_code: {
        type: "string",
        description: "Current TOTP code or backup code used to authorize regeneration."
      }
    }
  });

  setSchema(schemas, "CurrentUserMfaStatus", {
    type: "object",
    properties: {
      mfa_method: { type: "string", nullable: true },
      totp_enabled: { type: "boolean" },
      backup_codes_count: { type: "integer" }
    }
  });

  setSchema(schemas, "DiscourseSsoPayload", {
    type: "object",
    required: ["sso", "sig"],
    additionalProperties: false,
    properties: {
      sso: {
        type: "string",
        description: "Signed Base64-encoded Discourse SSO payload returned to the client."
      },
      sig: {
        type: "string",
        description: "HMAC signature for the returned Discourse SSO payload."
      }
    }
  });

  setSchema(schemas, "CustomMetricFormulaNode", {
    type: "object",
    required: ["type", "value"],
    additionalProperties: false,
    properties: {
      type: {
        type: "string",
        enum: ["metric", "const", "extend"]
      },
      value: {
        type: "object",
        additionalProperties: { $ref: "#/components/schemas/GenericValue" }
      }
    }
  });

  setSchema(schemas, "CustomMetricFormulaExpression", {
    type: "object",
    required: ["left", "operator", "right"],
    additionalProperties: false,
    properties: {
      left: {
        type: "array",
        items: { $ref: "#/components/schemas/CustomMetricFormulaNode" }
      },
      operator: {
        type: "string",
        enum: ["plus", "multiply", "divide", "substract"]
      },
      right: {
        type: "array",
        items: { $ref: "#/components/schemas/CustomMetricFormulaNode" }
      }
    }
  });

  setSchema(schemas, "CustomMetricCreateRequest", {
    type: "object",
    required: ["name", "type", "formula", "is_draft"],
    additionalProperties: false,
    properties: {
      name: { type: "string" },
      type: {
        type: "string",
        enum: ["percentage", "default", "currency"]
      },
      formula: {
        type: "array",
        items: { $ref: "#/components/schemas/CustomMetricFormulaExpression" }
      },
      is_draft: { type: "boolean" }
    }
  });

  setSchema(schemas, "CustomMetricUpdateRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      name: { type: "string" },
      type: {
        type: "string",
        enum: ["percentage", "default", "currency"]
      },
      formula: {
        type: "array",
        items: { $ref: "#/components/schemas/CustomMetricFormulaExpression" }
      },
      is_draft: { type: "boolean" }
    }
  });

  setSchema(schemas, "AdViewFunnelRequest", {
    type: "object",
    required: ["level", "actions", "is_goal"],
    additionalProperties: false,
    properties: {
      level: { type: "integer" },
      actions: {
        type: "array",
        minItems: 1,
        items: { type: "string" }
      },
      is_goal: { type: "boolean" }
    }
  });

  const adViewRequestProperties = {
    name: { type: "string" },
    is_vat: { type: "boolean" },
    is_favorite: { type: "boolean" },
    indexing: { type: "integer" },
    is_draft: { type: "boolean" },
    currency: { type: "string" },
    timezone: { type: "string" },
    ad_account_ids: {
      type: "array",
      items: {
        oneOf: [{ type: "integer" }, { type: "string" }]
      }
    },
    funnels: {
      type: "array",
      items: { $ref: "#/components/schemas/AdViewFunnelRequest" }
    }
  };

  setSchema(schemas, "AdViewCreateRequest", {
    type: "object",
    required: ["name", "is_draft", "currency", "timezone", "ad_account_ids", "funnels"],
    additionalProperties: false,
    properties: adViewRequestProperties
  });

  setSchema(schemas, "AdViewUpdateRequest", {
    type: "object",
    additionalProperties: false,
    properties: adViewRequestProperties
  });

  setSchema(schemas, "AdViewCardsRequest", {
    type: "object",
    required: ["since", "until", "metrics"],
    additionalProperties: false,
    properties: {
      since: { type: "string", format: "date" },
      until: { type: "string", format: "date" },
      metrics: {
        type: "array",
        minItems: 1,
        items: { type: "string" }
      },
      campaign_ids: {
        type: "array",
        items: { type: "string" }
      }
    }
  });

  setSchema(schemas, "AdViewSummaryTableRequest", {
    type: "object",
    required: ["metrics"],
    additionalProperties: false,
    properties: {
      metrics: {
        type: "array",
        minItems: 1,
        items: { type: "string" }
      },
      campaign_ids: {
        type: "array",
        items: { type: "string" }
      }
    }
  });

  setSchema(schemas, "AdViewTopPerformanceRequest", {
    type: "object",
    required: ["since", "until", "type"],
    additionalProperties: false,
    properties: {
      since: { type: "string", format: "date" },
      until: { type: "string", format: "date" },
      type: {
        type: "string",
        description: "Breakdown type accepted by the ad-view analytics runtime."
      },
      campaign_ids: {
        type: "array",
        items: { type: "string" }
      }
    }
  });

  setSchema(schemas, "AdViewSyncMetricsRequest", {
    type: "object",
    required: ["account_ids"],
    additionalProperties: false,
    properties: {
      account_ids: {
        type: "array",
        minItems: 1,
        items: { type: "string" }
      }
    }
  });

  setSchema(schemas, "MetaFbLoginRequest", {
    type: "object",
    required: ["fb_access_token"],
    additionalProperties: false,
    properties: {
      fb_access_token: {
        type: "string",
        description: "Facebook access token used to link the authenticated business."
      }
    }
  });

  setSchema(schemas, "MetaSyncAdAccountsRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      after: {
        type: "string",
        description: "Optional pagination cursor used when continuing a sync."
      },
      fields: {
        oneOf: [
          {
            type: "array",
            items: { type: "string" }
          },
          { type: "string" }
        ],
        description: "Optional extra Meta ad account fields to request during the sync."
      }
    }
  });

  setSchema(schemas, "MetaChildBusinessManagerRequest", {
    type: "object",
    required: ["page_id", "vertical", "timezone"],
    additionalProperties: false,
    properties: {
      page_id: { type: "string" },
      vertical: { type: "string" },
      timezone: { type: "string" }
    }
  });

  setSchema(schemas, "MetaChildBusinessManagerAdAccountRequest", {
    type: "object",
    required: ["name", "currency", "timezone"],
    additionalProperties: false,
    properties: {
      name: { type: "string" },
      currency: { type: "string", enum: ["IDR"] },
      timezone: { type: "string" }
    }
  });

  setSchema(schemas, "MetaAdAccountTopUpRequest", {
    type: "object",
    required: ["account_id", "method", "currency", "ads_amount"],
    additionalProperties: false,
    properties: {
      account_id: { type: "string" },
      method: { type: "string", enum: ["balance", "invoice", "volt"] },
      currency: { type: "string", enum: ["IDR"] },
      ads_amount: { type: "integer" }
    }
  });

  setSchema(schemas, "MetaAdAccountTopUpPreviewRequest", {
    type: "object",
    required: ["ads_amount", "currency"],
    additionalProperties: false,
    properties: {
      ads_amount: { type: "integer" },
      currency: { type: "string", enum: ["IDR"] },
      method: {
        type: "string",
        enum: ["balance", "invoice", "volt"],
        nullable: true
      }
    }
  });

  setSchema(schemas, "MetaGraphApiMutationRequest", {
    type: "object",
    description:
      "Pass-through payload forwarded to the relevant Meta Graph API mutation for the selected ad resource.",
    additionalProperties: { $ref: "#/components/schemas/GenericValue" }
  });

  setSchema(schemas, "MetaAdImageUploadRequest", {
    type: "object",
    required: ["file"],
    additionalProperties: false,
    properties: {
      file: {
        type: "string",
        format: "binary"
      }
    }
  });

  setSchema(schemas, "WabaLoginRequest", {
    type: "object",
    required: ["waba_id", "business_id", "code"],
    additionalProperties: false,
    properties: {
      waba_id: { type: "string" },
      business_id: { type: "string" },
      code: { type: "string" },
      phone_number_id: {
        type: "string",
        nullable: true
      }
    }
  });

  setSchema(schemas, "WabaRegisterPhoneRequest", {
    type: "object",
    required: ["pin"],
    additionalProperties: false,
    properties: {
      pin: { type: "string" }
    }
  });

  setSchema(schemas, "WabaCustomerUpdateRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      handler_id: {
        oneOf: [{ type: "integer" }, { type: "string" }]
      },
      handler_type: {
        type: "string",
        enum: ["auto", "human"]
      },
      tag_ids: {
        type: "array",
        items: {
          oneOf: [{ type: "integer" }, { type: "string" }]
        }
      },
      is_block: { type: "boolean" }
    }
  });

  setSchema(schemas, "WabaPurchaseEventRequest", {
    type: "object",
    required: ["currency", "value"],
    additionalProperties: false,
    properties: {
      currency: { type: "string" },
      value: {
        oneOf: [{ type: "number" }, { type: "string" }]
      }
    }
  });

  setSchema(schemas, "WabaCustomerTagCreateRequest", {
    type: "object",
    required: ["name", "color"],
    additionalProperties: false,
    properties: {
      name: { type: "string" },
      color: {
        type: "string",
        enum: ["red", "green", "blue", "yellow", "purple", "orange", "pink", "brown", "gray", "black"]
      }
    }
  });

  setSchema(schemas, "WabaCustomerTagUpdateRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      name: { type: "string" },
      color: {
        type: "string",
        enum: ["red", "green", "blue", "yellow", "purple", "orange", "pink", "brown", "gray", "black"]
      }
    }
  });

  setSchema(schemas, "QuickReplyCreateRequest", {
    type: "object",
    required: ["message", "code"],
    additionalProperties: false,
    properties: {
      message: { type: "string", minLength: 1, maxLength: 1000 },
      code: { type: "string", minLength: 1, maxLength: 100 }
    }
  });

  setSchema(schemas, "QuickReplyUpdateRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      message: { type: "string", minLength: 1, maxLength: 1000 },
      code: { type: "string", minLength: 1, maxLength: 100 }
    }
  });

  setSchema(schemas, "WabaDirectMessageRequest", {
    type: "object",
    description:
      "WhatsApp Cloud API message payload forwarded to the send-message runtime after Nexus injects the destination and sender metadata.",
    additionalProperties: { $ref: "#/components/schemas/GenericValue" }
  });

  setSchema(schemas, "BusinessXpFileUploadRequest", {
    type: "object",
    required: ["file"],
    additionalProperties: false,
    properties: {
      file: {
        type: "string",
        format: "binary"
      },
      type: {
        type: "string",
        nullable: true
      },
      purpose: {
        type: "string",
        nullable: true
      }
    }
  });

  setSchema(schemas, "InventoryFlowCreateRequest", {
    type: "object",
    required: ["variant_id", "warehouse_id", "change", "quantity_type"],
    additionalProperties: false,
    properties: {
      variant_id: {
        oneOf: [{ type: "integer" }, { type: "string" }]
      },
      warehouse_id: {
        oneOf: [{ type: "integer" }, { type: "string" }]
      },
      warehouse_id_from: {
        oneOf: [{ type: "integer" }, { type: "string" }]
      },
      change: {
        type: "integer",
        description: "Non-zero inventory delta to apply."
      },
      quantity_type: {
        type: "string"
      },
      category: {
        type: "string",
        nullable: true
      },
      notes: {
        type: "string",
        nullable: true
      }
    }
  });

  setSchema(schemas, "CreateOAuthApplicationRequest", {
    type: "object",
    required: ["name", "redirect_uri", "webhook_status"],
    additionalProperties: false,
    properties: {
      name: { type: "string" },
      description: { type: "string" },
      homepage_url: { type: "string", format: "uri" },
      redirect_uri: { type: "string", format: "uri" },
      manage_url: { type: "string", format: "uri" },
      available_scopes: {
        type: "array",
        items: { type: "string" }
      },
      logo_url: { type: "string", format: "uri" },
      webhook_status: { type: "string" },
      webhook_events: {
        type: "array",
        items: { type: "string" }
      },
      billing_tags: {
        type: "array",
        items: { $ref: "#/components/schemas/CreateOAuthApplicationBillingTagRequest" }
      },
      whitelisted_ips: {
        type: "array",
        items: { type: "string" }
      }
    }
  });

  setSchema(schemas, "UpdateOAuthApplicationRequest", {
    $ref: "#/components/schemas/CreateOAuthApplicationRequest"
  });

  setSchema(schemas, "CreateOAuthApplicationBillingTagRequest", {
    type: "object",
    required: ["action_key", "currency", "label", "price", "tag_code"],
    properties: {
      tag_code: {
        description: "Unique billing tag code for the application action.",
        type: "string"
      },
      label: {
        description: "Human-readable billing tag label.",
        type: "string"
      },
      price: {
        description: "Billing amount in the smallest currency unit.",
        type: "integer"
      },
      currency: {
        description: "Billing currency code.",
        type: "string",
        enum: ["IDR"]
      },
      action_key: {
        description: "OAuth billing action key that this tag prices.",
        type: "string"
      },
      is_available_for_new_approvals: {
        description: "Whether the billing tag is available for new OAuth approvals.",
        type: "boolean"
      }
    }
  });

  setSchema(schemas, "UpdateOAuthApplicationBillingTagAvailabilityRequest", {
    type: "object",
    required: ["is_available_for_new_approvals"],
    properties: {
      is_available_for_new_approvals: {
        description: "Whether this billing tag is available for new OAuth approvals.",
        type: "boolean"
      }
    }
  });

  setSchema(schemas, "BusinessEvent", {
    type: "object",
    properties: {
      event: { type: "string" },
      unique_id: { type: "string" },
      timestamp: { type: "string", format: "date-time" },
      data: { $ref: "#/components/schemas/GenericObject" },
      status: { type: "integer" },
      entity_type: { type: "string", nullable: true },
      entity_id: { type: "string", nullable: true }
    }
  });

  setSchema(schemas, "BusinessEventListData", {
    type: "object",
    properties: {
      next: { type: "string", format: "date-time", nullable: true },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessEvent" }
      }
    }
  });

  setSchema(schemas, "BusinessEventListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessEventListData" }
    }
  });

  setSchema(schemas, "BusinessWebhookLog", {
    type: "object",
    properties: {
      request_id: { type: "string", nullable: true },
      timestamp: { type: "string", format: "date-time", nullable: true },
      timestamp_end: { type: "string", format: "date-time", nullable: true },
      request_url: { type: "string", format: "uri", nullable: true },
      request_headers: {
        type: "object",
        additionalProperties: true,
        nullable: true
      },
      response_status: { type: "integer", nullable: true },
      response_body: { type: "string", nullable: true },
      response_headers: {
        type: "object",
        additionalProperties: true,
        nullable: true
      }
    }
  });

  setSchema(schemas, "BusinessWebhookLogListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessWebhookLog" }
      }
    }
  });

  setSchema(schemas, "BusinessWebhookSettings", {
    type: "object",
    properties: {
      id: { type: "integer" },
      url: { type: "string", format: "uri" },
      status: {
        type: "string",
        enum: ["active", "inactive"]
      },
      events: {
        type: "array",
        items: { type: "string" }
      }
    }
  });

  setSchema(schemas, "BusinessOAuthSettings", {
    type: "object",
    properties: {
      id: { type: "integer" },
      username: { type: "string", nullable: true },
      client_id: { type: "string", nullable: true },
      client_secret: { type: "string", nullable: true },
      webhook: {
        allOf: [{ $ref: "#/components/schemas/BusinessWebhookSettings" }],
        nullable: true
      }
    }
  });

  setSchema(schemas, "BusinessOAuthSettingsResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessOAuthSettings" }
    }
  });

  setSchema(schemas, "BusinessWebhookEventOption", {
    type: "object",
    properties: {
      code: { type: "string" },
      name: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessWebhookEventOptionListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessWebhookEventOption" }
      }
    }
  });

  setSchema(schemas, "BusinessWebhookEventCode", {
    type: "string",
    enum: [
      "order.spam_created",
      "order.created",
      "order.updated",
      "order.deleted",
      "order.status_changed",
      "order.payment_status_changed",
      "order.epayment_created",
      "subscription.created",
      "subscription.activated",
      "subscription.renewed",
      "subscription.item_upgraded",
      "subscription.canceled",
      "subscription.expired",
      "subscription.activation_failed",
      "subscription.item_revoked",
      "subscription.item_reactivated",
      "whatsapp.message.received",
      "whatsapp.message.status.updated",
      "agent.system_trigger"
    ]
  });

  setSchema(schemas, "BusinessWebhookSettingsRequest", {
    type: "object",
    description:
      "Webhook configuration payload for the authenticated business. `url` is required the first time a webhook is configured. On later updates, omitted fields keep their stored values.",
    properties: {
      url: {
        type: "string",
        format: "uri",
        pattern: "^https://"
      },
      status: {
        type: "string",
        enum: ["active", "inactive"]
      },
      events: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessWebhookEventCode" }
      }
    }
  });

  setSchema(schemas, "BusinessUpdateRequest", {
    type: "object",
    description: "Business profile payload for the current business.",
    additionalProperties: false,
    properties: {
      account_holder: { type: "string" },
      username: { type: "string" },
      email: { type: "string", format: "email" },
      contact_phone: { type: "string" },
      contact_email: { type: "string", format: "email" },
      address: { type: "string" },
      location_id: { type: "integer" },
      subdistrict_name: { type: "string" },
      city_name: { type: "string" },
      province_name: { type: "string" },
      description: { type: "string" },
      category_code: { type: "string" },
      website_url: { type: "string", format: "uri" },
      is_tax: { type: "boolean" },
      tax_rate: { type: "integer" },
      aff_code: { type: "string" },
      ses_tenant_id: { type: "string" },
      ses_tenant_arn: { type: "string" },
      hourly_email_limit: { type: "integer" },
      hourly_email_limit_bypass_status: { type: "string" },
      aff_pixel_id: { type: "string" },
      aff_conversion_token: { type: "string" },
      aff_test_event_code: { type: "string" },
      aff_tt_pixel_id: { type: "string" },
      aff_tt_conversion_token: { type: "string" },
      aff_tt_test_event_code: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessMetadataUpdateRequest", {
    type: "object",
    description:
      "Metadata keys to merge into the currently selected business metadata object. Existing keys are preserved unless overwritten by the submitted payload.",
    minProperties: 1,
    additionalProperties: { $ref: "#/components/schemas/GenericValue" }
  });

  setSchema(schemas, "BusinessLegalUpdateRequest", {
    type: "object",
    description:
      "Corporation legal-profile fields that can be updated before or between business verification submissions.",
    properties: {
      description: { type: "string" },
      category_code: { type: "string" },
      website_url: { type: "string", format: "uri" },
      legal_name: { type: "string" },
      tax_id: { type: "string" },
      nib_id: { type: "string" },
      id_file: { type: "string" },
      npwp_file: { type: "string" },
      address: { type: "string" },
      subdistrict_name: { type: "string" },
      city_name: { type: "string" },
      province_name: { type: "string" },
      country_name: { type: "string" },
      postal_code: { type: "string" },
      akta_pendirian_file: { type: "string" },
      akta_perubahan_file: { type: "string" },
      director_name: { type: "string" },
      director_nik: { type: "string", minLength: 16, maxLength: 16 }
    }
  });

  setSchema(schemas, "BusinessVerificationIndividualManualRequest", {
    type: "object",
    required: [
      "business_type",
      "description",
      "category_code",
      "website_url",
      "phone",
      "gov_id",
      "fullname",
      "date_of_birth",
      "verification_type",
      "selfie_image",
      "gov_image",
      "bank_account_number",
      "bank_statement_image",
      "channel_code",
      "is_consent_given",
      "consented_at"
    ],
    properties: {
      business_type: { type: "string", enum: ["individual"] },
      description: { type: "string" },
      category_code: { type: "string" },
      website_url: { type: "string", format: "uri" },
      phone: { type: "string", minLength: 10, maxLength: 15 },
      gov_id: { type: "string", minLength: 16, maxLength: 16 },
      fullname: { type: "string" },
      email: { type: "string", format: "email" },
      date_of_birth: { type: "string", format: "date" },
      verification_type: { type: "string", enum: ["manual"] },
      selfie_image: { type: "string", format: "binary" },
      gov_image: { type: "string", format: "binary" },
      bank_account_number: { type: "string" },
      bank_statement_image: { type: "string", format: "binary" },
      channel_code: { type: "string" },
      is_consent_given: { type: "boolean", enum: [true] },
      consented_at: { type: "string", format: "date-time" }
    }
  });

  setSchema(schemas, "BusinessVerificationIndividualAutomaticRequest", {
    type: "object",
    required: [
      "business_type",
      "description",
      "category_code",
      "website_url",
      "phone",
      "gov_id",
      "fullname",
      "date_of_birth",
      "verification_type",
      "selfie_image",
      "consented_at",
      "is_consent_given",
      "verification_privacy_version"
    ],
    properties: {
      business_type: { type: "string", enum: ["individual"] },
      description: { type: "string" },
      category_code: { type: "string" },
      website_url: { type: "string", format: "uri" },
      phone: { type: "string", minLength: 10, maxLength: 15 },
      gov_id: { type: "string", minLength: 16, maxLength: 16 },
      fullname: { type: "string" },
      email: { type: "string", format: "email" },
      date_of_birth: { type: "string", format: "date" },
      verification_type: { type: "string", enum: ["automatic"] },
      selfie_image: { type: "string", format: "binary" },
      consented_at: { type: "string", format: "date-time" },
      is_consent_given: { type: "boolean", enum: [true] },
      verification_privacy_version: { type: "string", format: "date" }
    }
  });

  setSchema(schemas, "BusinessVerificationCorporationManualRequest", {
    type: "object",
    required: [
      "business_type",
      "description",
      "category_code",
      "website_url",
      "tax_id",
      "nib_id",
      "id_file",
      "npwp_file",
      "legal_name",
      "address",
      "subdistrict_name",
      "city_name",
      "province_name",
      "country_name",
      "postal_code",
      "akta_pendirian_file",
      "director_name",
      "director_nik",
      "director_phone",
      "director_dob",
      "director_verification_type",
      "director_gov_image",
      "director_selfie_image",
      "director_bank_account_number",
      "director_bank_statement_image",
      "director_channel_code"
    ],
    properties: {
      business_type: { type: "string", enum: ["corporation"] },
      description: { type: "string" },
      category_code: { type: "string" },
      website_url: { type: "string", format: "uri" },
      tax_id: { type: "string" },
      nib_id: { type: "string" },
      id_file: { type: "string" },
      npwp_file: { type: "string" },
      legal_name: { type: "string" },
      address: { type: "string" },
      subdistrict_name: { type: "string" },
      city_name: { type: "string" },
      province_name: { type: "string" },
      country_name: { type: "string" },
      postal_code: { type: "string" },
      akta_pendirian_file: { type: "string" },
      akta_perubahan_file: { type: "string" },
      director_name: { type: "string" },
      director_nik: { type: "string", minLength: 16, maxLength: 16 },
      director_phone: { type: "string" },
      director_dob: { type: "string", format: "date" },
      director_verification_type: { type: "string", enum: ["manual"] },
      director_gov_image: { type: "string", format: "binary" },
      director_selfie_image: { type: "string", format: "binary" },
      director_bank_account_number: { type: "string" },
      director_bank_statement_image: { type: "string", format: "binary" },
      director_channel_code: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessVerificationCorporationAutomaticRequest", {
    type: "object",
    required: [
      "business_type",
      "description",
      "category_code",
      "website_url",
      "tax_id",
      "nib_id",
      "id_file",
      "npwp_file",
      "legal_name",
      "address",
      "subdistrict_name",
      "city_name",
      "province_name",
      "country_name",
      "postal_code",
      "akta_pendirian_file",
      "director_name",
      "director_nik",
      "director_phone",
      "director_dob",
      "director_verification_type",
      "director_selfie_image"
    ],
    properties: {
      business_type: { type: "string", enum: ["corporation"] },
      description: { type: "string" },
      category_code: { type: "string" },
      website_url: { type: "string", format: "uri" },
      tax_id: { type: "string" },
      nib_id: { type: "string" },
      id_file: { type: "string" },
      npwp_file: { type: "string" },
      legal_name: { type: "string" },
      address: { type: "string" },
      subdistrict_name: { type: "string" },
      city_name: { type: "string" },
      province_name: { type: "string" },
      country_name: { type: "string" },
      postal_code: { type: "string" },
      akta_pendirian_file: { type: "string" },
      akta_perubahan_file: { type: "string" },
      director_name: { type: "string" },
      director_nik: { type: "string", minLength: 16, maxLength: 16 },
      director_phone: { type: "string" },
      director_dob: { type: "string", format: "date" },
      director_verification_type: { type: "string", enum: ["automatic"] },
      director_selfie_image: { type: "string", format: "binary" }
    }
  });

  setSchema(schemas, "BusinessVerificationRequest", {
    description:
      "Business verification submission payload. Use the variant that matches the business type and manual or automatic verification flow.",
    oneOf: [
      { $ref: "#/components/schemas/BusinessVerificationIndividualManualRequest" },
      { $ref: "#/components/schemas/BusinessVerificationIndividualAutomaticRequest" },
      { $ref: "#/components/schemas/BusinessVerificationCorporationManualRequest" },
      { $ref: "#/components/schemas/BusinessVerificationCorporationAutomaticRequest" }
    ]
  });

  setSchema(schemas, "BusinessSubscriptionOrder", {
    type: "object",
    properties: {
      id: { type: "integer" },
      secret: { type: "string" },
      business: { type: "integer" },
      subscription_order_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      pricing_plan: { type: "integer" },
      payment_method: { type: "string" },
      recurring_interval: { type: "string" },
      price: { oneOf: [{ type: "number" }, { type: "string" }] },
      amount: { oneOf: [{ type: "number" }, { type: "string" }] },
      discount: { oneOf: [{ type: "number" }, { type: "string" }] },
      vat: { oneOf: [{ type: "number" }, { type: "string" }] },
      currency: { type: "string" },
      xendit_invoice_id: { type: "string" },
      xendit_invoice_url: { type: "string", format: "uri" },
      xendit_transfer_id: { type: "string" },
      status: { type: "string" },
      draft_time: { type: "string", format: "date-time" },
      open_time: { type: "string", format: "date-time" },
      paid_time: { type: "string", format: "date-time" },
      void_time: { type: "string", format: "date-time" },
      uncollectible_time: { type: "string", format: "date-time" },
      created_at: { type: "string", format: "date-time" },
      expired_at: { type: "string", format: "date-time" },
      period_start: { type: "string", format: "date-time" },
      period_end: { type: "string", format: "date-time" }
    }
  });

  setSchema(schemas, "BusinessSubscriptionPlanDetailed", {
    type: "object",
    properties: {
      id: { type: "integer" },
      name: { type: "string" },
      code: { type: "string" },
      monthly_order_limit: { type: "integer" },
      ai_spam_limit: { type: "integer" },
      active_pages_limit: { type: "integer" },
      team_members_limit: { type: "integer" },
      store_limit: { type: "integer" },
      data_time_limit: { type: "integer" },
      is_sharing_product: { type: "boolean" },
      mailev: { type: "boolean" },
      is_no_scalev_logo: { type: "boolean" },
      is_custom_domain: { type: "boolean" },
      is_resellership_system: { type: "boolean" },
      is_wa_integration_allowed: { type: "boolean" },
      is_moota_integration_allowed: { type: "boolean" },
      custom_domain_limit: { type: "integer" },
      is_epayment_allowed: { type: "boolean" },
      is_premium_hosting: { type: "boolean" },
      is_courier_aggregator: { type: "boolean" },
      epayment_fee_rate: { oneOf: [{ type: "number" }, { type: "string" }] },
      can_send_whatsapp_messages: { type: "boolean" },
      form_auto_fill: { type: "boolean" },
      is_bank_transfer_allowed: { type: "boolean" },
      is_product_affiliate: { type: "boolean" },
      email_recipients_limit: { type: "integer" }
    }
  });

  setSchema(schemas, "BusinessSubscriptionPlanSimple", {
    type: "object",
    properties: {
      id: { type: "integer" },
      name: { type: "string" },
      code: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessSubscriptionPricingPlanDetailed", {
    type: "object",
    properties: {
      id: { type: "integer" },
      code: { type: "string" },
      subscription_plan: {
        $ref: "#/components/schemas/BusinessSubscriptionPlanDetailed"
      },
      recurring_interval: { type: "string" },
      price: { oneOf: [{ type: "number" }, { type: "string" }] },
      currency: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessSubscriptionPricingPlanSimple", {
    type: "object",
    properties: {
      id: { type: "integer" },
      code: { type: "string" },
      subscription_plan: {
        $ref: "#/components/schemas/BusinessSubscriptionPlanSimple"
      },
      recurring_interval: { type: "string" },
      price: { oneOf: [{ type: "number" }, { type: "string" }] },
      currency: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessSubscriptionRecord", {
    type: "object",
    properties: {
      id: { type: "integer" },
      business: { type: "integer" },
      payment_method: { type: "string" },
      next_payment_method: { type: "string" },
      status: { type: "string" },
      current_period_start: { type: "string", format: "date-time" },
      current_period_end: { type: "string", format: "date-time" },
      latest_subscription_order: {
        $ref: "#/components/schemas/BusinessSubscriptionOrder"
      },
      latest_paid_subscription_order: {
        $ref: "#/components/schemas/BusinessSubscriptionOrder"
      },
      current_pricing_plan: {
        $ref: "#/components/schemas/BusinessSubscriptionPricingPlanDetailed"
      },
      next_pricing_plan: {
        $ref: "#/components/schemas/BusinessSubscriptionPricingPlanSimple"
      },
      next_discount_rate: { oneOf: [{ type: "number" }, { type: "string" }] },
      is_product_affiliate: { type: "boolean" }
    }
  });

  setSchema(schemas, "BusinessSubscriptionResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessSubscriptionRecord" }
    }
  });

  setSchema(schemas, "BusinessSubscriptionListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: {
        type: "object",
        properties: {
          results: {
            type: "array",
            items: { $ref: "#/components/schemas/BusinessSubscriptionRecord" }
          }
        }
      }
    }
  });

  setSchema(schemas, "BusinessSubscriptionUpdateRequest", {
    type: "object",
    required: ["pricing_plan_code"],
    properties: {
      pricing_plan_code: {
        type: "string",
        description: "Target pricing plan code for the authenticated business subscription."
      }
    }
  });

  setSchema(schemas, "BusinessCreateRequest", {
    type: "object",
    required: [
      "account_holder",
      "business_type",
      "username",
      "temp_email",
      "address",
      "location_id",
      "postal_code"
    ],
    properties: {
      account_holder: { type: "string" },
      business_type: { type: "string", enum: ["corporation", "individual"] },
      username: { type: "string" },
      temp_email: {
        oneOf: [{ type: "string", format: "email" }, { type: "string", enum: [""] }],
        description:
          "Email address for the business. Pass an empty string when creating the owner's first business so Nexus can fall back to the owner email."
      },
      phone: { type: "string" },
      address: { type: "string" },
      postal_code: { type: "string" },
      location_id: { type: "integer" },
      description: { type: "string" },
      category_code: { type: "string" },
      website_url: { type: "string", format: "uri" },
      metadata: {
        type: "object",
        additionalProperties: true
      }
    }
  });

  setSchema(schemas, "BusinessApiKeyUpdateRequest", {
    type: "object",
    properties: {
      name: { type: "string" },
      description: { type: "string" },
      scopes: {
        type: "array",
        items: { type: "string" }
      }
    }
  });

  setSchema(schemas, "BusinessCustomerCreateRequest", {
    type: "object",
    required: ["name"],
    properties: {
      name: { type: "string" },
      email: { type: "string", format: "email" },
      phone: { type: "string" },
      date_of_birth: { type: "string", format: "date" }
    }
  });

  setSchema(schemas, "BusinessCustomerUpdateRequest", {
    type: "object",
    properties: {
      name: { type: "string" },
      email: { type: "string", format: "email" },
      phone: { type: "string" },
      date_of_birth: { type: "string", format: "date" },
      status: { type: "string" },
      sex: { type: "string", enum: ["male", "female"] },
      fbp: { type: "string" },
      ttp: { type: "string" },
      is_bounced: { type: "boolean" },
      is_unsubscribe: { type: "boolean" }
    }
  });

  setSchema(schemas, "BusinessCustomerAddressRequest", {
    type: "object",
    properties: {
      name: { type: "string" },
      phone: { type: "string" },
      email: { type: "string", format: "email" },
      address: { type: "string" },
      postal_code: { type: "string" },
      notes: { type: "string" },
      location_id: { type: "integer" }
    }
  });

  setSchema(schemas, "DiscountCodeCreateRequest", {
    type: "object",
    required: ["code", "applied_to", "amount_type"],
    properties: {
      is_enabled: { type: "boolean" },
      code: { type: "string" },
      applied_to: { type: "string", enum: ["product_price", "shipping_cost"] },
      amount_type: { type: "string", enum: ["fixed", "percentage"] },
      percentage: { type: "integer" },
      is_max_amount: { type: "boolean" },
      max_amount: { oneOf: [{ type: "number" }, { type: "string" }] },
      amount: { oneOf: [{ type: "number" }, { type: "string" }] },
      is_usage_limit: { type: "boolean" },
      usage_limit: { type: "integer" },
      is_expiry: { type: "boolean" },
      expiry_time: { type: "string", format: "date-time" },
      is_limited_to_pages: { type: "boolean" },
      page_ids: {
        type: "array",
        items: { type: "integer" }
      },
      is_limited_to_payment_methods: { type: "boolean" },
      payment_methods: {
        type: "array",
        items: { type: "string" }
      },
      is_minimum_revenue: { type: "boolean" },
      minimum_revenue: { oneOf: [{ type: "number" }, { type: "string" }] }
    }
  });

  setSchema(schemas, "DiscountCodeUpdateRequest", {
    type: "object",
    properties: {
      is_enabled: { type: "boolean" },
      code: { type: "string" },
      applied_to: { type: "string", enum: ["product_price", "shipping_cost"] },
      amount_type: { type: "string", enum: ["fixed", "percentage"] },
      percentage: { type: "integer" },
      is_max_amount: { type: "boolean" },
      max_amount: { oneOf: [{ type: "number" }, { type: "string" }] },
      amount: { oneOf: [{ type: "number" }, { type: "string" }] },
      is_usage_limit: { type: "boolean" },
      usage_limit: { type: "integer" },
      is_expiry: { type: "boolean" },
      expiry_time: { type: "string", format: "date-time" },
      is_limited_to_pages: { type: "boolean" },
      page_ids: {
        type: "array",
        items: { type: "integer" }
      },
      is_limited_to_payment_methods: { type: "boolean" },
      payment_methods: {
        type: "array",
        items: { type: "string" }
      },
      is_minimum_revenue: { type: "boolean" },
      minimum_revenue: { oneOf: [{ type: "number" }, { type: "string" }] }
    }
  });

  setSchema(schemas, "MootaIntegrationRequest", {
    type: "object",
    required: ["token"],
    properties: {
      token: { type: "string" }
    }
  });

  setSchema(schemas, "PageCreateRequest", {
    type: "object",
    required: ["name"],
    properties: {
      name: { type: "string" },
      slug: { type: "string" },
      is_published: { type: "boolean" },
      published_at: { type: "string", format: "date-time" },
      is_homepage: { type: "boolean" },
      is_sending_email_invoice: { type: "boolean" },
      is_disable_custom_font: { type: "boolean" },
      is_disable_client_tagging: { type: "boolean" },
      client_analytics_config: {
        type: "string",
        enum: ["head", "body_close_delay", "web_worker"]
      },
      is_pinned: { type: "boolean" },
      current_page_display_id: { type: "integer" },
      store_id: { type: "integer" },
      business_user_ids: {
        type: "array",
        items: { type: "integer" }
      },
      custom_domain_ids: {
        type: "array",
        items: { type: "integer" }
      },
      homepage_custom_domain_ids: {
        type: "array",
        items: { type: "integer" }
      }
    }
  });

  setSchema(schemas, "PageUpdateRequest", {
    type: "object",
    properties: {
      name: { type: "string" },
      slug: { type: "string" },
      is_published: { type: "boolean" },
      published_at: { type: "string", format: "date-time" },
      is_homepage: { type: "boolean" },
      is_sending_email_invoice: { type: "boolean" },
      is_disable_custom_font: { type: "boolean" },
      is_disable_client_tagging: { type: "boolean" },
      client_analytics_config: {
        type: "string",
        enum: ["head", "body_close_delay", "web_worker"]
      },
      is_pinned: { type: "boolean" },
      current_page_display_id: { type: "integer" },
      store_id: { type: "integer" },
      business_user_ids: {
        type: "array",
        items: { type: "integer" }
      },
      custom_domain_ids: {
        type: "array",
        items: { type: "integer" }
      },
      homepage_custom_domain_ids: {
        type: "array",
        items: { type: "integer" }
      }
    }
  });

  setSchema(schemas, "PageDisplayCreateRequest", {
    type: "object",
    required: ["schema_version", "meta", "banner", "header", "general", "sidebar", "main"],
    properties: {
      schema_version: { type: "integer" },
      is_published: { type: "boolean" },
      published_at: { type: "string", format: "date-time" },
      meta: { type: "object", additionalProperties: true },
      banner: { type: "object", additionalProperties: true },
      header: { type: "object", additionalProperties: true },
      general: { type: "object", additionalProperties: true },
      sidebar: {
        type: "array",
        items: { type: "object", additionalProperties: true }
      },
      main: {
        type: "array",
        items: { type: "object", additionalProperties: true }
      },
      fb_pixel_ids: {
        type: "array",
        items: { type: "integer" }
      },
      onload_fb_events: {
        type: "array",
        items: { type: "string" }
      },
      fb_events_onload_parameters: {
        type: "object",
        additionalProperties: true
      },
      tiktok_pixel_ids: {
        type: "array",
        items: { type: "integer" }
      },
      onload_tiktok_events: {
        type: "array",
        items: { type: "string" }
      },
      tiktok_events_onload_parameters: {
        type: "object",
        additionalProperties: true
      },
      kwai_client_pixel_ids: {
        type: "array",
        items: { type: "integer" }
      },
      onload_kwai_client_events: {
        type: "array",
        items: { type: "string" }
      },
      kwai_client_events_onload_parameters: {
        type: "object",
        additionalProperties: true
      },
      kwai_server_pixel_ids: {
        type: "array",
        items: { type: "integer" }
      },
      onload_kwai_server_events: {
        type: "array",
        items: { type: "string" }
      },
      kwai_server_events_onload_parameters: {
        type: "object",
        additionalProperties: true
      },
      gtm_id: { type: "integer" },
      form_display: {
        type: "object",
        additionalProperties: true
      },
      page_buttons: {
        type: "array",
        items: { type: "object", additionalProperties: true }
      }
    }
  });

  setSchema(schemas, "ChannelCreateRequest", {
    type: "object",
    required: ["name"],
    properties: {
      name: { type: "string" },
      utm_source: { type: "string" },
      utm_campaign: { type: "string" },
      utm_content: { type: "string" },
      utm_medium: { type: "string" },
      utm_term: { type: "string" },
      advertiser_id: { type: "integer" }
    }
  });

  setSchema(schemas, "ChannelUpdateRequest", {
    type: "object",
    properties: {
      name: { type: "string" },
      utm_source: { type: "string" },
      utm_campaign: { type: "string" },
      utm_content: { type: "string" },
      utm_medium: { type: "string" },
      utm_term: { type: "string" },
      advertiser_id: { type: "integer" }
    }
  });

  setSchema(schemas, "StorefrontUpdateRequest", {
    type: "object",
    properties: {
      schema_version: { type: "integer" },
      meta: { type: "object", additionalProperties: true },
      header: { type: "object", additionalProperties: true },
      banner: { type: "object", additionalProperties: true },
      general: { type: "object", additionalProperties: true },
      sidebar: {
        type: "array",
        items: { type: "object", additionalProperties: true }
      },
      main: {
        type: "array",
        items: { type: "object", additionalProperties: true }
      },
      type: { type: "string", enum: ["checkout", "home"] },
      custom_html: { type: "string" },
      use_custom_html: { type: "boolean" },
      analytics: {
        type: "object",
        additionalProperties: true
      },
      form_display: {
        type: "object",
        additionalProperties: true
      },
      fb_pixel_ids: {
        type: "array",
        items: { type: "integer" }
      },
      tiktok_pixel_ids: {
        type: "array",
        items: { type: "integer" }
      },
      kwai_client_pixel_ids: {
        type: "array",
        items: { type: "integer" }
      },
      kwai_server_pixel_ids: {
        type: "array",
        items: { type: "integer" }
      },
      gtm_id: { type: "integer" }
    }
  });

  setSchema(schemas, "TrackingPixelCreateRequest", {
    type: "object",
    required: ["name", "pixel_id"],
    properties: {
      name: { type: "string" },
      pixel_id: { type: "string" },
      is_conversion_api: { type: "boolean" },
      conversion_token: { type: "string" },
      test_event_code: { type: "string" },
      errors: {
        type: "array",
        items: { type: "object", additionalProperties: true }
      }
    }
  });

  setSchema(schemas, "TrackingPixelUpdateRequest", {
    type: "object",
    properties: {
      name: { type: "string" },
      pixel_id: { type: "string" },
      is_conversion_api: { type: "boolean" },
      conversion_token: { type: "string" },
      test_event_code: { type: "string" },
      errors: {
        type: "array",
        items: { type: "object", additionalProperties: true }
      }
    }
  });

  setSchema(schemas, "KwaiPixelCreateRequest", {
    type: "object",
    required: ["name", "type", "pixel_id"],
    properties: {
      name: { type: "string" },
      type: { type: "string", enum: ["client", "server"] },
      pixel_id: { type: "string" },
      is_test_mode: { type: "boolean" },
      conversion_token: { type: "string" },
      errors: {
        type: "array",
        items: { type: "object", additionalProperties: true }
      }
    }
  });

  setSchema(schemas, "KwaiPixelUpdateRequest", {
    type: "object",
    properties: {
      name: { type: "string" },
      type: { type: "string", enum: ["client", "server"] },
      pixel_id: { type: "string" },
      is_test_mode: { type: "boolean" },
      conversion_token: { type: "string" },
      errors: {
        type: "array",
        items: { type: "object", additionalProperties: true }
      }
    }
  });

  setSchema(schemas, "GtmCreateRequest", {
    type: "object",
    required: ["name", "container_id"],
    properties: {
      name: { type: "string" },
      container_id: { type: "string" }
    }
  });

  setSchema(schemas, "GtmUpdateRequest", {
    type: "object",
    properties: {
      name: { type: "string" },
      container_id: { type: "string" }
    }
  });

  setSchema(schemas, "VariantCourseUpdateRequest", {
    type: "object",
    properties: {
      is_checked: { type: "boolean" },
      course_settings: {
        type: "object",
        additionalProperties: true
      }
    }
  });

  setSchema(schemas, "CourseSectionCreateRequest", {
    type: "object",
    required: ["title", "sequence_order", "is_active", "is_shown"],
    properties: {
      title: { type: "string" },
      sequence_order: { type: "integer" },
      is_active: { type: "boolean" },
      is_shown: { type: "boolean" },
      type: { type: "string", enum: ["regular", "agreement"] }
    }
  });

  setSchema(schemas, "CourseSectionUpdateRequest", {
    type: "object",
    properties: {
      title: { type: "string" },
      is_shown: { type: "boolean" },
      type: { type: "string", enum: ["regular", "agreement"] }
    }
  });

  setSchema(schemas, "CourseContentCreateRequest", {
    type: "object",
    required: ["title", "sequence_order", "is_active", "is_shown"],
    properties: {
      title: { type: "string" },
      text: { type: "string" },
      type: { type: "string", enum: ["video", "text"] },
      duration: { type: "integer" },
      video_url: { type: "string" },
      sequence_order: { type: "integer" },
      is_active: { type: "boolean" },
      is_shown: { type: "boolean" },
      topic_uuid: { type: "string", format: "uuid" }
    }
  });

  setSchema(schemas, "CourseContentUpdateRequest", {
    type: "object",
    properties: {
      title: { type: "string" },
      text: { type: "string" },
      type: { type: "string", enum: ["video", "text"] },
      duration: { type: "integer" },
      video_url: { type: "string" },
      is_shown: { type: "boolean" }
    }
  });

  setSchema(schemas, "WarehouseCreateRequest", {
    type: "object",
    required: ["name"],
    properties: {
      name: { type: "string" },
      contact_name: { type: "string" },
      contact_phone: { type: "string" },
      warehouse_admin_ids: {
        type: "array",
        items: { type: "integer" }
      },
      is_active: { type: "boolean" },
      is_same_city_delivery: { type: "boolean" },
      same_city_delivery_fee: { oneOf: [{ type: "number" }, { type: "string" }] },
      warehouse_address_id: { type: "integer" }
    }
  });

  setSchema(schemas, "WarehouseUpdateRequest", {
    type: "object",
    properties: {
      name: { type: "string" },
      contact_name: { type: "string" },
      contact_phone: { type: "string" },
      warehouse_admin_ids: {
        type: "array",
        items: { type: "integer" }
      },
      is_active: { type: "boolean" },
      is_same_city_delivery: { type: "boolean" },
      same_city_delivery_fee: { oneOf: [{ type: "number" }, { type: "string" }] },
      warehouse_address_id: { type: "integer" }
    }
  });

  setSchema(schemas, "BusinessLogoUploadRequest", {
    type: "object",
    required: ["logo"],
    properties: {
      logo: {
        type: "string",
        format: "binary",
        description: "Logo file to upload for the currently selected business."
      }
    }
  });

  setSchema(schemas, "BusinessVerificationPaymentRequest", {
    type: "object",
    properties: {
      payment_method: {
        type: "string",
        enum: ["invoice", "volt"],
        description:
          "Verification payment method. Omit or use `invoice` to create an invoice-backed order, or use `volt` to consume Volt balance."
      }
    }
  });

  setSchema(schemas, "XenditManagedAccountCreateRequest", {
    type: "object",
    required: ["email"],
    properties: {
      email: {
        type: "string",
        format: "email",
        description: "Email address to register for the Xendit managed account invitation."
      }
    }
  });

  setSchema(schemas, "XenditManagedAccountUpdateRequest", {
    type: "object",
    properties: {
      email: {
        type: "string",
        format: "email",
        description: "Updated invitation email address while the account is still in draft."
      },
      payment_methods: {
        type: "array",
        items: {
          type: "string",
          enum: ["va", "card", "qris", "invoice", "alfamart", "ovo", "dana", "shopeepay", "linkaja"]
        }
      },
      vas: {
        type: "array",
        items: {
          type: "string",
          enum: ["BCA", "BNI", "BRI", "MANDIRI", "PERMATA", "BSI", "BJB", "CIMB", "SAHABAT_SAMPOERNA"]
        }
      }
    }
  });

  setSchema(schemas, "BusinessPgAccountRequest", {
    type: "object",
    required: ["provider", "payment_method"],
    properties: {
      provider: {
        type: "string",
        enum: ["duitku", "midtrans", "ipaymu"]
      },
      payment_method: {
        type: "string",
        enum: ["card", "va", "qris", "invoice", "alfamart", "ovo", "dana", "shopeepay", "linkaja", "gopay", "indomaret"]
      },
      sub_payment_method: {
        type: "string",
        description: "Virtual-account bank code when `payment_method` is `va`."
      },
      status: {
        type: "string",
        description: "Gateway-account status override."
      }
    }
  });

  setSchema(schemas, "BusinessEpaymentMethodRequest", {
    type: "object",
    properties: {
      provider: {
        type: "string",
        enum: ["ipaymu", "scalev"]
      },
      payment_method: {
        type: "string",
        description: "Payment method to remove or switch."
      },
      va: {
        type: "string",
        description: "Virtual-account bank code to remove or switch."
      }
    },
    oneOf: [{ required: ["provider", "payment_method"] }, { required: ["provider", "va"] }]
  });

  setSchema(schemas, "BlockedIpCreateRequest", {
    type: "object",
    required: ["ip", "reason"],
    properties: {
      ip: { type: "string" },
      reason: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessCourierRequest", {
    type: "object",
    required: ["courier_id", "courier_aggregator_id"],
    properties: {
      courier_id: { type: "integer" },
      courier_aggregator_id: { type: "integer" }
    }
  });

  setSchema(schemas, "BusinessCourierAggregatorRequest", {
    type: "object",
    required: ["courier_aggregator_id", "api_key"],
    properties: {
      courier_aggregator_id: { type: "integer" },
      api_key: { type: "string" }
    }
  });

  setSchema(schemas, "FinalizeXenditManagedAccountRequest", {
    type: "object",
    required: ["token"],
    additionalProperties: false,
    properties: {
      token: {
        type: "string",
        description: "Verification token issued by Xendit for finalizing the managed account."
      }
    }
  });

  setSchema(schemas, "TagsUpdateRequest", {
    type: "object",
    required: ["tags"],
    additionalProperties: false,
    properties: {
      tags: {
        type: "array",
        description: "Ordered tag list to persist for the target resource.",
        items: {
          type: "string"
        }
      }
    }
  });

  setSchema(schemas, "DigitalProductFileUploadRequest", {
    type: "object",
    required: ["filename", "content_type", "content_length", "is_public"],
    additionalProperties: false,
    properties: {
      filename: { type: "string" },
      content_type: { type: "string" },
      content_length: { type: "integer" },
      is_public: { type: "boolean" }
    }
  });

  setSchema(schemas, "CourseSectionOrderUpdateRequest", {
    type: "object",
    required: ["course_section_uuids"],
    additionalProperties: false,
    properties: {
      course_section_uuids: {
        type: "array",
        items: { type: "string", format: "uuid" }
      }
    }
  });

  setSchema(schemas, "CourseContentOrderUpdateRequest", {
    type: "object",
    required: ["course_content_uuids"],
    additionalProperties: false,
    properties: {
      course_content_uuids: {
        type: "array",
        items: { type: "string", format: "uuid" }
      }
    }
  });

  setSchema(schemas, "BusinessClassicPayoutRequest", {
    type: "object",
    required: ["otp", "amount"],
    additionalProperties: false,
    properties: {
      otp: { type: "string" },
      amount: { oneOf: [{ type: "number" }, { type: "string" }] }
    }
  });

  setSchema(schemas, "BusinessXpPayoutRequest", {
    type: "object",
    required: ["otp"],
    additionalProperties: false,
    properties: {
      otp: { type: "string" },
      amount: { oneOf: [{ type: "number" }, { type: "string" }] },
      xp_type: { type: "string", nullable: true }
    }
  });

  setSchema(schemas, "ChatbotCreditCalculationRequest", {
    type: "object",
    required: ["credit"],
    additionalProperties: false,
    properties: {
      credit: { oneOf: [{ type: "integer" }, { type: "string" }] }
    }
  });

  setSchema(schemas, "CustomerCsvUploadRequest", {
    type: "object",
    required: ["file"],
    additionalProperties: false,
    properties: {
      file: {
        type: "string",
        format: "binary",
        description: "CSV file to import. Nexus accepts `text/csv` uploads up to 100 KB."
      }
    }
  });

  setSchema(schemas, "PartnershipRequestCreateRequest", {
    type: "object",
    required: ["partnership_type"],
    additionalProperties: false,
    properties: {
      partnership_type: {
        type: "string",
        enum: ["affiliate", "affiliate_pro", "reseller"]
      },
      message_to_product_owner: { type: "string", nullable: true },
      store_ids: {
        type: "array",
        items: { oneOf: [{ type: "integer" }, { type: "string" }] }
      },
      custom_domain_ids: {
        type: "array",
        items: { oneOf: [{ type: "integer" }, { type: "string" }] }
      }
    }
  });

  setSchema(schemas, "PartnershipApproveRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      store_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      custom_domain_ids: {
        type: "array",
        items: { oneOf: [{ type: "integer" }, { type: "string" }] }
      }
    }
  });

  setSchema(schemas, "PartnershipActionCheckRequest", {
    type: "object",
    required: ["action"],
    additionalProperties: false,
    properties: {
      action: {
        type: "string",
        enum: ["ban", "delete"]
      }
    }
  });

  setSchema(schemas, "ProductPartnershipChangeCheckRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      intended_changes: {
        type: "object",
        additionalProperties: { $ref: "#/components/schemas/GenericValue" }
      }
    }
  });

  setSchema(schemas, "VoltPreviewRequest", {
    type: "object",
    additionalProperties: false,
    properties: {
      amount: { oneOf: [{ type: "number" }, { type: "string" }] }
    }
  });

  setSchema(schemas, "CurrentBusinessUserUpdateRequest", {
    type: "object",
    properties: {
      metadata: {
        type: "object",
        additionalProperties: true
      },
      business_phone: { type: "string" },
      sidebar_menus: {
        type: "array",
        items: { type: "string" }
      },
      is_tg_public_order: { type: "boolean" },
      is_tg_private_order: { type: "boolean" },
      is_tg_draft: { type: "boolean" },
      is_tg_pending: { type: "boolean" },
      is_tg_paid: { type: "boolean" }
    }
  });

  setSchema(schemas, "TeamMemberCreateRequest", {
    type: "object",
    required: ["email", "role_id"],
    properties: {
      email: { type: "string", format: "email" },
      role_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      business_phone: { type: "string" },
      is_locked: { type: "boolean" },
      is_tg_public_order: { type: "boolean" },
      is_tg_private_order: { type: "boolean" },
      is_tg_draft: { type: "boolean" },
      is_tg_pending: { type: "boolean" },
      is_tg_paid: { type: "boolean" },
      sidebar_menus: {
        type: "array",
        items: { type: "string" }
      },
      metadata: {
        type: "object",
        additionalProperties: true
      },
      bank_account_holder: { type: "string" },
      bank_account_number: { type: "string" },
      financial_entity_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      store_ids: {
        type: "array",
        items: { type: "integer" }
      },
      warehouse_ids: {
        type: "array",
        items: { type: "integer" }
      }
    }
  });

  setSchema(schemas, "TeamMemberUpdateRequest", {
    type: "object",
    properties: {
      role_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      business_phone: { type: "string" },
      is_locked: { type: "boolean" },
      is_available: { type: "boolean" },
      financial_entity_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      bank_account_number: { type: "string" },
      bank_account_holder: { type: "string" },
      store_ids: {
        type: "array",
        items: { type: "integer" }
      },
      warehouse_ids: {
        type: "array",
        items: { type: "integer" }
      }
    }
  });

  setSchema(schemas, "PaymentAccountCreateRequest", {
    type: "object",
    required: ["account_holder", "method", "financial_entity_id"],
    properties: {
      account_number: { type: "string" },
      account_holder: { type: "string" },
      method: { type: "string" },
      financial_entity_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      financial_entity_code: { type: "string" },
      financial_entity_name: { type: "string" }
    }
  });

  setSchema(schemas, "PaymentAccountUpdateRequest", {
    type: "object",
    properties: {
      account_number: { type: "string" },
      account_holder: { type: "string" }
    }
  });

  setSchema(schemas, "UserPayoutInfoRequest", {
    type: "object",
    required: ["channel_code", "account_holder_name", "account_number"],
    properties: {
      channel_code: { type: "string" },
      account_holder_name: { type: "string" },
      account_number: { type: "string" }
    }
  });

  setSchema(schemas, "UserTermsPrivacyRequest", {
    type: "object",
    properties: {
      base_terms_version: { type: "string", format: "date" },
      base_privacy_version: { type: "string", format: "date" },
      verification_privacy_version: { type: "string", format: "date" }
    }
  });

  setSchema(schemas, "UserAvatarUploadRequest", {
    type: "object",
    required: ["avatar"],
    properties: {
      avatar: {
        type: "string",
        format: "binary",
        description: "Avatar image to upload for the authenticated user."
      }
    }
  });

  setSchema(schemas, "NinjaPluginIntegrationRequest", {
    type: "object",
    required: ["code", "state"],
    properties: {
      code: { type: "string" },
      state: { type: "string" }
    }
  });

  setSchema(schemas, "NinjaPluginUpdateRequest", {
    type: "object",
    required: ["client_secret"],
    properties: {
      client_secret: { type: "string" }
    }
  });

  setSchema(schemas, "IpaymuRegisterRequest", {
    type: "object",
    required: ["name", "email", "phone", "password"],
    properties: {
      name: { type: "string" },
      email: { type: "string", format: "email" },
      phone: { type: "string" },
      password: { type: "string" }
    }
  });

  setSchema(schemas, "VoltOrderCreateRequest", {
    type: "object",
    required: ["amount", "payment_method"],
    properties: {
      amount: { oneOf: [{ type: "integer" }, { type: "string" }] },
      payment_method: { type: "string", enum: ["balance", "invoice"] },
      metadata: {
        type: "object",
        additionalProperties: true
      }
    }
  });

  setSchema(schemas, "WakakaRegisterRequest", {
    type: "object",
    properties: {
      ig_handle: { type: "string" },
      whatsapp_number: { type: "string" },
      fb_user_id: { type: "string" }
    },
    oneOf: [{ required: ["ig_handle"] }, { required: ["whatsapp_number"] }, { required: ["fb_user_id"] }]
  });

  setSchema(schemas, "XenditAccountHolderAddressRequest", {
    type: "object",
    properties: {
      country: { type: "string" },
      district: { type: "string" },
      sub_district: { type: "string" },
      street_line1: { type: "string" },
      street_line2: { type: "string" },
      city: { type: "string" },
      province_state: { type: "string" },
      postal_code: { type: "string" }
    },
    additionalProperties: true
  });

  setSchema(schemas, "XenditAccountHolderIndividualAddressRequest", {
    type: "object",
    properties: {
      country: { type: "string" },
      district: { type: "string" },
      street_line1: { type: "string" },
      street_line2: { type: "string" },
      city: { type: "string" },
      province_state: { type: "string" },
      postal_code: { type: "string" }
    },
    additionalProperties: true
  });

  setSchema(schemas, "XenditAccountHolderIndividualDetailRequest", {
    type: "object",
    properties: {
      ktp_number: { type: "string" },
      passport_number: { type: "string" },
      given_names: { type: "string" },
      surname: { type: "string" },
      phone_number: { type: "string" },
      email: { type: "string", format: "email" },
      nationality: { type: "string" },
      place_of_birth: { type: "string" },
      date_of_birth: { type: "string" },
      gender: { type: "string" },
      tax_identification_number: { type: "string" },
      type: { type: "string" },
      role: { type: "string" },
      address: { $ref: "#/components/schemas/XenditAccountHolderIndividualAddressRequest" }
    },
    additionalProperties: true
  });

  setSchema(schemas, "XenditAccountHolderBusinessDetailRequest", {
    type: "object",
    properties: {
      type: { type: "string" },
      legal_name: { type: "string" },
      trading_name: { type: "string" },
      description: { type: "string" },
      industry_category: { type: "string" },
      tax_identification_number: { type: "string" },
      identification_number: { type: "string" },
      initial_deed_of_establishment_status: { type: "string" },
      date_of_registration: { type: "string" },
      country_of_operation: { type: "string" }
    },
    additionalProperties: true
  });

  setSchema(schemas, "XenditAccountHolderKycDocumentRequest", {
    type: "object",
    properties: {
      country: { type: "string" },
      type: { type: "string" },
      expires_at: { type: "string" },
      file_id: { type: "string" }
    },
    additionalProperties: true
  });

  setSchema(schemas, "XenditAccountHolderRequest", {
    type: "object",
    description:
      "Xendit account holder payload for the authenticated business. Nexus validates this payload against its embedded Xendit account holder schema before forwarding it upstream.",
    properties: {
      website_url: { type: "string", format: "uri" },
      phone_number: { type: "string" },
      email: { type: "string", format: "email" },
      business_detail: { $ref: "#/components/schemas/XenditAccountHolderBusinessDetailRequest" },
      individual_details: {
        type: "array",
        items: { $ref: "#/components/schemas/XenditAccountHolderIndividualDetailRequest" }
      },
      address: { $ref: "#/components/schemas/XenditAccountHolderAddressRequest" },
      kyc_documents: {
        type: "array",
        items: { $ref: "#/components/schemas/XenditAccountHolderKycDocumentRequest" }
      }
    },
    additionalProperties: true
  });

  setSchema(schemas, "BusinessBalancePayload", {
    type: "object",
    properties: {
      pending_balance: { type: "string" },
      available_balance: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessBalanceResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessBalancePayload" }
    }
  });

  setSchema(schemas, "BusinessBalanceHistoryItem", {
    type: "object",
    properties: {
      id: { type: "integer" },
      created_at: { type: "string", format: "date-time", nullable: true },
      amount: { type: "string" },
      balance_type: {
        type: "string",
        enum: ["pending", "available"],
        nullable: true
      },
      balance_before: { type: "string" },
      balance_after: { type: "string" },
      description: { type: "string", nullable: true },
      business_transaction_uuid: { type: "string", format: "uuid", nullable: true },
      business_transaction_invoice_id: { type: "string", nullable: true },
      business_transaction_secret: { type: "string", nullable: true }
    }
  });

  setSchema(schemas, "BusinessBalanceHistoryListData", {
    type: "object",
    properties: {
      count: { type: "integer" },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessBalanceHistoryItem" }
      }
    }
  });

  setSchema(schemas, "BusinessBalanceHistoryListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessBalanceHistoryListData" }
    }
  });

  setSchema(schemas, "MachineApiLogApiKeySummary", {
    type: "object",
    properties: {
      id: { type: "integer" },
      name: { type: "string", nullable: true },
      key_type: { type: "string", nullable: true }
    }
  });

  setSchema(schemas, "MachineApiLogOAuthApplicationSummary", {
    type: "object",
    properties: {
      id: { type: "integer" },
      name: { type: "string", nullable: true },
      client_id: { type: "string", nullable: true }
    }
  });

  setSchema(schemas, "MachineApiLogListEntry", {
    type: "object",
    properties: {
      id: { type: "string", format: "uuid" },
      request_id: { type: "string" },
      timestamp: { type: "string", format: "date-time", nullable: true },
      timestamp_end: { type: "string", format: "date-time", nullable: true },
      request_method: { type: "string" },
      request_base_url: { type: "string" },
      response_status: { type: "integer" },
      auth_method: { type: "string", nullable: true },
      auth_user_id: { type: "integer", nullable: true },
      billing_tag: { type: "string", nullable: true },
      billing_idempotency_key: { type: "string", nullable: true },
      billing_reservation_id: { type: "string", nullable: true },
      billing_currency: { type: "string", nullable: true },
      billing_status: { type: "string", nullable: true },
      billing_charge_id: { type: "string", nullable: true },
      api_key: {
        allOf: [{ $ref: "#/components/schemas/MachineApiLogApiKeySummary" }],
        nullable: true
      },
      oauth_application: {
        allOf: [{ $ref: "#/components/schemas/MachineApiLogOAuthApplicationSummary" }],
        nullable: true
      },
      oauth_authorized_business_id: { type: "integer", nullable: true }
    }
  });

  setSchema(schemas, "MachineApiLog", {
    allOf: [
      { $ref: "#/components/schemas/MachineApiLogListEntry" },
      {
        type: "object",
        properties: {
          request_query: { type: "string", nullable: true },
          request_headers: {
            type: "object",
            additionalProperties: true
          },
          request_body: { type: "string", nullable: true },
          response_headers: {
            type: "object",
            additionalProperties: true
          },
          response_body: { type: "string", nullable: true }
        }
      }
    ]
  });

  setSchema(schemas, "MachineApiLogListData", {
    type: "object",
    properties: {
      has_next: { type: "boolean" },
      last_id: { type: "string", format: "uuid", nullable: true },
      page_size: { type: "integer", nullable: true },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/MachineApiLogListEntry" }
      }
    }
  });

  setSchema(schemas, "MachineApiLogResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/MachineApiLog" }
    }
  });

  setSchema(schemas, "MachineApiLogListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/MachineApiLogListData" }
    }
  });

  setSchema(schemas, "OAuthApplicationBillingTag", {
    type: "object",
    properties: {
      id: { type: "integer" },
      tag_code: { type: "string" },
      label: { type: "string" },
      price: { type: "integer" },
      currency: { type: "string" },
      action_key: { type: "string" },
      is_available_for_new_approvals: { type: "boolean" }
    }
  });

  setSchema(schemas, "OAuthApplicationApprovedBillingTag", {
    type: "object",
    properties: {
      billing_tag_id: { type: "integer" },
      tag_code: { type: "string" },
      label: { type: "string" },
      price: { type: "integer" },
      currency: { type: "string" },
      action_key: { type: "string" }
    }
  });

  setSchema(schemas, "OwnedOAuthApplication", {
    type: "object",
    properties: {
      id: { type: "integer" },
      client_id: { type: "string" },
      client_secret: { type: "string" },
      name: { type: "string" },
      description: { type: "string", nullable: true },
      logo_url: { type: "string", format: "uri", nullable: true },
      homepage_url: { type: "string", format: "uri", nullable: true },
      redirect_uri: { type: "string", format: "uri" },
      manage_url: { type: "string", format: "uri", nullable: true },
      available_scopes: {
        type: "array",
        items: { type: "string" }
      },
      billing_tags: {
        type: "array",
        items: { $ref: "#/components/schemas/OAuthApplicationBillingTag" }
      },
      webhook_status: { type: "string", nullable: true },
      webhook_events: {
        type: "array",
        items: { type: "string" }
      },
      whitelisted_ips: {
        type: "array",
        items: { type: "string" }
      },
      is_verified: { type: "boolean" }
    }
  });

  setSchema(schemas, "OwnedOAuthApplicationDetail", {
    allOf: [
      { $ref: "#/components/schemas/OwnedOAuthApplication" },
      {
        type: "object",
        properties: {
          authorized_business_limit: { type: "integer", nullable: true },
          authorized_business_count: { type: "integer", nullable: true }
        }
      }
    ]
  });

  setSchema(schemas, "AuthorizedApplicationOAuthApplication", {
    type: "object",
    properties: {
      id: { type: "integer" },
      client_id: { type: "string" },
      name: { type: "string" },
      description: { type: "string", nullable: true },
      logo_url: { type: "string", format: "uri", nullable: true },
      homepage_url: { type: "string", format: "uri", nullable: true },
      redirect_uri: { type: "string", format: "uri" },
      available_scopes: {
        type: "array",
        items: { type: "string" }
      },
      billing_tags: {
        type: "array",
        items: { $ref: "#/components/schemas/OAuthApplicationBillingTag" }
      },
      webhook_status: { type: "string", nullable: true },
      webhook_events: {
        type: "array",
        items: { type: "string" }
      },
      business: {
        allOf: [{ $ref: "#/components/schemas/BusinessSimple" }],
        nullable: true
      },
      is_verified: { type: "boolean" }
    }
  });

  setSchema(schemas, "AuthorizedApplication", {
    type: "object",
    properties: {
      id: { type: "integer" },
      application: { $ref: "#/components/schemas/AuthorizedApplicationOAuthApplication" },
      authorized_business_id: { type: "integer" },
      authorized_by: {
        allOf: [{ $ref: "#/components/schemas/UserSimple" }],
        nullable: true
      },
      is_enabled: { type: "boolean" },
      scopes: {
        type: "array",
        items: { type: "string" }
      },
      approved_billing_tags: {
        type: "array",
        items: { $ref: "#/components/schemas/OAuthApplicationApprovedBillingTag" }
      },
      webhook_status: { type: "string", nullable: true },
      webhook_events: {
        type: "array",
        items: { type: "string" }
      },
      manage_launch_available: { type: "boolean" },
      inserted_at: { type: "string", format: "date-time", nullable: true },
      updated_at: { type: "string", format: "date-time", nullable: true }
    }
  });

  setSchema(schemas, "OwnedOAuthApplicationListData", {
    type: "object",
    properties: {
      has_next: { type: "boolean" },
      last_id: { type: "integer", nullable: true },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/OwnedOAuthApplication" }
      }
    }
  });

  setSchema(schemas, "OwnedOAuthApplicationResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/OwnedOAuthApplicationDetail" }
    }
  });

  setSchema(schemas, "OwnedOAuthApplicationListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/OwnedOAuthApplicationListData" }
    }
  });

  setSchema(schemas, "AuthorizedApplicationListData", {
    type: "object",
    properties: {
      has_next: { type: "boolean" },
      last_id: { type: "integer", nullable: true },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/AuthorizedApplication" }
      }
    }
  });

  setSchema(schemas, "AuthorizedApplicationResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/AuthorizedApplication" }
    }
  });

  setSchema(schemas, "AuthorizedApplicationListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/AuthorizedApplicationListData" }
    }
  });

  setSchema(schemas, "AuthorizedApplicationManageLink", {
    type: "object",
    properties: {
      launch_url: { type: "string", format: "uri" },
      expires_at: { type: "string", format: "date-time" }
    }
  });

  setSchema(schemas, "AuthorizedApplicationManageLinkResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/AuthorizedApplicationManageLink" }
    }
  });

  setSchema(schemas, "OAuthBillingReservationRequest", {
    type: "object",
    required: ["action_key", "billing_idempotency_key", "billing_tag"],
    properties: {
      billing_tag: { type: "string" },
      billing_idempotency_key: { type: "string" },
      action_key: { type: "string" }
    }
  });

  setSchema(schemas, "OAuthBillingReservationResult", {
    type: "object",
    properties: {
      reservation_id: { type: "string" },
      billing_tag: { type: "string" },
      action_key: { type: "string" },
      price: { type: "integer" },
      currency: { type: "string" },
      expires_at: { type: "string", format: "date-time", nullable: true },
      billing_status: { type: "string" },
      released_at: { type: "string", format: "date-time", nullable: true }
    }
  });

  setSchema(schemas, "OAuthBillingReservationResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/OAuthBillingReservationResult" }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingEarnings", {
    type: "object",
    properties: {
      balance: { type: "integer" },
      currency: { type: "string", enum: ["IDR"] }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingEarningsResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessOAuthBillingEarnings" }
    }
  });

  setSchema(schemas, "OAuthBillingAction", {
    type: "object",
    properties: {
      action_key: { type: "string" },
      label: { type: "string", nullable: true },
      description: { type: "string", nullable: true },
      endpoint_templates: {
        type: "array",
        items: { type: "string" }
      },
      required_scopes: {
        type: "array",
        items: { type: "string" }
      },
      reservation_required: { type: "boolean", nullable: true },
      capture_rule: { type: "string", nullable: true }
    }
  });

  setSchema(schemas, "OAuthBillingActionListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: {
        type: "array",
        items: { $ref: "#/components/schemas/OAuthBillingAction" }
      }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingReservationListEntry", {
    type: "object",
    properties: {
      id: { type: "string", format: "uuid" },
      timestamp: { type: "string", format: "date-time", nullable: true },
      expires_at: { type: "string", format: "date-time", nullable: true },
      released_at: { type: "string", format: "date-time", nullable: true },
      captured_at: { type: "string", format: "date-time", nullable: true },
      billing_status: {
        type: "string",
        enum: ["active", "consuming", "captured", "released"],
        nullable: true
      },
      billing_tag: { type: "string", nullable: true },
      billing_idempotency_key: { type: "string", nullable: true },
      action_key: { type: "string", nullable: true },
      amount: { type: "integer", nullable: true },
      currency: { type: "string", enum: ["IDR"], nullable: true },
      released_reason: { type: "string", nullable: true },
      charge_id: { type: "string", format: "uuid", nullable: true },
      oauth_application_id: { type: "integer", nullable: true },
      oauth_authorized_business_id: { type: "integer", nullable: true },
      merchant_business_id: { type: "integer", nullable: true },
      developer_business_id: { type: "integer", nullable: true }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingReservation", {
    allOf: [
      { $ref: "#/components/schemas/BusinessOAuthBillingReservationListEntry" },
      {
        type: "object",
        properties: {
          metadata: {
            type: "object",
            additionalProperties: true
          }
        }
      }
    ]
  });

  setSchema(schemas, "BusinessOAuthBillingReservationListData", {
    type: "object",
    properties: {
      has_next: { type: "boolean" },
      last_id: { type: "string", format: "uuid", nullable: true },
      page_size: { type: "integer", nullable: true },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessOAuthBillingReservationListEntry" }
      }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingReservationListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessOAuthBillingReservationListData" }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingReservationResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessOAuthBillingReservation" }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingChargeListEntry", {
    type: "object",
    properties: {
      id: { type: "string", format: "uuid" },
      timestamp: { type: "string", format: "date-time", nullable: true },
      captured_at: { type: "string", format: "date-time", nullable: true },
      billing_tag: { type: "string", nullable: true },
      billing_idempotency_key: { type: "string", nullable: true },
      action_key: { type: "string", nullable: true },
      gross_amount: { type: "integer", nullable: true },
      platform_fee_bps: { type: "integer", nullable: true },
      platform_fee_amount: { type: "integer", nullable: true },
      developer_net_amount: { type: "integer", nullable: true },
      currency: { type: "string", enum: ["IDR"], nullable: true },
      reservation_id: { type: "string", format: "uuid", nullable: true },
      request_id: { type: "string", nullable: true },
      oauth_application_id: { type: "integer", nullable: true },
      oauth_authorized_business_id: { type: "integer", nullable: true },
      merchant_business_id: { type: "integer", nullable: true },
      developer_business_id: { type: "integer", nullable: true }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingCharge", {
    allOf: [
      { $ref: "#/components/schemas/BusinessOAuthBillingChargeListEntry" },
      {
        type: "object",
        properties: {
          metadata: {
            type: "object",
            additionalProperties: true
          }
        }
      }
    ]
  });

  setSchema(schemas, "BusinessOAuthBillingChargeListData", {
    type: "object",
    properties: {
      has_next: { type: "boolean" },
      last_id: { type: "string", format: "uuid", nullable: true },
      page_size: { type: "integer", nullable: true },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessOAuthBillingChargeListEntry" }
      }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingChargeListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessOAuthBillingChargeListData" }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingChargeResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessOAuthBillingCharge" }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingLedgerEntry", {
    type: "object",
    properties: {
      id: { type: "string", format: "uuid" },
      timestamp: { type: "string", format: "date-time", nullable: true },
      entry_type: { type: "string", nullable: true },
      amount: { type: "integer", nullable: true },
      currency: { type: "string", enum: ["IDR"], nullable: true },
      balance_before: { type: "integer", nullable: true },
      balance_after: { type: "integer", nullable: true },
      description: { type: "string", nullable: true },
      charge_id: { type: "string", format: "uuid", nullable: true },
      settlement_id: { type: "string", format: "uuid", nullable: true },
      business_id: { type: "integer", nullable: true },
      oauth_application_id: { type: "integer", nullable: true },
      metadata: {
        type: "object",
        additionalProperties: true
      }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingLedgerListData", {
    type: "object",
    properties: {
      has_next: { type: "boolean" },
      last_id: { type: "string", format: "uuid", nullable: true },
      page_size: { type: "integer", nullable: true },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessOAuthBillingLedgerEntry" }
      }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingLedgerListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessOAuthBillingLedgerListData" }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingSettlement", {
    type: "object",
    properties: {
      id: { type: "string", format: "uuid" },
      timestamp: { type: "string", format: "date-time", nullable: true },
      settlement_rail: {
        type: "string",
        enum: ["xendit", "ipaymu"],
        nullable: true
      },
      status: {
        type: "string",
        enum: ["success", "failed"],
        nullable: true
      },
      amount: { type: "integer", nullable: true },
      currency: { type: "string", enum: ["IDR"], nullable: true },
      balance_before: { type: "integer", nullable: true },
      balance_after: { type: "integer", nullable: true },
      description: { type: "string", nullable: true },
      xendit_transfer_id: { type: "string", nullable: true },
      ipaymu_reference_id: { type: "string", nullable: true },
      ipaymu_related_id: { type: "string", nullable: true },
      business_id: { type: "integer", nullable: true },
      metadata: {
        type: "object",
        additionalProperties: true
      }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingSettlementListData", {
    type: "object",
    properties: {
      has_next: { type: "boolean" },
      last_id: { type: "string", format: "uuid", nullable: true },
      page_size: { type: "integer", nullable: true },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessOAuthBillingSettlement" }
      }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingSettlementListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessOAuthBillingSettlementListData" }
    }
  });

  setSchema(schemas, "BusinessOAuthBillingSettlementResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessOAuthBillingSettlement" }
    }
  });

  setSchema(schemas, "OAuthBillingWithdrawalRequest", {
    type: "object",
    required: ["amount", "settlement_rail"],
    properties: {
      amount: { type: "integer", minimum: 1 },
      settlement_rail: {
        type: "string",
        enum: ["xendit", "ipaymu"]
      }
    }
  });

  setSchema(schemas, "BusinessApiKey", {
    type: "object",
    properties: {
      id: { type: "integer" },
      name: { type: "string" },
      description: { type: "string", nullable: true },
      key_type: { type: "string" },
      scopes: {
        type: "array",
        items: { type: "string" }
      },
      last_used_at: { type: "string", format: "date-time", nullable: true },
      expires_at: { type: "string", format: "date-time", nullable: true },
      is_expired: { type: "boolean" },
      usage_count: { type: "integer", nullable: true },
      rate_limit_per_hour: { type: "integer", nullable: true },
      business_id: { type: "integer" },
      created_by: {
        allOf: [{ $ref: "#/components/schemas/UserSimple" }],
        nullable: true
      },
      inserted_at: { type: "string", format: "date-time", nullable: true },
      updated_at: { type: "string", format: "date-time", nullable: true },
      api_key: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessApiKeyListData", {
    type: "object",
    properties: {
      has_next: { type: "boolean" },
      last_id: { type: "integer", nullable: true },
      page_size: { type: "integer", nullable: true },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/BusinessApiKey" }
      }
    }
  });

  setSchema(schemas, "BusinessApiKeyResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessApiKey" }
    }
  });

  setSchema(schemas, "BusinessApiKeyListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessApiKeyListData" }
    }
  });

  setSchema(schemas, "BusinessPayoutTarget", {
    type: "object",
    properties: {
      id: { type: "integer" },
      channel_code: { type: "string" },
      account_holder_name: { type: "string" },
      account_number: { type: "string" },
      business_id: { type: "integer" }
    }
  });

  setSchema(schemas, "BusinessPayoutTargetRequest", {
    type: "object",
    required: ["account_holder_name", "account_number", "channel_code"],
    properties: {
      channel_code: { type: "string" },
      account_holder_name: { type: "string" },
      account_number: { type: "string" }
    }
  });

  setSchema(schemas, "BusinessPayoutTargetResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessPayoutTarget" }
    }
  });

  setSchema(schemas, "BusinessXpBalance", {
    type: "object",
    properties: {
      balance: { type: "integer" }
    }
  });

  setSchema(schemas, "BusinessXpBalanceResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/BusinessXpBalance" }
    }
  });

  setSchema(schemas, "XenditFee", {
    type: "object",
    properties: {
      xendit_fee: { type: "integer", nullable: true },
      value_added_tax: { type: "integer", nullable: true },
      xendit_withholding_tax: { type: "integer", nullable: true },
      third_party_withholding_tax: { type: "integer", nullable: true },
      status: { type: "string", nullable: true }
    }
  });

  setSchema(schemas, "XenditTransaction", {
    type: "object",
    properties: {
      id: { type: "string" },
      product_id: { type: "string", nullable: true },
      type: { type: "string" },
      channel_code: { type: "string", nullable: true },
      reference_id: { type: "string", nullable: true },
      account_identifier: { type: "string", nullable: true },
      currency: { type: "string", nullable: true },
      amount: { type: "integer", nullable: true },
      net_amount: { type: "integer", nullable: true },
      cashflow: { type: "string", nullable: true },
      status: { type: "string", nullable: true },
      channel_category: { type: "string", nullable: true },
      business_id: { type: "integer", nullable: true },
      created: { type: "string", format: "date-time", nullable: true },
      updated: { type: "string", format: "date-time", nullable: true },
      fee: {
        allOf: [{ $ref: "#/components/schemas/XenditFee" }],
        nullable: true
      },
      settlement_status: { type: "string", nullable: true },
      estimated_settlement_time: { type: "string", format: "date-time", nullable: true }
    }
  });

  setSchema(schemas, "XenditTransactionListData", {
    type: "object",
    properties: {
      has_next: { type: "boolean" },
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/XenditTransaction" }
      }
    }
  });

  setSchema(schemas, "XenditTransactionResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/XenditTransaction" }
    }
  });

  setSchema(schemas, "XenditTransactionListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/XenditTransactionListData" }
    }
  });

  setSchema(schemas, "CreateXenditReportRequest", {
    type: "object",
    properties: {
      type: { type: "string" },
      xp_type: { type: "string" }
    }
  });

  setSchema(schemas, "XenditReport", {
    type: "object",
    properties: {
      id: { type: "integer" },
      xendit_report_id: { type: "string" },
      data: {
        allOf: [{ $ref: "#/components/schemas/GenericObject" }],
        nullable: true
      },
      requested_by: {
        allOf: [{ $ref: "#/components/schemas/UserSimple" }],
        nullable: true
      },
      inserted_at: { type: "string", format: "date-time", nullable: true },
      updated_at: { type: "string", format: "date-time", nullable: true }
    }
  });

  setSchema(schemas, "XenditReportListData", {
    type: "object",
    properties: {
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/XenditReport" }
      }
    }
  });

  setSchema(schemas, "XenditReportResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/XenditReport" }
    }
  });

  setSchema(schemas, "XenditReportListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/XenditReportListData" }
    }
  });

  setSchema(schemas, "UnprocessableEntityError", {
    type: "object",
    properties: {
      code: { type: "integer", example: 422 },
      status: { type: "string", example: "Unprocessable Entity" },
      error: { type: "string" }
    }
  });

  setSchema(schemas, "InternalServerError", {
    type: "object",
    properties: {
      code: { type: "integer", example: 500 },
      status: { type: "string", example: "Internal Server Error" },
      error: { type: "string" }
    }
  });

  setSchema(schemas, "AdViewChartRequest", {
    type: "object",
    required: ["series1", "series2", "since", "until"],
    additionalProperties: false,
    properties: {
      since: { type: "string", format: "date" },
      until: { type: "string", format: "date" },
      series1: { type: "string" },
      series2: { type: "string" },
      tz: { type: "string" },
      campaign_ids: {
        type: "array",
        items: {
          oneOf: [{ type: "integer" }, { type: "string" }]
        }
      }
    }
  });

  setSchema(schemas, "AdViewChartPayload", {
    type: "object",
    properties: {
      now: {
        type: "object",
        additionalProperties: true
      },
      before: {
        type: "object",
        additionalProperties: true
      },
      changes: {
        type: "object",
        additionalProperties: {
          type: "number",
          nullable: true
        }
      }
    }
  });

  setSchema(schemas, "AdViewChartResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/AdViewChartPayload" }
    }
  });

  setSchema(schemas, "CourierAggregatorOriginRequest", {
    type: "object",
    required: ["courier_aggregator_code"],
    properties: {
      courier_aggregator_code: {
        description: "Courier aggregator code used to generate the origin mapping.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "StoreResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/Store" }
    }
  });

  setSchema(schemas, "WarehousePartnerBusiness", {
    type: "object",
    properties: {
      id: { type: "integer" },
      is_banned: { type: "boolean" },
      unique_id: { type: "string" },
      account_holder: { type: "string" },
      email: { type: "string" },
      contact_phone: { type: "string" },
      contact_email: { type: "string" },
      logo: { type: "string" },
      username: { type: "string" },
      is_manual_reseller_transfer_allowed: { type: "boolean" }
    }
  });

  setSchema(schemas, "WarehousePartner", {
    type: "object",
    properties: {
      id: { type: "integer" },
      warehouse_id: { type: "integer" },
      partner: { $ref: "#/components/schemas/WarehousePartnerBusiness" },
      ka_origin_id: { type: "integer", nullable: true },
      lincah_origin_id: { type: "integer", nullable: true },
      mengantar_origin_id: { type: "integer", nullable: true },
      is_comply: { type: "boolean" },
      created_at: { type: "string", format: "date-time" },
      last_updated_at: { type: "string", format: "date-time" }
    }
  });

  setSchema(schemas, "WarehousePartnerResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/WarehousePartner" }
    }
  });

  setSchema(schemas, "WarehousePartnerListPayload", {
    type: "object",
    properties: {
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/WarehousePartner" }
      },
      has_next: { type: "boolean" },
      last_id: { type: "integer", nullable: true },
      page_size: { type: "integer" }
    }
  });

  setSchema(schemas, "WarehousePartnerListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/WarehousePartnerListPayload" }
    }
  });

  setSchema(schemas, "WarehousePartnerCreateRequest", {
    type: "object",
    required: ["unique_id", "warehouse_id"],
    properties: {
      warehouse_id: {
        description: "Warehouse ID that will own the partner association.",
        oneOf: [{ type: "integer" }, { type: "string" }]
      },
      unique_id: {
        description: "Partner business unique ID to associate with the warehouse.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "WarehousePartnerUpdateRequest", {
    type: "object",
    required: ["is_comply"],
    properties: {
      is_comply: {
        description: "Whether the warehouse partner is currently marked as compliant.",
        type: "boolean"
      }
    }
  });

  setSchema(schemas, "EmailIdentityListPayload", {
    type: "object",
    properties: {
      results: {
        type: "array",
        items: { $ref: "#/components/schemas/EmailIdentity" }
      },
      has_next: { type: "boolean" },
      last_id: {
        type: "string",
        nullable: true,
        format: "uuid"
      },
      page_size: { type: "integer" }
    }
  });

  setSchema(schemas, "EmailIdentityListResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/EmailIdentityListPayload" }
    }
  });

  setSchema(schemas, "WabaMessage", {
    type: "object",
    properties: {
      wamid: { type: "string" },
      phone_number_id: { type: "string" },
      wa_user_id: { type: "string" },
      handler_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      inserted_at: { type: "string", format: "date-time" },
      conversation_id: { type: "string", nullable: true },
      timestamp_sent: { type: "string", format: "date-time", nullable: true },
      timestamp_delivered: { type: "string", format: "date-time", nullable: true },
      timestamp_read: { type: "string", format: "date-time", nullable: true },
      status: { type: "string" },
      error: { $ref: "#/components/schemas/GenericObject" },
      direction: { type: "string" },
      type: { type: "string" },
      pricing_category: { type: "string", nullable: true },
      pricing_model: { type: "string", nullable: true },
      sender_type: { type: "string", nullable: true },
      agent_context: { $ref: "#/components/schemas/GenericObject" },
      audio: { $ref: "#/components/schemas/GenericObject" },
      button: { $ref: "#/components/schemas/GenericObject" },
      context: { $ref: "#/components/schemas/GenericObject" },
      document: { $ref: "#/components/schemas/GenericObject" },
      image: { $ref: "#/components/schemas/GenericObject" },
      interactive: { $ref: "#/components/schemas/GenericObject" },
      order: { $ref: "#/components/schemas/GenericObject" },
      referral: { $ref: "#/components/schemas/GenericObject" },
      sticker: { $ref: "#/components/schemas/GenericObject" },
      text: { $ref: "#/components/schemas/GenericObject" },
      video: { $ref: "#/components/schemas/GenericObject" },
      template: { $ref: "#/components/schemas/GenericObject" }
    }
  });

  setSchema(schemas, "WabaMessageResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/WabaMessage" }
    }
  });

  setSchema(schemas, "WabaMessageUpdateRequest", {
    type: "object",
    required: ["status"],
    properties: {
      status: {
        type: "string",
        enum: ["read"],
        description: "Updated message status."
      }
    }
  });

  setSchema(schemas, "SubscriptionResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/Subscription" }
    }
  });

  setSchema(schemas, "SubscriptionItemChangeRequest", {
    type: "object",
    required: ["variant_id"],
    properties: {
      variant_id: {
        description: "ID of the target variant for the requested subscription-item change.",
        type: "integer"
      }
    }
  });

  setSchema(schemas, "SubscriptionRenewalInvoice", {
    type: "object",
    properties: {
      id: { type: "integer" },
      order_id: { type: "integer", nullable: true },
      status: { type: "string", nullable: true },
      amount: { type: "string", nullable: true },
      currency: { type: "string", nullable: true },
      created_at: { type: "string", format: "date-time", nullable: true },
      due_date: { type: "string", format: "date-time", nullable: true },
      paid_at: { type: "string", format: "date-time", nullable: true }
    }
  });

  setSchema(schemas, "SubscriptionAction", {
    type: "object",
    properties: {
      id: { type: "integer" },
      action_type: { type: "string" },
      execution_type: { type: "string", nullable: true },
      status: { type: "string", nullable: true },
      next_variant_config: {
        type: "object",
        additionalProperties: true
      },
      confirmed_at: { type: "string", format: "date-time", nullable: true },
      completed_at: { type: "string", format: "date-time", nullable: true },
      order_id: { type: "integer", nullable: true },
      created_by: { oneOf: [{ type: "integer" }, { type: "string" }] },
      inserted_at: { type: "string", format: "date-time", nullable: true },
      updated_at: { type: "string", format: "date-time", nullable: true }
    }
  });

  setSchema(schemas, "MailketingIntegrationRequest", {
    type: "object",
    required: ["identifier", "api_token"],
    properties: {
      identifier: {
        description: "Mailketing identifier for the authenticated business.",
        type: "string"
      },
      api_token: {
        description: "Mailketing API token used to authenticate synchronization requests.",
        type: "string"
      }
    }
  });

  setSchema(schemas, "MailketingIntegration", {
    type: "object",
    properties: {
      id: { type: "integer" },
      identifier: { type: "string" },
      api_token: { type: "string", nullable: true },
      inserted_at: { type: "string", format: "date-time", nullable: true },
      updated_at: { type: "string", format: "date-time", nullable: true }
    }
  });

  setSchema(schemas, "MailketingIntegrationResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/MailketingIntegration" }
    }
  });

  setSchema(schemas, "MailketingList", {
    type: "object",
    properties: {
      id: { type: "integer" },
      list_id: { type: "integer" },
      list_name: { type: "string" }
    }
  });

  setSchema(schemas, "MailketingListArrayResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: {
        type: "array",
        items: { $ref: "#/components/schemas/MailketingList" }
      }
    }
  });

  setSchema(schemas, "WhatsappIntegrationResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/WhatsappIntegration" }
    }
  });

  setSchema(schemas, "WhatsappIntegrationRequest", {
    type: "object",
    required: ["name", "provider"],
    properties: {
      name: {
        description: "Display name for the WhatsApp integration.",
        type: "string",
        maxLength: 255
      },
      provider: {
        description: "Provider used to connect the WhatsApp integration.",
        type: "string",
        enum: ["woowa", "starsender"]
      },
      phone_number: {
        description: "Phone number associated with the WhatsApp integration.",
        type: "string"
      },
      woowa_api_key: {
        description: "Woowa API key. Required when `provider` is `woowa`.",
        type: "string",
        maxLength: 100
      },
      ss_device_pk: {
        description: "StarSender device primary key, when available.",
        type: "integer",
        nullable: true
      },
      ss_device_api_key: {
        description: "StarSender device API key. Required when `provider` is `starsender`.",
        type: "string",
        maxLength: 100
      }
    },
    oneOf: [
      {
        properties: {
          provider: { type: "string", enum: ["woowa"] }
        },
        required: ["woowa_api_key"]
      },
      {
        properties: {
          provider: { type: "string", enum: ["starsender"] }
        },
        required: ["ss_device_api_key"]
      }
    ]
  });

  setSchema(schemas, "EmailIdentityUpdateRequest", {
    type: "object",
    properties: {
      name: {
        description: "Updated display name for the SES email identity.",
        type: "string"
      },
      email: {
        description: "Updated sending email address or domain.",
        type: "string"
      },
      is_verified: {
        description: "Whether the SES email identity is verified.",
        type: "boolean"
      },
      verification_data: {
        description: "Provider-specific verification metadata.",
        type: "object",
        additionalProperties: true
      }
    }
  });

  setSchema(schemas, "EmailIdentityResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/EmailIdentity" }
    }
  });

  setSchema(schemas, "Notification", {
    type: "object",
    properties: {
      id: { type: "integer" },
      type: { type: "string" },
      title: { type: "string" },
      body: { type: "string" },
      order_id: { type: "integer", nullable: true },
      metadata: {
        type: "object",
        additionalProperties: true,
        nullable: true
      },
      is_read: { type: "boolean" },
      inserted_at: { type: "string", format: "date-time", nullable: true },
      updated_at: { type: "string", format: "date-time", nullable: true }
    }
  });

  setSchema(schemas, "NotificationUpdateRequest", {
    type: "object",
    required: ["is_read"],
    properties: {
      is_read: {
        description: "Whether the notification should be marked as read.",
        type: "boolean"
      }
    }
  });

  setSchema(schemas, "NotificationResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/Notification" }
    }
  });

  setSchema(schemas, "ChatbotConversationAnalysis", {
    type: "object",
    properties: {
      conversation_state: {
        type: "object",
        nullable: true,
        properties: {
          last_summary: { type: "string", nullable: true },
          last_stage: { type: "string", nullable: true },
          last_intent: { type: "string", nullable: true },
          metadata: {
            type: "object",
            additionalProperties: true,
            nullable: true
          }
        }
      },
      response: {
        type: "object",
        nullable: true,
        properties: {
          intent: { type: "string", nullable: true },
          action: { type: "string", nullable: true },
          response_text: { type: "string", nullable: true },
          metadata: {
            type: "object",
            additionalProperties: true,
            nullable: true
          }
        }
      },
      usage: {
        type: "object",
        additionalProperties: true,
        nullable: true
      },
      order: {
        type: "object",
        additionalProperties: true,
        nullable: true
      }
    }
  });

  setSchema(schemas, "ChatbotConversationAnalysisRequest", {
    type: "object",
    additionalProperties: false,
    description:
      "Conversation transcript and context payload used to analyze a chatbot conversation for the authenticated business.",
    properties: {
      conversation: {
        type: "array",
        description: "Ordered conversation messages supplied to the analyzer.",
        items: {
          type: "object",
          additionalProperties: { $ref: "#/components/schemas/GenericValue" }
        }
      },
      conversation_state: {
        type: "object",
        description: "Persisted conversation state from the previous analysis result.",
        additionalProperties: { $ref: "#/components/schemas/GenericValue" }
      },
      metadata: {
        type: "object",
        description: "Additional context used by the analyzer, such as storefront or customer details.",
        additionalProperties: { $ref: "#/components/schemas/GenericValue" }
      },
      order: {
        type: "object",
        description: "Order context that can be used while interpreting the conversation.",
        additionalProperties: { $ref: "#/components/schemas/GenericValue" }
      }
    }
  });

  setSchema(schemas, "ChatbotConversationAnalysisResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/ChatbotConversationAnalysis" }
    }
  });

  if (schemas.EmailIdentity?.properties?.email) {
    schemas.EmailIdentity.properties.email = {
      description: "Email address or verified sending domain.",
      type: "string"
    };
  }

  if (schemas.SubscriptionItem?.properties?.pending_action) {
    schemas.SubscriptionItem.properties.pending_action = {
      type: "object",
      allOf: [{ $ref: "#/components/schemas/SubscriptionAction" }],
      nullable: true
    };
  }

  if (schemas.SubscriptionAction && !schemas.SubscriptionAction.title) {
    schemas.SubscriptionAction.title = "SubscriptionAction";
  }

  if (schemas.Subscription?.properties) {
    schemas.Subscription.properties.order_id = {
      description: "Identifier for the source order linked to the subscription, when available.",
      type: "integer",
      nullable: true
    };

    schemas.Subscription.properties.latest_renewal_invoice = {
      allOf: [{ $ref: "#/components/schemas/SubscriptionRenewalInvoice" }],
      nullable: true
    };

    for (const key of ["business_customer_id", "business_id", "customer_id", "store_id"]) {
      if (schemas.Subscription.properties[key]) {
        schemas.Subscription.properties[key] = {
          ...schemas.Subscription.properties[key],
          type: "integer"
        };
        delete schemas.Subscription.properties[key].format;
      }
    }

    const itemProperties = schemas.Subscription.properties.subscription_items?.items?.properties;
    if (itemProperties?.price) {
      itemProperties.unit_price = {
        ...itemProperties.price,
        description: "The unit price of the item."
      };
      delete itemProperties.price;
    }
  }

  if (schemas.SubscriptionItemListData?.properties) {
    Object.assign(schemas.SubscriptionItemListData.properties, {
      currency: {
        description: "Currency used for the subscription item unit price.",
        type: "string",
        nullable: true
      },
      activated_at: {
        description: "The date and time when the subscription item became active.",
        type: "string",
        format: "date-time",
        nullable: true
      },
      canceled_at: {
        description: "The date and time when the subscription item was canceled.",
        type: "string",
        format: "date-time",
        nullable: true
      },
      expired_at: {
        description: "The date and time when the subscription item expired.",
        type: "string",
        format: "date-time",
        nullable: true
      },
      is_cancel_at_period_end: {
        description: "Whether the subscription item is scheduled to cancel at the end of the current period.",
        type: "boolean",
        nullable: true
      },
      orderline_id: {
        description: "Identifier for the related order line, when available.",
        type: "integer",
        nullable: true
      },
      license_id: {
        description: "Identifier for the related license, when available.",
        type: "integer",
        nullable: true
      },
      subscription_id: {
        description: "Subscription UUID that owns the subscription item.",
        type: "string",
        format: "uuid",
        nullable: true
      },
      variant_id: {
        description: "Identifier for the subscribed variant.",
        type: "integer",
        nullable: true
      },
      product_id: {
        description: "Identifier for the subscribed product.",
        type: "integer",
        nullable: true
      },
      inserted_at: {
        description: "The date and time when the subscription item was created.",
        type: "string",
        format: "date-time",
        nullable: true
      },
      updated_at: {
        description: "The date and time when the subscription item was last updated.",
        type: "string",
        format: "date-time",
        nullable: true
      },
      pending_action: {
        allOf: [{ $ref: "#/components/schemas/SubscriptionAction" }],
        nullable: true
      }
    });
  }

  if (schemas.WhatsappIntegration?.properties) {
    Object.assign(schemas.WhatsappIntegration.properties, {
      id: { description: "WhatsApp Integration ID", type: "integer" },
      name: { description: "Integration name", type: "string" },
      provider: { description: "WhatsApp integration provider", type: "string" },
      phone_number: { description: "Prepared phone number for the integration", type: "string" },
      woowa_api_key: {
        description: "Woowa API key or masked API key, depending on the endpoint.",
        type: "string",
        nullable: true
      },
      ss_device_pk: {
        description: "StarSender device primary key.",
        type: "integer",
        nullable: true
      },
      ss_device_api_key: {
        description: "StarSender device API key or masked API key, depending on the endpoint.",
        type: "string",
        nullable: true
      },
      business_id: {
        description: "Identifier for the owning business.",
        type: "integer",
        nullable: true
      },
      created_at: {
        description: "The date and time when the integration was created.",
        type: "string",
        format: "date-time",
        nullable: true
      },
      last_updated_at: {
        description: "The date and time when the integration was last updated.",
        type: "string",
        format: "date-time",
        nullable: true
      },
      is_online: {
        description: "Whether the provider currently reports the integration as online.",
        type: "boolean",
        nullable: true
      }
    });
  }

  if (!schemas.PeriodUnit) {
    setSchema(schemas, "PeriodUnit", {
      title: "PeriodUnit",
      description: "Unit of the period",
      type: "string",
      enum: ["day", "week", "month", "year"]
    });
  }

  setSchema(schemas, "DurationUnit", {
    $ref: "#/components/schemas/PeriodUnit"
  });

  if (schemas.License) {
    setSchema(schemas, "LicenseList", {
      $ref: "#/components/schemas/License"
    });
  }

  setResponseComponent(
    responses,
    "BadRequestResponse",
    "Bad Request",
    "#/components/schemas/BadRequestError"
  );
  setResponseComponent(
    responses,
    "UnauthorizedResponse",
    "Unauthorized",
    "#/components/schemas/UnauthorizedError"
  );
  setResponseComponent(
    responses,
    "ForbiddenResponse",
    "Forbidden",
    "#/components/schemas/ForbiddenError"
  );
  setResponseComponent(
    responses,
    "NotFoundResponse",
    "Not Found",
    "#/components/schemas/NotFoundError"
  );
  setResponseComponent(
    responses,
    "PaymentRequiredResponse",
    "Payment Required",
    "#/components/schemas/PaymentRequiredError"
  );
  setResponseComponent(
    responses,
    "SuccessDataResponse",
    "Success",
    "#/components/schemas/GenericSuccessDataResponse"
  );
  setResponseComponent(
    responses,
    "SuccessMessageResponse",
    "Success",
    "#/components/schemas/SuccessMessageResponse"
  );
  setResponseComponent(
    responses,
    "SuccessObjectResponse",
    "Success",
    "#/components/schemas/GenericSuccessObjectResponse"
  );
  setResponseComponent(
    responses,
    "SuccessListResponse",
    "Success",
    "#/components/schemas/GenericSuccessListResponse"
  );
  setResponseComponent(
    responses,
    "CreatedObjectResponse",
    "Created",
    "#/components/schemas/GenericCreatedObjectResponse"
  );
  setResponseComponent(
    responses,
    "BlankSuccessApiResponse",
    "Success",
    "#/components/schemas/BlankSuccessResponse"
  );
  setResponseComponent(
    responses,
    "JwtAccessTokenResponse",
    "Success",
    "#/components/schemas/JwtAccessTokenPayload"
  );
}

function buildSuccessResponse(spec, route) {
  const status = String(inferSuccessStatus(route));
  const kind = inferResponseKind(route);

  if (kind === "binary") {
    return {
      [status]: {
        description: "Success",
        content: {
          "application/octet-stream": {
            schema: {
              type: "string",
              format: "binary"
            }
          }
        }
      }
    };
  }

  if (kind === "blank" && status === "204") {
    return {
      "204": {
        description: "Success"
      }
    };
  }

  if (kind === "blank") {
    return {
      [status]: {
        $ref: "#/components/responses/BlankSuccessApiResponse"
      }
    };
  }

  const inferredResponseRef = ensureInferredResponseComponent(
    spec,
    route,
    inferResponseDataSchemaFromRawData(route) || inferResponseDataSchemaFromView(route)
  );

  if (inferredResponseRef) {
    return {
      [status]: {
        $ref: inferredResponseRef
      }
    };
  }

  if (kind === "value") {
    return {
      [status]: {
        $ref: "#/components/responses/SuccessDataResponse"
      }
    };
  }

  if (status === "201") {
    return {
      "201": {
        $ref: "#/components/responses/CreatedObjectResponse"
      }
    };
  }

  if (kind === "list") {
    return {
      [status]: {
        $ref: "#/components/responses/SuccessListResponse"
      }
    };
  }

  return {
    [status]: {
      $ref: "#/components/responses/SuccessObjectResponse"
    }
  };
}

function buildErrorResponses(route) {
  const responses = {
    "400": {
      $ref: "#/components/responses/BadRequestResponse"
    },
    "401": {
      $ref: "#/components/responses/UnauthorizedResponse"
    }
  };

  if (responseMayBeForbidden(route)) {
    responses["403"] = {
      $ref: "#/components/responses/ForbiddenResponse"
    };
  }

  if (responseMayBeNotFound(route)) {
    responses["404"] = {
      $ref: "#/components/responses/NotFoundResponse"
    };
  }

  if (/:payment_required\b/.test(route.actionBody)) {
    responses["402"] = {
      $ref: "#/components/responses/PaymentRequiredResponse"
    };
  }

  return responses;
}

function inferRequestBodyDescription(route, contentType) {
  return inferRequestBodyDescriptionFromSummary(inferSummary(route), contentType);
}

function inferRequestBodyDescriptionFromSummary(summary, contentType) {
  const match = summary.match(/^([A-Za-z]+)\s+(.+)$/);

  if (match) {
    const [, verb, subject] = match;
    const prefix = contentType === "multipart/form-data" ? "Multipart payload" : "Payload";
    const lowerVerb = verb.toLowerCase();
    const article =
      lowerVerb === "create"
        ? "a"
        : ["update", "delete", "cancel", "resume", "approve", "mark", "check", "release", "set", "switch", "confirm", "finalize", "sync"].includes(
              lowerVerb
            )
          ? "the"
          : lowerVerb === "generate"
            ? "a"
          : null;
    return `${prefix} used to ${lowerVerb} ${naturalizeRequestSubject(subject, article)}.`;
  }

  return contentType === "multipart/form-data"
    ? "Multipart payload for the requested operation."
    : "JSON payload for the requested operation.";
}

function naturalizeRequestSubject(text, article = null) {
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

function buildRequestBody(spec, route) {
  const operationKey = `${route.method} ${route.path}`;

  if (operationKey === "DELETE /v2/stores/{store_id}/courier-services") {
    return buildSchemaRefRequestBody(
      "#/components/schemas/StoreCourierServiceRemovalRequest",
      "Courier services to dissociate from the store. This DELETE operation requires a JSON body, and some OpenAPI 3.0 tooling may ignore DELETE request bodies.",
      true
    );
  }

  if (operationKey === "DELETE /v2/stores/{store_id}/payment-methods") {
    return buildSchemaRefRequestBody(
      "#/components/schemas/StorePaymentMethodRemovalRequest",
      "Payment method association to remove from the store. This DELETE operation requires a JSON body, and some OpenAPI 3.0 tooling may ignore DELETE request bodies.",
      true
    );
  }

  const contentType = inferConsumes(route);
  if (!contentType) {
    return null;
  }

  const schema = inferRequestSchema(route, contentType);
  if (routeProbablyHasNoRequestBody(route, schema)) {
    return null;
  }

  const { schemaRef, required } = ensureInferredRequestSchema(spec, route, contentType, schema);

  return {
    required,
    description: inferRequestBodyDescription(route, contentType),
    content: {
      [contentType]: {
        schema: {
          $ref: schemaRef
        }
      }
    }
  };
}

function buildOperation(spec, route) {
  const operation = {
    callbacks: {},
    description: inferDescription(route),
    operationId: route.operationId,
    parameters: buildPathParameters(route.path),
    responses: {
      ...buildSuccessResponse(spec, route),
      ...buildErrorResponses(route)
    },
    security: inferSecurity(route),
    summary: inferSummary(route),
    tags: [inferTag(route.path)]
  };

  const requestBody = buildRequestBody(spec, route);
  if (requestBody) {
    operation.requestBody = requestBody;
  }

  return operation;
}

function getOperationMap(spec, routePath) {
  const paths = ensureObject(spec, "paths");
  if (!paths[routePath] || typeof paths[routePath] !== "object" || Array.isArray(paths[routePath])) {
    paths[routePath] = {};
  }

  return paths[routePath];
}

function getOperation(spec, routePath, method) {
  return spec.paths?.[routePath]?.[method.toLowerCase()] || null;
}

function* iterateOperations(spec) {
  for (const [routePath, pathItem] of Object.entries(spec.paths || {})) {
    for (const [method, operation] of Object.entries(pathItem)) {
      yield {
        routePath,
        method: method.toUpperCase(),
        operation
      };
    }
  }
}

function removeDocumentedAliasPaths(spec) {
  const { aliasPaths } = loadAliasLookup(nexusDir);
  const paths = ensureObject(spec, "paths");

  for (const aliasPath of aliasPaths) {
    delete paths[aliasPath];
  }
}

function removeDocumentedPublicPaths(spec) {
  const paths = ensureObject(spec, "paths");

  for (const routePath of Object.keys(paths)) {
    if (isPublicRoute(routePath)) {
      delete paths[routePath];
    }
  }
}

function removeIgnoredOperations(spec) {
  return spec;
}

function removeUnexpectedDocumentedOperations(spec, routes) {
  const paths = ensureObject(spec, "paths");
  const canonicalMethods = new Set(routes.map((route) => `${route.method} ${route.path}`));

  for (const [routePath, pathItem] of Object.entries(paths)) {
    if (!routePath.startsWith("/v2/") || !pathItem || typeof pathItem !== "object") {
      continue;
    }

    for (const method of Object.keys(pathItem)) {
      const methodName = method.toUpperCase();
      if (!canonicalMethods.has(`${methodName} ${routePath}`)) {
        delete pathItem[method];
      }
    }

    if (Object.keys(pathItem).length === 0) {
      delete paths[routePath];
    }
  }
}

function syncRoutes(spec) {
  const routes = sortRoutes(loadRouteManifest(nexusDir));
  let addedOperations = 0;

  for (const route of routes) {
    const operationMap = getOperationMap(spec, route.path);
    const methodKey = route.method.toLowerCase();

    if (operationMap[methodKey]) {
      continue;
    }

    operationMap[methodKey] = buildOperation(spec, route);
    addedOperations += 1;
  }

  return { addedOperations, routes };
}

function refreshPathParameters(operation, routePath) {
  const generatedParameters = buildPathParameters(routePath);
  if (generatedParameters.length === 0) {
    return;
  }

  const currentParameters = Array.isArray(operation.parameters) ? operation.parameters : [];
  const parameterMap = new Map(
    currentParameters.map((parameter) => [`${parameter.in}:${parameter.name}`, parameter])
  );

  for (const parameter of generatedParameters) {
    const key = `${parameter.in}:${parameter.name}`;
    const existing = parameterMap.get(key);

    if (!existing) {
      parameterMap.set(key, parameter);
      continue;
    }

    if (
      !existing.description ||
      /path parameter$/i.test(existing.description) ||
      /^id path parameter$/i.test(existing.description) ||
      /\bof the my\b/i.test(existing.description) ||
      /\bwarehous\b/i.test(existing.description) ||
      /^ID of the licens$/i.test(existing.description) ||
      /^ID of the bu$/i.test(existing.description) ||
      /^ID of the waba unique$/i.test(existing.description) ||
      /^ID of the wa user$/i.test(existing.description) ||
      /^Wamid path parameter$/i.test(existing.description) ||
      /^Custom Domain path parameter$/i.test(existing.description)
    ) {
      existing.description = parameter.description;
    }

    if (!existing.schema) {
      existing.schema = parameter.schema;
    }
  }

  operation.parameters = Array.from(parameterMap.values());
}

function looksGenerated(operation) {
  return typeof operation.description === "string" && GENERATED_DESCRIPTION_RE.test(operation.description);
}

function getRequestBodySchemaRef(spec, operation) {
  const requestBody =
    operation.requestBody?.$ref?.match(/^#\/components\/requestBodies\/(.+)$/)
      ? spec.components?.requestBodies?.[
          operation.requestBody.$ref.match(/^#\/components\/requestBodies\/(.+)$/)[1]
        ]
      : operation.requestBody;

  for (const mediaType of Object.values(requestBody?.content || {})) {
    const schemaRef = mediaType?.schema?.$ref;
    if (schemaRef) {
      return schemaRef;
    }
  }

  return null;
}

function hasStaleRequestBodyDescription(operation) {
  const description = operation.requestBody?.description;
  return (
    typeof description === "string" &&
    (/request payload\.$/i.test(description) ||
      /^payload used to\b/i.test(description) ||
      /^multipart payload used to\b/i.test(description))
  );
}

function hasAutogeneratedDescription(operation) {
  const description = operation.description;
  return (
    typeof description === "string" &&
    (GENERATED_DESCRIPTION_RE.test(description) ||
      /^(Returns|Creates|Updates|Deletes|Checks|Downloads|Marks|Cancels|Approves|Sends|Uploads|Synchronizes|Registers|Resends|Previews|Calculates|Refreshes|Completes|Disables|Switches|Merges|Confirms|Sets|Finalizes|Releases)\b/.test(
        description
      ))
  );
}

function isGenericSuccessEntry(entry) {
  if (!entry) {
    return false;
  }

  if (entry.$ref) {
    return [
      "#/components/responses/SuccessDataResponse",
      "#/components/responses/SuccessObjectResponse",
      "#/components/responses/SuccessListResponse",
      "#/components/responses/CreatedObjectResponse",
      "#/components/responses/BlankSuccessApiResponse"
    ].includes(entry.$ref);
  }

  const schemaRef = entry.content?.["application/json"]?.schema?.$ref;

  return [
    "#/components/schemas/GenericSuccessDataResponse",
    "#/components/schemas/GenericSuccessObjectResponse",
    "#/components/schemas/GenericSuccessListResponse",
    "#/components/schemas/GenericCreatedObjectResponse",
    "#/components/schemas/BlankSuccessResponse"
  ].includes(schemaRef);
}

function syncGenericSuccessResponses(spec, operation, route) {
  const desiredResponses = buildSuccessResponse(spec, route);
  const desiredStatuses = new Set(Object.keys(desiredResponses));
  const responses = ensureObject(operation, "responses");

  for (const [status, entry] of Object.entries(responses)) {
    if (/^2\d\d$/.test(status) && isGenericSuccessEntry(entry) && !desiredStatuses.has(status)) {
      delete responses[status];
    }
  }

  for (const [status, entry] of Object.entries(desiredResponses)) {
    if (!responses[status] || isGenericSuccessEntry(responses[status])) {
      responses[status] = entry;
    }
  }
}

function syncMissingErrorResponses(operation, route) {
  const desiredResponses = buildErrorResponses(route);
  const responses = ensureObject(operation, "responses");

  for (const [status, entry] of Object.entries(desiredResponses)) {
    if (!responses[status]) {
      responses[status] = entry;
    }
  }
}

function normalizeRouteOperations(spec, routes) {
  for (const route of routes) {
    const operation = getOperation(spec, route.path, route.method);
    if (!operation) {
      continue;
    }

    operation.security = inferSecurity(route);
    refreshPathParameters(operation, route.path);

    if (/\/count$/.test(route.path)) {
      operation.parameters = (operation.parameters || []).filter((parameter) => parameter.in === "path");
    }

    const currentTags = Array.isArray(operation.tags) ? operation.tags : [];
    const desiredTag = inferTag(route.path);

    if (
      currentTags.length === 0 ||
      (currentTags.length === 1 &&
        (currentTags[0] === "Authenticated API" ||
          desiredTag === "SES Credits" ||
          desiredTag === "WhatsApp"))
    ) {
      operation.tags = [desiredTag];
    }

    syncGenericSuccessResponses(spec, operation, route);
    syncMissingErrorResponses(operation, route);

    const requestBody = buildRequestBody(spec, route);
    const currentSchemaRef = getRequestBodySchemaRef(spec, operation);
    const desiredSchemaRef =
      requestBody?.content &&
      Object.values(requestBody.content)[0]?.schema?.$ref;

    if (
      !requestBody &&
      currentSchemaRef &&
      currentSchemaRef.startsWith("#/components/schemas/Inferred")
    ) {
      delete operation.requestBody;
    } else if (
      requestBody &&
      (!operation.requestBody ||
        currentSchemaRef === "#/components/schemas/GenericObject" ||
        (currentSchemaRef?.startsWith("#/components/schemas/Inferred") &&
          desiredSchemaRef &&
          desiredSchemaRef !== currentSchemaRef))
    ) {
      operation.requestBody = requestBody;
    } else if (requestBody && operation.requestBody && hasStaleRequestBodyDescription(operation)) {
      operation.requestBody.description = requestBody.description;
    }

    if (looksGenerated(operation)) {
      operation.summary = inferSummary(route);
      operation.description = inferDescription(route);
    } else if (hasAutogeneratedDescription(operation)) {
      operation.description = inferDescription(route);
    }
  }
}

function setOperationJsonResponse(operation, status, description, schemaRef) {
  operation.responses = operation.responses || {};
  operation.responses[status] = {
    description,
    content: {
      "application/json": {
        schema: {
          $ref: schemaRef
        }
      }
    }
  };
}

function setOperationResponseSchema(operation, status, description, schemaRef) {
  operation.responses = operation.responses || {};
  operation.responses[status] = {
    description,
    content: {
      "application/json": {
        schema: {
          $ref: schemaRef
        }
      }
    }
  };
}

function setOperationResponseRef(operation, status, ref) {
  operation.responses = operation.responses || {};
  operation.responses[status] = { $ref: ref };
}

function setBlankSuccessResponse(operation, status = "200") {
  setOperationResponseRef(operation, status, "#/components/responses/BlankSuccessApiResponse");
}

function setOperationText(operation, summary, description) {
  operation.summary = summary;
  operation.description = description;
}

function setOperationRequestBodyDescription(operation, description) {
  if (operation.requestBody) {
    operation.requestBody.description = description;
  }
}

function setOperationRequestBodyRequired(operation, required) {
  if (operation.requestBody) {
    operation.requestBody.required = required;
  }
}

function setOperationPathParameterSchema(operation, parameterName, schema) {
  for (const parameter of operation.parameters || []) {
    if (parameter?.in === "path" && parameter.name === parameterName) {
      parameter.schema = schema;
    }
  }
}

function setOperationPathParameterDescription(operation, parameterName, description) {
  for (const parameter of operation.parameters || []) {
    if (parameter?.in === "path" && parameter.name === parameterName) {
      parameter.description = description;
    }
  }
}

function setOperationQueryParameterSchema(operation, parameterName, schema) {
  for (const parameter of operation.parameters || []) {
    if (parameter?.in === "query" && parameter.name === parameterName) {
      parameter.schema = schema;
    }
  }
}

function normalizeDocumentationText(text) {
  if (typeof text !== "string") {
    return text;
  }

  let normalized = text;

  for (const [pattern, replacement] of [
    [/\bbirdsend\b/gi, "Birdsend"],
    [/\bmailketing\b/gi, "Mailketing"],
    [/\bmoota\b/gi, "Moota"],
    [/\boauth\b/gi, "OAuth"],
    [/\btiktok\b/gi, "TikTok"],
    [/\bwhatsapp\b/gi, "WhatsApp"],
    [/\bwhatsApp\b/g, "WhatsApp"],
    [/\bwakaka\b/gi, "Wakaka"],
    [/\bxendit\b/gi, "Xendit"],
    [/\bdiscourse\b/gi, "Discourse"],
    [/\breadme\b/gi, "ReadMe"]
  ]) {
    normalized = normalized.replace(pattern, replacement);
  }

  normalized = normalized
    .replace(/\bFollow up chats\b/g, "Follow-up chats")
    .replace(/\bfollow up chats\b/g, "follow-up chats")
    .replace(/\bFollow up chat\b/g, "Follow-up chat")
    .replace(/\bfollow up chat\b/g, "follow-up chat");

  normalized = normalized.replace(
    /^Returns businesses accessible to the authenticated user or business context\.$/,
    "Returns the businesses accessible to the authenticated user or current business context."
  );
  normalized = normalized.replace(
    /^Returns businesses that the authenticated user can access\.$/,
    "Returns the businesses that the authenticated user can access."
  );

  return normalized;
}

function normalizeSummaryText(text) {
  const normalized = normalizeDocumentationText(text);
  const smallWords = new Set(["a", "an", "and", "as", "at", "by", "for", "in", "of", "on", "or", "the", "to", "with"]);
  const wordOverrides = {
    api: "API",
    birdsend: "Birdsend",
    discourse: "Discourse",
    fcm: "FCM",
    gtm: "GTM",
    id: "ID",
    ipaymu: "iPaymu",
    jwt: "JWT",
    kwai: "Kwai",
    lms: "LMS",
    mailketing: "Mailketing",
    mfa: "MFA",
    moota: "Moota",
    oauth: "OAuth",
    otp: "OTP",
    pg: "PG",
    qr: "QR",
    readme: "ReadMe",
    ses: "SES",
    sso: "SSO",
    tiktok: "TikTok",
    totp: "TOTP",
    wakaka: "Wakaka",
    waba: "WABA",
    whatsapp: "WhatsApp",
    xp: "XP",
    xendit: "Xendit"
  };

  const formatPart = (part, isSmallWord) => {
    const lower = part.toLowerCase();
    const overridden = wordOverrides[lower];
    if (overridden) {
      return overridden;
    }

    if (isSmallWord && smallWords.has(lower)) {
      return lower;
    }

    return lower.charAt(0).toUpperCase() + lower.slice(1);
  };

  const words = normalized.split(/\s+/).filter(Boolean);

  return words
    .map((word, index) => {
      const prefix = word.match(/^[^A-Za-z0-9]*/)?.[0] || "";
      const suffix = word.match(/[^A-Za-z0-9]*$/)?.[0] || "";
      const core = word.slice(prefix.length, word.length - suffix.length);

      if (!core) {
        return word;
      }

      const parts = core.split("-");
      const formatted = parts
        .map((part, partIndex) => formatPart(part, parts.length === 1 && index > 0 && index < words.length - 1))
        .join("-");

      return `${prefix}${formatted}${suffix}`;
    })
    .join(" ");
}

function shouldStandardizeRequestBodyDescription(description) {
  return (
    typeof description === "string" &&
    (!description.trim().endsWith(".") ||
      /request payload\.$/i.test(description) ||
      /^payload used to\b/i.test(description) ||
      /^multipart payload used to\b/i.test(description) ||
      /\bdata to (create|update|delete|cancel|resume|approve|mark|check|release|set|switch|confirm|finalize|sync|upgrade|downgrade)\b/i.test(
        description
      ) ||
      /^(?:multipart |json )?payload$/i.test(description) ||
      /^[A-Z][A-Za-z0-9'\/ (),-]+(?: data| payload| details)$/i.test(description))
  );
}

function normalizeDocumentationTextFields(value) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      normalizeDocumentationTextFields(entry);
    }
    return;
  }

  if (!value || typeof value !== "object") {
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (key === "summary" && typeof nested === "string") {
      value[key] = normalizeSummaryText(nested);
      continue;
    }

    if (key === "description" && typeof nested === "string") {
      value[key] = normalizeDocumentationText(nested);
      continue;
    }

    normalizeDocumentationTextFields(nested);
  }
}

function normalizeRequestBodyDescriptions(spec) {
  for (const { operation } of iterateOperations(spec)) {
    const requestBody = operation.requestBody;
    if (!requestBody || !shouldStandardizeRequestBodyDescription(requestBody.description)) {
      continue;
    }

    const contentType = Object.keys(requestBody.content || {})[0] || "application/json";
    requestBody.description = inferRequestBodyDescriptionFromSummary(operation.summary || "Update Resource", contentType);
  }
}

function normalizePathParameterSchemas(spec) {
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
  const stringIdDescriptionPatterns = [
    /facebook page/i,
    /machine api log/i,
    /oauth billing (charge|reservation|settlement)/i,
    /request response log/i,
    /xp transaction/i
  ];

  const maybeNormalizeParameter = (parameter) => {
    if (!parameter || parameter.$ref || parameter.in !== "path") {
      return;
    }

    const description = `${parameter.description || ""}`.toLowerCase();
    if (parameter.schema?.format === "uuid" || description.includes("uuid")) {
      parameter.schema = {
        type: "string",
        format: "uuid"
      };
      return;
    }

    const shouldStayString =
      stringParameterNames.has(parameter.name) ||
      stringIdDescriptionPatterns.some((pattern) => pattern.test(description));

    if (!shouldStayString && (integerParameterNames.has(parameter.name) || parameter.name === "id" || parameter.name.endsWith("_id"))) {
      parameter.schema = { type: "integer" };
    }
  };

  for (const parameter of Object.values(spec.components?.parameters || {})) {
    maybeNormalizeParameter(parameter);
  }

  for (const pathItem of Object.values(spec.paths || {})) {
    if (!pathItem || typeof pathItem !== "object") {
      continue;
    }

    for (const parameter of pathItem.parameters || []) {
      maybeNormalizeParameter(parameter);
    }

    for (const operation of Object.values(pathItem)) {
      if (!operation || typeof operation !== "object") {
        continue;
      }

      for (const parameter of operation.parameters || []) {
        maybeNormalizeParameter(parameter);
      }
    }
  }
}

function normalizeDateTimeFormats(value) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      normalizeDateTimeFormats(entry);
    }
    return;
  }

  if (!value || typeof value !== "object") {
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (key === "format" && nested === "datetime") {
      value[key] = "date-time";
      continue;
    }

    normalizeDateTimeFormats(nested);
  }
}

function relaxDeleteRequestBodies(spec) {
  const requestBodies = spec.components?.requestBodies || {};

  for (const { method, operation } of iterateOperations(spec)) {
    if (method !== "DELETE" || !operation.requestBody) {
      continue;
    }

    const requestBody =
      operation.requestBody.$ref?.match(/^#\/components\/requestBodies\/(.+)$/)
        ? requestBodies[operation.requestBody.$ref.match(/^#\/components\/requestBodies\/(.+)$/)[1]]
        : operation.requestBody;

    if (!requestBody) {
      continue;
    }

    requestBody.required = false;

    if (
      typeof requestBody.description === "string" &&
      !requestBody.description.includes("some OpenAPI 3.0 tooling may ignore DELETE request bodies")
    ) {
      requestBody.description =
        `${requestBody.description} This DELETE operation requires a JSON body, and some OpenAPI 3.0 tooling may ignore DELETE request bodies.`.trim();
    }
  }
}

function syncTopLevelTags(spec) {
  const seen = new Set();
  const tags = [];
  const tagDescriptions = {
    "Email Broadcasts":
      "Authenticated operations for managing SES email broadcasts, templates, recipients, identities, dashboard metrics, and tenant settings.",
    GTM:
      "Authenticated operations for managing GTM configurations and advertising pixel integrations, including Facebook, Kwai, and TikTok events."
  };

  for (const pathItem of Object.values(spec.paths || {})) {
    if (!pathItem || typeof pathItem !== "object") {
      continue;
    }

    for (const operation of Object.values(pathItem)) {
      if (!operation || typeof operation !== "object" || !Array.isArray(operation.tags)) {
        continue;
      }

      for (const tag of operation.tags) {
        if (typeof tag !== "string" || seen.has(tag)) {
          continue;
        }

        seen.add(tag);
        tags.push({
          name: tag,
          description:
            tagDescriptions[tag] ||
            `Authenticated operations for managing ${naturalizeRequestSubject(tag, "the")} and related workflows.`
        });
      }
    }
  }

  spec.tags = tags;
}

function setOperationRequestSchema(
  operation,
  schemaRef,
  {
    contentType = "application/json",
    description = operation.requestBody?.description || "Request payload.",
    required = false
  } = {}
) {
  operation.requestBody = buildSchemaRefRequestBody(schemaRef, description, required, contentType);
}

function setOperationSecurity(operation, security) {
  operation.security = security;
}

function applyOperationOverride(spec, method, routePath, apply) {
  const operation = getOperation(spec, routePath, method);
  if (operation) {
    apply(operation);
  }
}

function applyTextOverrides(spec, overrides) {
  for (const [method, routePath, summary, description] of overrides) {
    applyOperationOverride(spec, method, routePath, (operation) => {
      setOperationText(operation, summary, description);
    });
  }
}

function applySpecMetadataOverrides(spec) {
  const securitySchemes = ensureObject(ensureObject(spec, "components"), "securitySchemes");
  const oauthScheme = spec.components?.securitySchemes?.oauth2;
  const authCodeFlow = oauthScheme?.flows?.authorizationCode;

  securitySchemes.appLoginJwt = {
    type: "http",
    scheme: "bearer",
    bearerFormat: "JWT",
    description:
      "JWT issued by Nexus user-login flows. Use this when an endpoint rejects OAuth access tokens and API keys."
  };

  if (authCodeFlow) {
    authCodeFlow.authorizationUrl = "https://auth.scalev.co/authorize";
    authCodeFlow.refreshUrl = "https://auth.scalev.co/token";
    authCodeFlow.tokenUrl = "https://auth.scalev.co/token";
  }

  if (spec.info) {
    spec.info.title = "Scalev API v2 (Nexus)";
  }
}

function applyRouteSpecificOverrides(spec) {
  const schemas = ensureObject(ensureObject(spec, "components"), "schemas");
  const currentUserResponseSchema = schemas.InferredUserControllerShowResponse;
  const currentUserDataProperties = currentUserResponseSchema?.properties?.data?.properties;
  const currentBusinessUserProperties = currentUserDataProperties?.current_business_user?.properties;
  const currentBusinessRoleProperties = currentBusinessUserProperties?.role?.properties;
  const currentBusinessProperties = currentUserDataProperties?.current_business?.properties;

  if (currentBusinessUserProperties) {
    currentBusinessUserProperties.current_business_roles = {
      type: "object",
      nullable: true,
      description:
        "Map of model names to the business role currently assigned to the authenticated user.",
      additionalProperties: {
        type: "string"
      }
    };
  }

  if (currentBusinessRoleProperties) {
    currentBusinessRoleProperties.permissions = {
      type: "object",
      nullable: true,
      description:
        "Expanded permission map for the current business role, including nested action groups when applicable.",
      additionalProperties: { $ref: "#/components/schemas/GenericValue" }
    };
    currentBusinessRoleProperties.permissions_metadata = {
      type: "object",
      nullable: true,
      description: "Additional metadata for the expanded permission map.",
      additionalProperties: { $ref: "#/components/schemas/GenericValue" }
    };
  }

  if (currentBusinessProperties) {
    currentBusinessProperties.is_epayment_enabled = {
      type: "boolean",
      description:
        "Whether e-payment is currently enabled for the business after Nexus applies its verification checks."
    };
    currentBusinessProperties.date_of_birth = {
      type: "string",
      nullable: true,
      description:
        "Date of birth exposed for the current business. Owners receive the full date string; non-owners may receive a masked day-only value."
    };
    currentBusinessProperties.verification_deadline_remaining_days = {
      type: "integer",
      description: "Remaining number of days before the current business verification deadline."
    };
    currentBusinessProperties.verification_quota = {
      type: "integer",
      description: "Remaining verification quota for the current business."
    };
    currentBusinessProperties.is_verified = {
      type: "boolean",
      description:
        "Whether the current business is verified after Nexus applies the same verification checks used in the app."
    };
  }

  if (currentUserDataProperties) {
    currentUserDataProperties.verification_quota = {
      type: "integer",
      description: "Remaining verification quota for the authenticated user."
    };
    currentUserDataProperties.current_business_subscription = {
      $ref: "#/components/schemas/CurrentUserBusinessSubscription"
    };
  }

  if (currentBusinessProperties?.owner?.properties) {
    currentBusinessProperties.owner.properties.verification_quota = {
      type: "integer",
      description: "Remaining verification quota for the current business owner."
    };
  }

  setSchema(schemas, "CurrentUserBusinessSubscription", {
    type: "object",
    properties: {
      id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      business_id: { oneOf: [{ type: "integer" }, { type: "string" }] },
      status: { type: "string" },
      current_period_start: { type: "string", format: "date-time" },
      current_period_end: { type: "string", format: "date-time" },
      monthly_order_limit: { type: "integer" },
      ai_spam_limit: { type: "integer" },
      active_pages_limit: { type: "integer" },
      team_members_limit: { type: "integer" },
      store_limit: { type: "integer" },
      data_time_limit: { type: "integer" },
      is_sharing_product: { type: "boolean" },
      is_product_affiliate: { type: "boolean" },
      mailev: { type: "boolean" },
      is_no_scalev_logo: { type: "boolean" },
      is_custom_domain: { type: "boolean" },
      is_resellership_system: { type: "boolean" },
      is_wa_integration_allowed: { type: "boolean" },
      is_moota_integration_allowed: { type: "boolean" },
      custom_domain_limit: { type: "integer" },
      is_epayment_allowed: { type: "boolean" },
      is_premium_hosting: { type: "boolean" },
      is_courier_aggregator: { type: "boolean" },
      epayment_fee_rate: { oneOf: [{ type: "number" }, { type: "string" }] },
      is_duitku_allowed: { type: "boolean" },
      is_gopay_allowed: { type: "boolean" },
      is_lms_banner: { type: "boolean" },
      can_send_whatsapp_messages: { type: "boolean" },
      form_auto_fill: { type: "boolean" },
      is_bank_transfer_allowed: { type: "boolean" },
      waylev_bot_eligibility: { type: "boolean" },
      current_pricing_plan: {
        $ref: "#/components/schemas/BusinessSubscriptionPricingPlanDetailed"
      },
      next_pricing_plan: {
        $ref: "#/components/schemas/BusinessSubscriptionPricingPlanDetailed"
      },
      latest_subscription_order: {
        $ref: "#/components/schemas/BusinessSubscriptionOrder"
      },
      latest_paid_subscription_order: {
        $ref: "#/components/schemas/BusinessSubscriptionOrder"
      },
      next_discount_rate: { oneOf: [{ type: "number" }, { type: "string" }] }
    }
  });

  setSchema(schemas, "InferredUserControllerRegenerateBackupCodesResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: {
        type: "object",
        properties: {
          backup_codes: {
            type: "array",
            items: { type: "string" }
          }
        }
      }
    }
  });

  setSchema(schemas, "InferredUserControllerCompleteTotpSetupResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: {
        type: "object",
        properties: {
          mfa_status: { $ref: "#/components/schemas/CurrentUserMfaStatus" },
          backup_codes: {
            type: "array",
            items: { type: "string" }
          }
        }
      }
    }
  });

  setSchema(schemas, "InferredUserControllerGetDiscourseSsoResponse", {
    type: "object",
    properties: {
      code: { type: "integer", example: 200 },
      status: { type: "string", example: "Success" },
      data: { $ref: "#/components/schemas/DiscourseSsoPayload" }
    }
  });

  applyOperationOverride(spec, "POST", "/v2/chatbot/analyze-conversation", (operation) => {
    operation.summary = "Analyze a Chat Conversation";
    operation.description =
      "Analyzes a conversation transcript and returns the chatbot analysis result.";
    setOperationRequestBodyDescription(
      operation,
      "Conversation transcript and metadata payload used for chatbot analysis."
    );
  });

  applyOperationOverride(
    spec,
    "PATCH",
    "/v2/course-sections/{section_uuid}/course-content-orders",
    (operation) => {
      operation.summary = "Reorder Course Content in a Course Section";
      operation.description =
        "Updates the display order of course content items inside the specified course section.";
      setOperationRequestBodyDescription(
        operation,
        "Ordered course content payload for the specified course section."
      );
    }
  );

  applyOperationOverride(spec, "POST", "/v2/shipments/ninja-plugin", (operation) => {
    operation.summary = "Configure the Ninja Shipment Plugin";
    operation.description =
      "Creates or updates the Ninja shipment plugin configuration for the authenticated business.";
    setOperationRequestSchema(operation, "#/components/schemas/NinjaPluginIntegrationRequest", {
      description: "Ninja shipment plugin configuration payload.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/shipments/ninja-plugin/sync-webhooks", (operation) => {
    operation.summary = "Sync Ninja Shipment Webhooks";
    operation.description =
      "Synchronizes Ninja shipment webhook registrations for the authenticated business.";
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "POST", "/v2/subscription-orders/{id}/pay-with-balance", (operation) => {
    operation.summary = "Pay a Subscription Order with Balance";
    operation.description =
      "Pays the specified subscription order using the business balance.";
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "POST", "/v2/warehouse-partners/{id}/generate-ca-origin", (operation) => {
    operation.summary = "Generate a Courier Aggregator Origin for a Warehouse Partner";
    operation.description =
      "Generates the courier aggregator origin data for the specified warehouse partner.";
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CourierAggregatorOriginRequest",
      "Courier aggregator code payload used to generate the warehouse partner origin mapping.",
      true
    );
  });

  applyOperationOverride(spec, "GET", "/v2/warehouses/{warehouse_id}/warehouse-partners", (operation) => {
    operation.summary = "List Warehouse Partners for a Warehouse";
    operation.description =
      "Returns warehouse partners associated with the specified warehouse.";
    operation.tags = ["Warehouse Partners"];
  });

  applyOperationOverride(spec, "POST", "/v2/warehouses/{warehouse_id}/warehouse-partners", (operation) => {
    operation.summary = "Create a Warehouse Partner for a Warehouse";
    operation.description =
      "Creates a warehouse partner association for the specified warehouse.";
    operation.tags = ["Warehouse Partners"];
  });

  applyOperationOverride(spec, "GET", "/v2/stores/{id}", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/StoreResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/stores", (operation) => {
    operation.parameters = (operation.parameters || []).map((parameter) =>
      parameter.in === "query" && parameter.name === "last_id"
        ? {
            ...parameter,
            description: "Last store ID for cursor-based pagination"
          }
        : parameter
    );
  });

  applyOperationOverride(spec, "POST", "/v2/stores", (operation) => {
    operation.responses = {
      ...Object.fromEntries(
        Object.entries(operation.responses || {}).filter(
          ([status]) => status !== "200" && status !== "201"
        )
      ),
      "200": {
        description: "Success",
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/StoreResponse"
            }
          }
        }
      }
    };
  });

  applyOperationOverride(spec, "PATCH", "/v2/stores/{id}", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/StoreResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/business-users/me/leave", (operation) => {
    operation.summary = "Leave the Current Business";
    operation.description =
      "Removes the authenticated user from the current business after password confirmation.";
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/LeaveBusinessRequest",
      "Password confirmation payload for leaving the current business.",
      true
    );
  });

  applyOperationOverride(spec, "POST", "/v2/business-users/me/switch-business-role", (operation) => {
    operation.summary = "Switch the Current Business Role";
    operation.description =
      "Switches the authenticated user's business role for a specific business capability model.";
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/SwitchBusinessRoleRequest",
      "Target model and role payload for switching the current business role.",
      true
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/api-keys", (operation) => {
    operation.summary = "Create a Business API Key";
    operation.description =
      "Creates a new API key for the authenticated business.";
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CreateBusinessApiKeyRequest",
      "Business API key creation payload.",
      true
    );
    operation.responses = {
      "200": {
        description: "Success",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/BusinessApiKeyResponse" }
          }
        }
      },
      ...Object.fromEntries(
        Object.entries(operation.responses || {}).filter(
          ([status]) => status !== "200" && status !== "201"
        )
      )
    };
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/api-keys", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessApiKeyListResponse"
    );
  });

  for (const method of ["GET", "PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/businesses/api-keys/{id}", (operation) => {
      setOperationPathParameterSchema(operation, "id", { type: "integer" });
      setOperationJsonResponse(
        operation,
        "200",
        "Success",
        "#/components/schemas/BusinessApiKeyResponse"
      );
    });
  }

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/businesses/api-keys/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/BusinessApiKeyUpdateRequest", {
        description: "Business API key update payload.",
        required: false
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/businesses/api-keys/{id}/rotate", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessApiKeyResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/applications", (operation) => {
    operation.summary = "Create an OAuth Application";
    operation.description =
      "Creates a new OAuth application owned by the authenticated business.";
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CreateOAuthApplicationRequest",
      "OAuth application creation payload.",
      true
    );
    operation.responses = {
      "200": {
        description: "Success",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/OwnedOAuthApplicationResponse" }
          }
        }
      },
      ...Object.fromEntries(
        Object.entries(operation.responses || {}).filter(
          ([status]) => status !== "200" && status !== "201"
        )
      )
    };
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/applications", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/OwnedOAuthApplicationListResponse"
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/applications/{id}", (operation) => {
    operation.summary = "Update an OAuth Application";
    operation.description =
      "Updates the specified OAuth application owned by the authenticated business.";
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/UpdateOAuthApplicationRequest",
      "OAuth application update payload.",
      true
    );
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/OwnedOAuthApplicationResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/applications/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/OwnedOAuthApplicationResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/applications/{id}/billing-tags", (operation) => {
    operation.summary = "Create an OAuth Application Billing Tag";
    operation.description =
      "Creates a billing tag for the specified OAuth application.";
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CreateOAuthApplicationBillingTagRequest",
      "Billing tag payload for the specified OAuth application.",
      true
    );
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/OwnedOAuthApplicationResponse"
    );
  });

  applyOperationOverride(
    spec,
    "PATCH",
    "/v2/businesses/applications/{id}/billing-tags/{billing_tag_id}/availability",
    (operation) => {
      operation.summary = "Update OAuth Application Billing Tag Availability";
      operation.description =
        "Updates whether the specified OAuth application billing tag is available for new approvals.";
      operation.requestBody = buildSchemaRefRequestBody(
        "#/components/schemas/UpdateOAuthApplicationBillingTagAvailabilityRequest",
        "Availability payload for the specified OAuth application billing tag.",
        true
      );
      setOperationPathParameterSchema(operation, "id", { type: "integer" });
      setOperationPathParameterSchema(operation, "billing_tag_id", { type: "integer" });
      setOperationJsonResponse(
        operation,
        "200",
        "Success",
        "#/components/schemas/OwnedOAuthApplicationResponse"
      );
    }
  );

  applyOperationOverride(spec, "POST", "/v2/businesses/applications/{id}/regenerate-secret", (operation) => {
    operation.summary = "Regenerate an OAuth Application Secret";
    operation.description =
      "Regenerates the client secret for the specified OAuth application.";
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/OwnedOAuthApplicationResponse"
    );
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/authorized-applications", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/AuthorizedApplicationListResponse"
    );
  });

  for (const method of ["GET", "POST"]) {
    for (const routePath of [
      "/v2/businesses/authorized-applications/{id}",
      "/v2/businesses/authorized-applications/{id}/disable",
      "/v2/businesses/authorized-applications/{id}/enable"
    ]) {
      applyOperationOverride(spec, method, routePath, (operation) => {
        setOperationPathParameterSchema(operation, "id", { type: "integer" });
        setOperationJsonResponse(
          operation,
          "200",
          "Success",
          "#/components/schemas/AuthorizedApplicationResponse"
        );
      });
    }
  }

  applyOperationOverride(spec, "GET", "/v2/businesses/authorized-applications/{id}/manage-link", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/AuthorizedApplicationManageLinkResponse"
    );
    setOperationResponseSchema(
      operation,
      "422",
      "Unprocessable Entity",
      "#/components/schemas/UnprocessableEntityError"
    );
    setOperationResponseSchema(
      operation,
      "500",
      "Internal Server Error",
      "#/components/schemas/InternalServerError"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/ads/views/{id}/chart", (operation) => {
    operation.summary = "Get an Ad View Chart";
    operation.description =
      "Builds the comparative chart payload for the specified ad view.";
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/AdViewChartRequest",
      "Date range and metric selection used to build the ad view chart.",
      true
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/AdViewChartResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/ads/views/{id}/cards", (operation) => {
    setOperationText(
      operation,
      "Get Ad View Metric Cards",
      "Builds the metric card payload for the specified ad view."
    );
    setOperationRequestSchema(operation, "#/components/schemas/AdViewCardsRequest", {
      description:
        "Date range, metric list, and optional campaign filter used to build the ad view card summary.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/ads/views/{id}/summary-table", (operation) => {
    setOperationText(
      operation,
      "Get an Ad View Summary Table",
      "Builds the summary table payload for the specified ad view."
    );
    setOperationRequestSchema(operation, "#/components/schemas/AdViewSummaryTableRequest", {
      description:
        "Metric list and optional campaign filter used to build the ad view summary table.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/ads/views/{id}/top-performance", (operation) => {
    setOperationText(
      operation,
      "Get Ad View Top Performance",
      "Builds the top-performance breakdown for the specified ad view."
    );
    setOperationRequestSchema(operation, "#/components/schemas/AdViewTopPerformanceRequest", {
      description:
        "Date range, breakdown type, and optional campaign filter used to build the ad view top-performance breakdown.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/ads/views/sync-metrics", (operation) => {
    setOperationText(
      operation,
      "Sync Ad View Metrics",
      "Synchronizes metrics for the specified advertising accounts."
    );
    setOperationRequestSchema(operation, "#/components/schemas/AdViewSyncMetricsRequest", {
      description: "Advertising account IDs used to synchronize cached ad view metrics.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/subscriptions", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/SubscriptionResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/subscriptions/{id}", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/SubscriptionResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/current", (operation) => {
    operation.summary = "Get Current Business";
    operation.description =
      "Returns the currently selected business for the authenticated business context.";
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/current/verification-payment", (operation) => {
    operation.summary = "List Current Business Verification Payments";
    operation.description =
      "Returns verification payment records for the currently selected business.";
    operation.parameters = [
      { $ref: "#/components/parameters/PageSizeQueryParameter" },
      {
        name: "status",
        in: "query",
        required: false,
        description: "Filter verification payments by status.",
        schema: { type: "string" }
      },
      {
        name: "last_id",
        in: "query",
        required: false,
        description: "Pagination cursor for continuing from the next older verification payment record.",
        schema: { type: "integer" }
      }
    ];
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/current/verification-payment/{id}", (operation) => {
    operation.summary = "Get Current Business Verification Payment";
    operation.description =
      "Returns a single verification payment record for the currently selected business.";
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/current/xendit-managed-account", (operation) => {
    operation.summary = "Get Current Business Xendit Managed Account";
    operation.description =
      "Returns the Xendit managed account configuration for the currently selected business.";
  });

  applyOperationOverride(spec, "GET", "/v2/users/me", (operation) => {
    operation.summary = "Get Current User";
    operation.description =
      "Returns the authenticated user profile together with the current business context. This route requires a user login JWT and rejects OAuth access tokens and API keys.";
  });

  applyOperationOverride(spec, "GET", "/v2/users/me/verification", (operation) => {
    operation.summary = "Get Current User Verification";
    operation.description =
      "Returns verification status and verification-related records for the authenticated user.";
  });

  applyTextOverrides(spec, [
    [
      "GET",
      "/v2/auth/jwt/productlift/create",
      "Create a Productlift JWT",
      "Returns a Productlift JWT access token for the authenticated user."
    ],
    [
      "GET",
      "/v2/auth/jwt/readme/create",
      "Create a ReadMe JWT",
      "Returns a ReadMe JWT access token for the authenticated user."
    ],
    [
      "GET",
      "/v2/businesses/all-payment-methods",
      "List All Payment Methods",
      "Returns all payment methods currently available to the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/all-epayment-methods",
      "List All E-Payment Methods",
      "Returns all e-payment methods currently available to the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/api-keys",
      "List Business API Keys",
      "Returns API keys owned by the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/api-keys/{id}",
      "Get a Business API Key",
      "Returns the specified API key owned by the authenticated business."
    ],
    [
      "PATCH",
      "/v2/businesses/api-keys/{id}",
      "Update a Business API Key",
      "Updates the specified API key owned by the authenticated business."
    ],
    [
      "PUT",
      "/v2/businesses/api-keys/{id}",
      "Update a Business API Key",
      "Updates the specified API key owned by the authenticated business."
    ],
    [
      "DELETE",
      "/v2/businesses/api-keys/{id}",
      "Delete a Business API Key",
      "Deletes the specified API key owned by the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/api-keys/{id}/rotate",
      "Rotate a Business API Key",
      "Rotates the secret for the specified business API key."
    ],
    [
      "GET",
      "/v2/businesses/api-keys/scopes",
      "List Business API Key Scopes",
      "Returns the API key scopes available to the authenticated business."
    ],
    [
      "DELETE",
      "/v2/businesses/applications/{id}",
      "Delete an OAuth Application",
      "Deletes the specified OAuth application owned by the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/authorized-applications",
      "List Authorized Applications",
      "Returns OAuth applications that have been authorized by the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/authorized-applications/{id}",
      "Get an Authorized Application",
      "Returns a single OAuth application authorized by the authenticated business."
    ],
    [
      "DELETE",
      "/v2/businesses/authorized-applications/{id}",
      "Revoke an Authorized Application",
      "Revokes the specified OAuth application authorization for the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/authorized-applications/{id}/disable",
      "Disable an Authorized Application",
      "Disables the specified OAuth application authorization for the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/authorized-applications/{id}/enable",
      "Enable an Authorized Application",
      "Enables the specified OAuth application authorization for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/authorized-applications/{id}/manage-link",
      "Get an Authorized Application Manage Link",
      "Returns the management link for the specified authorized application."
    ],
    [
      "GET",
      "/v2/businesses/blocked-ips",
      "List Blocked IP Addresses",
      "Returns blocked IP addresses configured for the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/blocked-ips",
      "Create a Blocked IP Address",
      "Adds a blocked IP address for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/blocked-ips/{id}",
      "Get a Blocked IP Address",
      "Returns the specified blocked IP address for the authenticated business."
    ],
    [
      "DELETE",
      "/v2/businesses/blocked-ips/{id}",
      "Delete a Blocked IP Address",
      "Removes the specified blocked IP address from the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/change-ownership",
      "Change Business Ownership",
      "Transfers ownership of the authenticated business to another user after OTP confirmation."
    ],
    [
      "DELETE",
      "/v2/businesses/epayment-methods",
      "Delete a Business E-Payment Method",
      "Removes an e-payment method from the authenticated business."
    ],
    [
      "PATCH",
      "/v2/businesses/epayment-methods",
      "Switch the Active Business E-Payment Method",
      "Switches the active e-payment method configuration for the authenticated business."
    ],
    [
      "POST",
      "/v2/business-users/me/deny",
      "Deny the Current Business Invitation",
      "Denies the pending invitation for the authenticated business user."
    ],
    [
      "POST",
      "/v2/customers/me/subscription-items/{id}/cancel",
      "Cancel a Subscription Item",
      "Cancels the specified subscription item for the authenticated customer and returns the updated subscription."
    ],
    [
      "GET",
      "/v2/customers/me/subscription-items/{id}/downgrade",
      "List Available Downgrade Variants for a Subscription Item",
      "Returns variant options the authenticated customer can use to downgrade the specified subscription item."
    ],
    [
      "POST",
      "/v2/customers/me/subscription-items/{id}/downgrade",
      "Downgrade a Subscription Item",
      "Schedules a downgrade for the specified subscription item and returns the updated subscription."
    ],
    [
      "POST",
      "/v2/customers/me/subscription-items/{id}/downgrade/cancel",
      "Cancel a Subscription Item Downgrade",
      "Cancels the scheduled downgrade for the specified subscription item and returns the updated subscription."
    ],
    [
      "POST",
      "/v2/customers/me/subscription-items/{id}/resume",
      "Resume a Subscription Item",
      "Resumes the specified subscription item and returns the updated subscription."
    ],
    [
      "GET",
      "/v2/customers/me/subscription-items/{id}/upgrade",
      "List Available Upgrade Variants for a Subscription Item",
      "Returns variant options the authenticated customer can use to upgrade the specified subscription item."
    ],
    [
      "POST",
      "/v2/customers/me/subscription-items/{id}/upgrade",
      "Upgrade a Subscription Item",
      "Schedules an upgrade for the specified subscription item and returns the updated subscription."
    ],
    [
      "POST",
      "/v2/customers/me/subscription-items/{id}/upgrade/cancel",
      "Cancel a Subscription Item Upgrade",
      "Cancels the scheduled upgrade for the specified subscription item and returns the updated subscription."
    ],
    [
      "POST",
      "/v2/customers/me/cart/checkout",
      "Check Out the Current Customer Cart",
      "Creates an order from the authenticated customer's active cart."
    ],
    [
      "POST",
      "/v2/customers/me/cart/items",
      "Add an Item to the Current Customer Cart",
      "Adds a variant to the authenticated customer's active cart and returns the updated cart."
    ],
    [
      "PATCH",
      "/v2/customers/me/cart/items/{item_id}",
      "Update an Item in the Current Customer Cart",
      "Updates the quantity for the specified cart item and returns the updated cart."
    ],
    [
      "DELETE",
      "/v2/customers/me/cart/items/{item_id}",
      "Delete an Item from the Current Customer Cart",
      "Removes the specified item from the authenticated customer's active cart and returns the updated cart."
    ],
    [
      "GET",
      "/v2/customers/me/checkout/addresses",
      "List Saved Checkout Addresses",
      "Returns saved checkout addresses for the authenticated customer."
    ],
    [
      "GET",
      "/v2/customers/me/checkout/payment-methods",
      "List Available Checkout Payment Methods",
      "Returns payment methods currently available for the authenticated customer's active cart."
    ],
    [
      "POST",
      "/v2/customers/me/checkout/shipping-options",
      "List Available Checkout Shipping Options",
      "Calculates shipping options for the authenticated customer's active cart."
    ],
    [
      "POST",
      "/v2/customers/me/checkout/summary",
      "Get the Current Customer Checkout Summary",
      "Calculates the current checkout summary for the authenticated customer's active cart."
    ],
    [
      "POST",
      "/v2/customers/me/checkout/confirm",
      "Confirm the Current Customer Checkout",
      "Creates an order from the authenticated customer's checkout data."
    ],
    [
      "GET",
      "/v2/customers/me/variants/{uuid}/course",
      "Get Current Customer Variant Course",
      "Returns the course skeleton and progress metadata for the specified customer-accessible variant."
    ],
    [
      "GET",
      "/v2/users/me/business",
      "List Current User Businesses",
      "Returns businesses that the authenticated user can access."
    ],
    [
      "POST",
      "/v2/users/me/confirm-email",
      "Confirm Current User Email",
      "Confirms the email address for the authenticated user."
    ],
    [
      "POST",
      "/v2/users/me/delete",
      "Delete Current User Account",
      "Deletes the authenticated user account after password confirmation."
    ],
    [
      "POST",
      "/v2/users/me/fcm-subscription",
      "Save Current User FCM Subscription",
      "Stores or refreshes the push notification subscription for the authenticated user device."
    ],
    [
      "DELETE",
      "/v2/users/me/fcm-subscription/{device_id}",
      "Delete Current User FCM Subscription",
      "Removes the push notification subscription for the specified authenticated user device."
    ],
    [
      "POST",
      "/v2/users/me/mfa/backup-codes/regenerate",
      "Regenerate Current User MFA Backup Codes",
      "Generates a new set of MFA backup codes for the authenticated user."
    ],
    [
      "GET",
      "/v2/users/me/mfa/status",
      "Get Current User MFA Status",
      "Returns the current MFA status for the authenticated user."
    ],
    [
      "POST",
      "/v2/users/me/mfa/totp/complete",
      "Complete Current User TOTP Setup",
      "Verifies the supplied secret and code to enable TOTP MFA for the authenticated user."
    ],
    [
      "POST",
      "/v2/users/me/mfa/totp/disable",
      "Disable Current User TOTP",
      "Disables TOTP MFA for the authenticated user after password and code verification."
    ],
    [
      "POST",
      "/v2/users/me/mfa/totp/initiate",
      "Initiate Current User TOTP Setup",
      "Starts TOTP MFA setup for the authenticated user and returns the setup payload."
    ],
    [
      "GET",
      "/v2/users/me/mfa/totp/qr-code",
      "Get Current User TOTP QR Code",
      "Returns the QR code payload for the authenticated user's active TOTP setup."
    ],
    [
      "POST",
      "/v2/users/me/otp",
      "Send Current User OTP",
      "Sends a one-time password for the authenticated user."
    ],
    [
      "PATCH",
      "/v2/users/me/payout-info",
      "Update Current User Payout Info",
      "Updates payout information for the authenticated user."
    ],
    [
      "POST",
      "/v2/users/me/resend-verification-email",
      "Resend Current User Verification Email",
      "Resends the verification email for the authenticated user."
    ],
    [
      "POST",
      "/v2/users/me/send-telegram-test-message",
      "Send a Telegram Test Message",
      "Sends a Telegram test message for the authenticated user."
    ],
    [
      "POST",
      "/v2/users/me/set-password",
      "Set Current User Password",
      "Sets or replaces the password for the authenticated user."
    ],
    [
      "GET",
      "/v2/users/me/simplified",
      "Get Simplified Current User",
      "Returns the simplified authenticated user payload."
    ],
    [
      "POST",
      "/v2/users/me/switch-business",
      "Switch Current User Business",
      "Switches the current business context for the authenticated user."
    ],
    [
      "PATCH",
      "/v2/users/me/tnc-privacy",
      "Update Current User Terms and Privacy Acceptance",
      "Updates the authenticated user's terms and privacy acceptance record."
    ],
    [
      "POST",
      "/v2/users/me/upload-avatar",
      "Upload Current User Avatar",
      "Uploads or replaces the authenticated user's avatar."
    ],
    [
      "GET",
      "/v2/businesses/waba",
      "List WhatsApp Business Accounts",
      "Returns WhatsApp Business Accounts connected to the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/waba/{id}",
      "Get a WhatsApp Business Account",
      "Returns the specified WhatsApp Business Account."
    ],
    [
      "PATCH",
      "/v2/businesses/waba/{id}",
      "Update a WhatsApp Business Account",
      "Updates the specified WhatsApp Business Account."
    ],
    [
      "DELETE",
      "/v2/businesses/waba/{id}",
      "Delete a WhatsApp Business Account",
      "Disconnects the specified WhatsApp Business Account from the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/waba/{id}/dataset",
      "Create a WhatsApp Dataset",
      "Creates dataset metadata for the specified WhatsApp Business Account."
    ],
    [
      "GET",
      "/v2/businesses/waba/{id}/message-attempts",
      "List WhatsApp Message Attempts",
      "Returns outbound message attempt records for the specified WhatsApp Business Account."
    ],
    [
      "GET",
      "/v2/businesses/waba/{id}/message-templates",
      "List WhatsApp Message Templates",
      "Returns message templates available for the specified WhatsApp Business Account."
    ],
    [
      "POST",
      "/v2/businesses/waba/{id}/register-phone",
      "Register a WhatsApp Phone Number",
      "Registers a phone number for the specified WhatsApp Business Account using the supplied PIN."
    ],
    [
      "POST",
      "/v2/businesses/waba/{id}/send-messages",
      "Send WhatsApp Template Messages",
      "Sends a batch of WhatsApp template messages for the specified WhatsApp Business Account."
    ],
    [
      "POST",
      "/v2/businesses/waba/{id}/sync",
      "Sync a WhatsApp Business Account",
      "Synchronizes metadata for the specified WhatsApp Business Account."
    ],
    [
      "POST",
      "/v2/businesses/waba/{id}/upload-media",
      "Upload WhatsApp Media",
      "Uploads a media asset to the specified WhatsApp Business Account."
    ],
    [
      "GET",
      "/v2/businesses/waba/{unique_id}/customers",
      "List WhatsApp Customers",
      "Returns WhatsApp customer conversations for the specified WhatsApp Business Account."
    ],
    [
      "PATCH",
      "/v2/businesses/waba/{unique_id}/customers/{id}",
      "Update a WhatsApp Customer",
      "Updates the specified WhatsApp customer conversation."
    ],
    [
      "POST",
      "/v2/businesses/waba/{unique_id}/customers/{id}/purchase",
      "Send a WhatsApp Purchase Event",
      "Sends a purchase event to the specified WhatsApp customer conversation."
    ],
    [
      "GET",
      "/v2/businesses/waba/{unique_id}/quick-replies",
      "List WhatsApp Quick Replies",
      "Returns quick replies configured for the specified WhatsApp Business Account."
    ],
    [
      "POST",
      "/v2/businesses/waba/{unique_id}/quick-replies",
      "Create a WhatsApp Quick Reply",
      "Creates a quick reply for the specified WhatsApp Business Account."
    ],
    [
      "PATCH",
      "/v2/businesses/waba/{unique_id}/quick-replies/{id}",
      "Update a WhatsApp Quick Reply",
      "Updates the specified quick reply for the selected WhatsApp Business Account."
    ],
    [
      "DELETE",
      "/v2/businesses/waba/{unique_id}/quick-replies/{id}",
      "Delete a WhatsApp Quick Reply",
      "Deletes the specified quick reply from the selected WhatsApp Business Account."
    ],
    [
      "GET",
      "/v2/businesses/waba/customer-tags",
      "List WhatsApp Customer Tags",
      "Returns WhatsApp customer tags available to the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/waba/customer-tags",
      "Create a WhatsApp Customer Tag",
      "Creates a WhatsApp customer tag for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/waba/customer-tags/{id}",
      "Get a WhatsApp Customer Tag",
      "Returns the specified WhatsApp customer tag."
    ],
    [
      "PATCH",
      "/v2/businesses/waba/customer-tags/{id}",
      "Update a WhatsApp Customer Tag",
      "Updates the specified WhatsApp customer tag."
    ],
    [
      "DELETE",
      "/v2/businesses/waba/customer-tags/{id}",
      "Delete a WhatsApp Customer Tag",
      "Deletes the specified WhatsApp customer tag."
    ],
    [
      "PATCH",
      "/v2/businesses/waba/login",
      "Connect a WhatsApp Business Account",
      "Connects a WhatsApp Business Account to the authenticated business."
    ]
  ]);

  for (const routePath of [
    "/v2/businesses/authorized-applications/{id}/disable",
    "/v2/businesses/authorized-applications/{id}/enable",
    "/v2/business-users/me/deny",
    "/v2/customers/me/subscription-items/{id}/cancel",
    "/v2/customers/me/subscription-items/{id}/resume",
    "/v2/customers/me/subscription-items/{id}/upgrade/cancel",
    "/v2/customers/me/subscription-items/{id}/downgrade/cancel",
    "/v2/businesses/current/resend-verification-email",
    "/v2/users/me/mfa/totp/initiate",
    "/v2/users/me/resend-verification-email",
    "/v2/businesses/waba/{id}/sync"
  ]) {
    applyOperationOverride(spec, "POST", routePath, (operation) => {
      delete operation.requestBody;
    });
  }

  applyOperationOverride(spec, "DELETE", "/v2/businesses/applications/{id}", (operation) => {
    delete operation.requestBody;
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/change-ownership", (operation) => {
    setOperationText(
      operation,
      "Change Business Ownership",
      "Transfers ownership of the authenticated business to another user after OTP confirmation by the current owner."
    );
    setOperationSecurity(operation, [{ bearerApiKey: [] }]);
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/ChangeBusinessOwnershipRequest",
      "New owner email and OTP payload used to transfer business ownership.",
      true
    );
  });

  applyOperationOverride(spec, "POST", "/v2/subscription-items/{id}/resume", (operation) => {
    setOperationText(
      operation,
      "Resume a Subscription Item Scheduled for Cancellation",
      "Resumes a subscription item that is scheduled to cancel at period end and returns the updated subscription."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/subscriptions/{id}/resume", (operation) => {
    setOperationText(
      operation,
      "Resume a Subscription Scheduled for Cancellation",
      "Resumes a subscription that is scheduled to cancel at period end and returns the updated subscription."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/subscription-items/{id}/resume", (operation) => {
    setOperationText(
      operation,
      "Resume a Current Customer Subscription Item Scheduled for Cancellation",
      "Resumes a current customer subscription item that is scheduled to cancel at period end and returns the updated subscription."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/subscriptions/{id}/resume", (operation) => {
    setOperationText(
      operation,
      "Resume a Current Customer Subscription Scheduled for Cancellation",
      "Resumes a current customer subscription that is scheduled to cancel at period end and returns the updated subscription."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/business-users/me/deny", (operation) => {
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/business-users/me/leave", (operation) => {
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/business-users/me/switch-business-role", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/SwitchBusinessRoleRequest",
      "Target model and role payload for switching the current business role.",
      true
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/close", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/PasswordConfirmationRequest",
      "Password confirmation payload for closing the current business.",
      true
    );
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/confirm-email", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/TokenConfirmationRequest",
      "Confirmation token payload for the current business email address change.",
      true
    );
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/resend-verification-email", (operation) => {
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(
    spec,
    "POST",
    "/v2/businesses/current/xendit-managed-account/resend-verification-email",
    (operation) => {
      setBlankSuccessResponse(operation);
    }
  );

  applyOperationOverride(
    spec,
    "POST",
    "/v2/businesses/current/xendit-managed-account/finalize",
    (operation) => {
      setOperationRequestSchema(
        operation,
        "#/components/schemas/FinalizeXenditManagedAccountRequest",
        {
          description: "Verification token payload used to finalize the current Xendit managed account.",
          required: true
        }
      );
      setOperationRequestBodyDescription(
        operation,
        "Verification token payload used to finalize the current Xendit managed account."
      );
    }
  );

  applyOperationOverride(spec, "POST", "/v2/users/me/delete", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/PasswordConfirmationRequest",
      "Password confirmation payload for deleting the authenticated user account.",
      true
    );
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "PATCH", "/v2/users/me", (operation) => {
    setOperationResponseRef(
      operation,
      "200",
      "#/components/responses/InferredUserControllerShowResponse"
    );
    setOperationRequestSchema(operation, "#/components/schemas/UserUpdateRequest", {
      description: "Authenticated user profile update payload.",
      required: false
    });
    setOperationRequestBodyDescription(
      operation,
      "Authenticated user profile update payload."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/confirm-email", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/TokenConfirmationRequest",
      "Confirmation token payload for the authenticated user's pending email address change.",
      true
    );
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/fcm-subscription", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/UserFcmSubscriptionRequest", {
      description:
        "Device and token payload used to register push notifications for the authenticated user.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Device and token payload used to register push notifications for the authenticated user."
    );
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "DELETE", "/v2/users/me/fcm-subscription/{device_id}", (operation) => {
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/otp", (operation) => {
    setOperationResponseRef(
      operation,
      "200",
      "#/components/responses/SuccessMessageResponse"
    );
    setOperationRequestSchema(operation, "#/components/schemas/UserOtpRequest", {
      description: "OTP purpose payload used to send a one-time password for the authenticated user.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "OTP purpose payload used to send a one-time password for the authenticated user."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/customers/me/orders/{id}", (operation) => {
    setOperationSecurity(operation, [{ bearerApiKey: [] }]);
    setOperationText(
      operation,
      "Get Current Customer Order",
      "Returns the current customer order for the authenticated customer."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/resend-verification-email", (operation) => {
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "PATCH", "/v2/users/me/payout-info", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/UserPayoutInfoRequest", {
      description: "Payout information payload for the authenticated user.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Payout information payload for the authenticated user."
    );
  });

  for (const routePath of [
    "/v2/users/me/resend-verification-email",
    "/v2/users/me/send-telegram-test-message"
  ]) {
    applyOperationOverride(spec, "POST", routePath, (operation) => {
      delete operation.requestBody;
    });
  }

  applyOperationOverride(spec, "POST", "/v2/users/me/send-telegram-test-message", (operation) => {
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/set-password", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/SetCurrentUserPasswordRequest",
      "Current and new password payload used to change the authenticated user's password.",
      true
    );
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/switch-business", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/SwitchCurrentUserBusinessRequest", {
      description:
        "Business selection payload used to switch the authenticated user's current business context.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Business selection payload used to switch the authenticated user's current business context."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/users/me/tnc-privacy", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/UserTermsPrivacyRequest", {
      description: "Terms and privacy acceptance payload for the authenticated user.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Terms and privacy acceptance payload for the authenticated user."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/upload-avatar", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/UserAvatarUploadRequest", {
      contentType: "multipart/form-data",
      description: "Multipart avatar upload payload for the authenticated user.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Multipart avatar upload payload for the authenticated user."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/mfa/totp/complete", (operation) => {
    setOperationRequestSchema(
      operation,
      "#/components/schemas/CompleteCurrentUserTotpSetupRequest",
      {
        description: "Secret and verification code payload used to complete TOTP setup.",
        required: true
      }
    );
    setOperationRequestBodyDescription(
      operation,
      "Secret and verification code payload used to complete TOTP setup."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/mfa/totp/disable", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/DisableCurrentUserTotpRequest", {
      description: "Password and TOTP or backup code payload used to disable MFA.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Password and TOTP or backup code payload used to disable MFA."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/users/me/mfa/backup-codes/regenerate", (operation) => {
    setOperationRequestSchema(
      operation,
      "#/components/schemas/RegenerateCurrentUserBackupCodesRequest",
      {
        description: "TOTP or backup code payload used to regenerate MFA backup codes.",
        required: true
      }
    );
    setOperationRequestBodyDescription(
      operation,
      "TOTP or backup code payload used to regenerate MFA backup codes."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/subscription-items/{id}/upgrade", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Variant selection payload used to upgrade the specified subscription item."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/subscription-items/{id}/downgrade", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Variant selection payload used to downgrade the specified subscription item."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{id}/register-phone", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "PIN payload used to register the phone number for the specified WhatsApp Business Account."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/waba/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WabaAccountUpdateRequest", {
      description:
        "Store assignment and runtime-owner payload for the specified WhatsApp Business Account.",
      required: false
    });
    setOperationRequestBodyDescription(
      operation,
      "WhatsApp Business Account update payload."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{id}/dataset", (operation) => {
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{id}/send-messages", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Template ID, recipient CSV upload, component values, and duplicate-prevention settings for the WhatsApp message batch."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{id}/upload-media", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WabaMediaUploadRequest", {
      contentType: "multipart/form-data",
      description: "Multipart media upload payload for the specified WhatsApp Business Account.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/waba/{unique_id}/customers/{id}", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Conversation assignment, tag, and customer metadata payload for the specified WhatsApp customer."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{unique_id}/customers/{id}/purchase", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Purchase event payload to send to the specified WhatsApp customer conversation."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{unique_id}/quick-replies", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Quick reply code and message payload for the specified WhatsApp Business Account."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/waba/{unique_id}/quick-replies/{id}", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Quick reply update payload for the specified WhatsApp Business Account."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/customer-tags", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Customer tag payload for the authenticated business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/waba/customer-tags/{id}", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Customer tag update payload for the authenticated business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/waba/login", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "WhatsApp Business Account login payload containing the WABA ID, business ID, authorization code, and optional phone number ID."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/users/me/verification", (operation) => {
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/courier", (operation) => {
    setOperationText(
      operation,
      "Create a Business Courier",
      "Creates a courier configuration for the authenticated business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/BusinessCourierRequest", {
      description: "Courier configuration payload for the authenticated business.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Courier configuration payload for the authenticated business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/courier/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessCourierRequest", {
      description: "Courier update payload for the specified business courier.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Courier update payload for the specified business courier."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/courier-aggregator", (operation) => {
    setOperationText(
      operation,
      "Create a Business Courier Aggregator",
      "Creates a courier aggregator configuration for the authenticated business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/BusinessCourierAggregatorRequest", {
      description: "Courier aggregator configuration payload for the authenticated business.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Courier aggregator configuration payload for the authenticated business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/courier-aggregator/{id}", (operation) => {
    setOperationRequestSchema(
      operation,
      "#/components/schemas/BusinessCourierAggregatorRequest",
      {
        description: "Courier aggregator update payload for the specified configuration.",
        required: true
      }
    );
    setOperationRequestBodyDescription(
      operation,
      "Courier aggregator update payload for the specified configuration."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/events/{unique_id}/resend", (operation) => {
    setOperationText(
      operation,
      "Resend a Business Event",
      "Resends the specified business event."
    );
    delete operation.requestBody;
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/set-new-password", (operation) => {
    setOperationText(
      operation,
      "Set a New Password for the Current Customer",
      "Sets a new password for the authenticated customer."
    );
    setOperationRequestSchema(
      operation,
      "#/components/schemas/CustomerSetNewPasswordRequest",
      {
        description: "New password payload for the authenticated customer.",
        required: true
      }
    );
    setOperationResponseRef(
      operation,
      "200",
      "#/components/responses/InferredCustomerControllerMeResponse"
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/customers/me/course-contents/{uuid}", (operation) => {
    setOperationRequestSchema(
      operation,
      "#/components/schemas/CustomerCourseContentProgressRequest",
      {
        description: "Integer progress payload used to update the current customer's course content progress.",
        required: true
      }
    );
  });

  applyOperationOverride(spec, "POST", "/v2/oauth/billing/reservations", (operation) => {
    setOperationResponseRef(
      operation,
      "200",
      "#/components/responses/SuccessObjectResponse"
    );
    delete operation.responses?.["201"];
  });

  applyOperationOverride(spec, "POST", "/v2/oauth/billing/reservations/{id}/release", (operation) => {
    delete operation.responses?.["404"];
  });

  for (const routePath of [
    "/v2/ads/custom-metrics/count",
    "/v2/ads/views/count",
    "/v2/affiliated-businesses/count",
    "/v2/bundles/count",
    "/v2/businesses/applications/count",
    "/v2/customers/count",
    "/v2/products/count"
  ]) {
    applyOperationOverride(spec, "GET", routePath, (operation) => {
      operation.parameters = [];
      delete operation.responses?.["404"];
    });
  }

  applyOperationOverride(spec, "GET", "/v2/affiliated-businesses/count", (operation) => {
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/blocked-ips", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BlockedIpCreateRequest", {
      description: "Blocked IP payload for the authenticated business.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Blocked IP payload for the authenticated business."
    );
  });

  applyOperationOverride(spec, "DELETE", "/v2/businesses/epayment-methods", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessEpaymentMethodRequest", {
      description:
        "E-payment method payload used to remove a payment configuration from the authenticated business.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "E-payment method payload used to remove a payment configuration from the authenticated business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/epayment-methods", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessEpaymentMethodRequest", {
      description:
        "E-payment method payload used to switch the active payment configuration for the authenticated business.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "E-payment method payload used to switch the active payment configuration for the authenticated business."
    );
  });

  for (const routePath of ["/v2/businesses/epayment-methods"]) {
    for (const method of ["DELETE", "PATCH"]) {
      applyOperationOverride(spec, method, routePath, (operation) => {
        setBlankSuccessResponse(operation);
      });
    }
  }

  applyOperationOverride(spec, "GET", "/v2/shipments/ninja-plugin", (operation) => {
    setOperationText(
      operation,
      "Get Ninja Shipment Plugin Configuration",
      "Returns the current Ninja shipment plugin configuration for the authenticated business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/shipments/ninja-plugin", (operation) => {
    setOperationText(
      operation,
      "Update Ninja Shipment Plugin Configuration",
      "Updates the current Ninja shipment plugin configuration for the authenticated business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/NinjaPluginUpdateRequest", {
      description: "Updated Ninja shipment plugin configuration payload.",
      required: true
    });
  });

  applyOperationOverride(spec, "DELETE", "/v2/shipments/ninja-plugin", (operation) => {
    setOperationText(
      operation,
      "Delete Ninja Shipment Plugin Configuration",
      "Deletes the current Ninja shipment plugin configuration for the authenticated business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/current", (operation) => {
    setOperationText(
      operation,
      "Update Current Business",
      "Updates the currently selected business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/BusinessUpdateRequest", {
      description: "Business profile payload for the currently selected business.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/close", (operation) => {
    setOperationText(
      operation,
      "Close Current Business",
      "Closes the currently selected business."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/confirm-email", (operation) => {
    setOperationText(
      operation,
      "Confirm Current Business Email",
      "Confirms the email address for the currently selected business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/current/legal", (operation) => {
    setOperationText(
      operation,
      "Update Current Business Legal Details",
      "Updates legal details for the currently selected business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/BusinessLegalUpdateRequest", {
      description:
        "Corporation legal-profile fields to update on the currently selected business.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/resend-verification-email", (operation) => {
    setOperationText(
      operation,
      "Resend Current Business Verification Email",
      "Resends the verification email for the currently selected business."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/switch-to-xp-managed", (operation) => {
    setOperationText(
      operation,
      "Switch Current Business to XP Managed",
      "Switches the currently selected business to the XP-managed mode."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/switch-to-xp-owned", (operation) => {
    setOperationText(
      operation,
      "Switch Current Business to XP Owned",
      "Switches the currently selected business to the XP-owned mode."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/update-metadata", (operation) => {
    setOperationText(
      operation,
      "Update Current Business Metadata",
      "Updates metadata for the currently selected business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/BusinessMetadataUpdateRequest", {
      description:
        "Metadata keys to merge into the currently selected business metadata object.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/upload-logo", (operation) => {
    setOperationText(
      operation,
      "Upload Current Business Logo",
      "Uploads or replaces the logo for the currently selected business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/BusinessLogoUploadRequest", {
      contentType: "multipart/form-data",
      description: "Multipart logo upload payload for the currently selected business.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/verification", (operation) => {
    setOperationText(
      operation,
      "Submit Current Business Verification",
      "Submits verification data for the currently selected business."
    );
    setOperationSecurity(operation, [
      { bearerApiKey: [] },
      { oauth2: ["business:update"] }
    ]);
    setOperationRequestSchema(operation, "#/components/schemas/BusinessVerificationRequest", {
      contentType: "multipart/form-data",
      description:
        "Verification submission payload for the currently selected business, including uploaded images when the chosen verification flow requires them.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/verification-payment", (operation) => {
    setOperationText(
      operation,
      "Create Current Business Verification Payment",
      "Creates a verification payment record for the currently selected business."
    );
    setOperationRequestSchema(
      operation,
      "#/components/schemas/BusinessVerificationPaymentRequest",
      {
        description:
          "Verification payment method payload for the currently selected business.",
        required: false
      }
    );
    delete operation.responses?.["201"];
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/events", (operation) => {
    operation.parameters = [
      { $ref: "#/components/parameters/PageSizeQueryParameter" },
      {
        name: "next",
        in: "query",
        required: false,
        description: "Timestamp cursor used to continue event pagination.",
        schema: { type: "string", format: "date-time" }
      },
      {
        name: "unique_id",
        in: "query",
        required: false,
        description: "Filter events by unique event ID.",
        schema: { type: "string" }
      },
      {
        name: "search",
        in: "query",
        required: false,
        deprecated: true,
        description: "Deprecated alias for `unique_id`.",
        schema: { type: "string" }
      },
      {
        name: "entity_type",
        in: "query",
        required: false,
        description: "Filter events by entity type.",
        schema: { type: "string" }
      },
      {
        name: "entity_id",
        in: "query",
        required: false,
        description: "Filter events by entity ID.",
        schema: { type: "string" }
      },
      {
        name: "events",
        in: "query",
        required: false,
        description: "Comma-separated event names to include.",
        schema: { type: "string" }
      },
      {
        name: "statuses",
        in: "query",
        required: false,
        description: "Comma-separated HTTP statuses to include.",
        schema: { type: "string" }
      },
      {
        name: "since",
        in: "query",
        required: false,
        description: "Only return events created at or after this timestamp.",
        schema: { type: "string", format: "date-time" }
      },
      {
        name: "until",
        in: "query",
        required: false,
        description: "Only return events created before this timestamp window closes.",
        schema: { type: "string", format: "date-time" }
      }
    ];
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessEventListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/events/{unique_id}/logs", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessWebhookLogListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/machine-api-logs", (operation) => {
    operation.parameters = [
      { $ref: "#/components/parameters/PageSizeQueryParameter" },
      {
        name: "last_id",
        in: "query",
        required: false,
        description: "UUID cursor for machine API log pagination.",
        schema: { type: "string", format: "uuid" }
      },
      {
        name: "search",
        in: "query",
        required: false,
        description: "Filter by request UUID or request ID.",
        schema: { type: "string" }
      },
      {
        name: "methods",
        in: "query",
        required: false,
        description: "Comma-separated HTTP methods to include.",
        schema: { type: "string" }
      },
      {
        name: "statuses",
        in: "query",
        required: false,
        description: "Comma-separated response statuses to include.",
        schema: { type: "string" }
      },
      {
        name: "auth_methods",
        in: "query",
        required: false,
        description: "Comma-separated authentication methods to include.",
        schema: { type: "string" }
      },
      {
        name: "api_key_ids",
        in: "query",
        required: false,
        description: "Comma-separated API key IDs to include.",
        schema: { type: "string" }
      },
      {
        name: "oauth_application_ids",
        in: "query",
        required: false,
        description: "Comma-separated OAuth application IDs to include.",
        schema: { type: "string" }
      },
      {
        name: "base_url",
        in: "query",
        required: false,
        description: "Filter by the exact request base URL.",
        schema: { type: "string" }
      },
      {
        name: "since",
        in: "query",
        required: false,
        description: "Only return logs created at or after this timestamp.",
        schema: { type: "string", format: "date-time" }
      },
      {
        name: "until",
        in: "query",
        required: false,
        description: "Only return logs created before this timestamp window closes.",
        schema: { type: "string", format: "date-time" }
      }
    ];
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/MachineApiLogListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/machine-api-logs/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "string", format: "uuid" });
    setOperationPathParameterDescription(operation, "id", "UUID of the machine API log");
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/MachineApiLogResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/xendit-managed-account", (operation) => {
    setOperationText(
      operation,
      "Create Current Business Xendit Managed Account",
      "Creates a Xendit managed account for the currently selected business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/XenditManagedAccountCreateRequest", {
      description: "Invitation email payload for creating a Xendit managed account.",
      required: true
    });
    delete operation.responses?.["201"];
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/current/xendit-managed-account", (operation) => {
    setOperationText(
      operation,
      "Update Current Business Xendit Managed Account",
      "Updates the Xendit managed account for the currently selected business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/XenditManagedAccountUpdateRequest", {
      description:
        "Email or enabled payment-method payload for the current Xendit managed account.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/current/xendit-managed-account/finalize", (operation) => {
    setOperationText(
      operation,
      "Finalize Current Business Xendit Managed Account",
      "Finalizes the Xendit managed account setup for the currently selected business."
    );
    setOperationRequestBodyDescription(
      operation,
      "Verification token payload used to finalize the current business Xendit managed account."
    );
  });

  applyOperationOverride(
    spec,
    "POST",
    "/v2/businesses/current/xendit-managed-account/resend-verification-email",
    (operation) => {
      setOperationText(
        operation,
        "Resend Xendit Managed Account Verification Email",
        "Resends the Xendit managed account verification email for the currently selected business."
      );
    }
  );

  applyOperationOverride(spec, "GET", "/v2/my-affiliate-orders", (operation) => {
    setOperationText(
      operation,
      "List My Affiliate Orders",
      "Returns affiliate orders that belong to the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/my-affiliate-orders/{id}", (operation) => {
    setOperationText(
      operation,
      "Get My Affiliate Order",
      "Returns a single affiliate order that belongs to the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/my-partners", (operation) => {
    setOperationText(
      operation,
      "List My Partners",
      "Returns partners associated with the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/my-partners/{id}", (operation) => {
    setOperationText(
      operation,
      "Get My Partner",
      "Returns a single partner associated with the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/my-partners/{id}/partnerships", (operation) => {
    setOperationText(
      operation,
      "List Partnerships for My Partner",
      "Returns partnerships associated with the specified partner."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/my-partnerships", (operation) => {
    setOperationText(
      operation,
      "List My Partnerships",
      "Returns partnerships that belong to the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/my-partnerships/{id}", (operation) => {
    setOperationText(
      operation,
      "Get My Partnership",
      "Returns a single partnership that belongs to the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/partnership-marketplace", (operation) => {
    setOperationText(
      operation,
      "List Partnership Marketplace Offers",
      "Returns partnership marketplace offers available to the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/partnership-marketplace/{secret}", (operation) => {
    setOperationText(
      operation,
      "Get a Partnership Marketplace Offer",
      "Returns a partnership marketplace offer identified by its secret."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/partnership-marketplace/{secret}/request", (operation) => {
    setOperationText(
      operation,
      "Request a Partnership Marketplace Offer",
      "Creates a partnership request for the marketplace offer identified by its secret."
    );
    setOperationRequestSchema(
      operation,
      "#/components/schemas/PartnershipRequestCreateRequest",
      {
        description: "Partnership request payload for the marketplace offer identified by its secret.",
        required: true
      }
    );
    setOperationRequestBodyDescription(
      operation,
      "Partnership request payload for the marketplace offer identified by its secret."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/auth/sso/discourse", (operation) => {
    setOperationText(
      operation,
      "Generate a Discourse SSO Payload",
      "Generates the signed SSO payload used to log the authenticated user into Discourse."
    );
    setOperationRequestSchema(operation, "#/components/schemas/DiscourseSsoRequest", {
      description:
        "Discourse SSO nonce and signature payload used to generate the signed login response.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/auth/token", (operation) => {
    setOperationText(
      operation,
      "Create an SSO Authorization Code",
      "Creates an SSO authorization code for the authenticated user."
    );
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CreateSsoAuthorizationCodeRequest",
      "OAuth client, PKCE challenge, redirect URI, and optional state used to create the authorization code.",
      true
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/SsoAuthorizationCodeResponse"
    );
    delete operation.responses?.["201"];
  });

  applyOperationOverride(spec, "GET", "/v2/auth/jwt/productlift/create", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/JwtAccessTokenPayload"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/auth/jwt/readme/create", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/JwtAccessTokenPayload"
    );
  });

  const pixelFamilies = [
    {
      basePath: "/v2/fb-pixels",
      singular: "Facebook Pixel",
      singularNoun: "Facebook pixel",
      plural: "Facebook Pixels",
      pluralNoun: "Facebook pixels"
    },
    {
      basePath: "/v2/kwai-pixels",
      singular: "Kwai Pixel",
      singularNoun: "Kwai pixel",
      plural: "Kwai Pixels",
      pluralNoun: "Kwai pixels"
    },
    {
      basePath: "/v2/tiktok-pixels",
      singular: "TikTok Pixel",
      singularNoun: "TikTok pixel",
      plural: "TikTok Pixels",
      pluralNoun: "TikTok pixels"
    }
  ];

  for (const family of pixelFamilies) {
    applyOperationOverride(spec, "GET", family.basePath, (operation) => {
      setOperationText(
        operation,
        `List ${family.plural}`,
        `Returns the ${family.pluralNoun} for the authenticated business.`
      );
    });
    applyOperationOverride(spec, "POST", family.basePath, (operation) => {
      setOperationText(
        operation,
        `Create a ${family.singular}`,
        `Creates a ${family.singularNoun} for the authenticated business.`
      );
    });
    applyOperationOverride(spec, "GET", `${family.basePath}/{id}`, (operation) => {
      setOperationText(
        operation,
        `Get a ${family.singular}`,
        `Returns the specified ${family.singularNoun}.`
      );
    });
    applyOperationOverride(spec, "PATCH", `${family.basePath}/{id}`, (operation) => {
      setOperationText(
        operation,
        `Update a ${family.singular}`,
        `Updates the specified ${family.singularNoun}.`
      );
    });
    applyOperationOverride(spec, "DELETE", `${family.basePath}/{id}`, (operation) => {
      setOperationText(
        operation,
        `Delete a ${family.singular}`,
        `Deletes the specified ${family.singularNoun}.`
      );
    });
  }

  applyOperationOverride(spec, "GET", "/v2/fb-standard-events", (operation) => {
    setOperationText(
      operation,
      "List Facebook Standard Events",
      "Returns Facebook standard event options for the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/kwai-standard-events", (operation) => {
    setOperationText(
      operation,
      "List Kwai Standard Events",
      "Returns Kwai standard event options for the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/tiktok-standard-events", (operation) => {
    setOperationText(
      operation,
      "List TikTok Standard Events",
      "Returns TikTok standard event options for the authenticated business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/birdsend-integrations/{birdsend_integration_id}/refresh-access-token", (operation) => {
    setOperationText(
      operation,
      "Refresh a Birdsend Integration Access Token",
      "Refreshes the access token for the specified Birdsend integration."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/birdsend-integrations/{birdsend_integration_id}/sync", (operation) => {
    setOperationText(
      operation,
      "Sync Birdsend Sequences",
      "Synchronizes the latest Birdsend sequence catalog into Nexus for the specified integration."
    );
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "GET", "/v2/birdsend-integrations/{birdsend_integration_id}/sequences", (operation) => {
    setOperationText(
      operation,
      "List Birdsend Integration Sequences",
      "Returns the sequence list currently available for the specified Birdsend integration."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/customers/me", (operation) => {
  });

  applyOperationOverride(spec, "POST", "/v2/customers", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessCustomerCreateRequest", {
      description: "Customer creation payload for the authenticated business.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/customers/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/BusinessCustomerUpdateRequest", {
        description: "Customer update payload for the authenticated business.",
        required: false
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/customers/{business_customer_id}/addresses", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessCustomerAddressRequest", {
      description: "Address payload for the specified business customer.",
      required: false
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/customers/{business_customer_id}/addresses/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessCustomerAddressRequest", {
      description: "Address update payload for the specified business customer.",
      required: false
    });
  });

  applyOperationOverride(spec, "GET", "/v2/customers/me/storefront/checkout-page", (operation) => {
    setOperationText(
      operation,
      "Get Current Customer Storefront Checkout Page",
      "Returns the authenticated customer's checkout-page payload, including saved customer addresses and the storefront page configuration built from the current cart."
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CurrentCustomerCheckoutPageResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/customers/me/cart", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CustomerCartResponse"
    );
  });

  applyOperationOverride(
    spec,
    "GET",
    "/v2/businesses/waba/{waba_unique_id}/customers/{wa_user_id}/messages",
    (operation) => {
      setOperationText(
        operation,
        "List WhatsApp Messages for a Customer",
        "Returns WhatsApp messages for the specified customer in the selected WhatsApp Business Account."
      );
    }
  );

  applyOperationOverride(
    spec,
    "POST",
    "/v2/businesses/waba/{waba_unique_id}/customers/{wa_user_id}/messages",
    (operation) => {
      setOperationText(
        operation,
        "Send a WhatsApp Message to a Customer",
        "Sends a WhatsApp message to the specified customer in the selected WhatsApp Business Account."
      );
      setOperationRequestBodyDescription(
        operation,
        "WhatsApp message payload for the specified customer."
      );
    }
  );

  applyOperationOverride(
    spec,
    "POST",
    "/v2/businesses/waba/{waba_unique_id}/customers/{wa_user_id}/message-template",
    (operation) => {
      setOperationText(
        operation,
        "Send a WhatsApp Template Message to a Customer",
        "Sends a WhatsApp template message to the specified customer in the selected WhatsApp Business Account."
      );
      setOperationRequestSchema(operation, "#/components/schemas/WabaCustomerTemplateMessageRequest", {
        contentType: "multipart/form-data",
        description: "Template ID, optional header image, and component payload used to send the WhatsApp template message.",
        required: true
      });
    }
  );

  applyOperationOverride(
    spec,
    "GET",
    "/v2/businesses/waba/{waba_unique_id}/customers/{wa_user_id}/messages/{wamid}",
    (operation) => {
      setOperationText(
        operation,
        "Get a WhatsApp Customer Message",
        "Returns the specified WhatsApp message for the customer in the selected WhatsApp Business Account."
      );
      setOperationJsonResponse(
        operation,
        "200",
        "Success",
        "#/components/schemas/WabaMessageResponse"
      );
    }
  );

  applyOperationOverride(
    spec,
    "PATCH",
    "/v2/businesses/waba/{waba_unique_id}/customers/{wa_user_id}/messages/{wamid}",
    (operation) => {
      setOperationText(
        operation,
        "Update a WhatsApp Customer Message",
        "Updates the specified WhatsApp message for the customer in the selected WhatsApp Business Account."
      );
      operation.requestBody = buildSchemaRefRequestBody(
        "#/components/schemas/WabaMessageUpdateRequest",
        "Message status update payload.",
        true
      );
      setOperationJsonResponse(
        operation,
        "200",
        "Success",
        "#/components/schemas/WabaMessageResponse"
      );
    }
  );

  applyOperationOverride(
    spec,
    "DELETE",
    "/v2/businesses/waba/{waba_unique_id}/customers/{wa_user_id}/messages/{wamid}",
    (operation) => {
      setOperationText(
        operation,
        "Delete a WhatsApp Customer Message",
        "Deletes the specified WhatsApp message for the customer in the selected WhatsApp Business Account."
      );
      delete operation.requestBody;
      operation.responses = {
        "200": {
          $ref: "#/components/responses/BlankSuccessApiResponse"
        },
        ...Object.fromEntries(
          Object.entries(operation.responses || {}).filter(([status]) => status !== "200")
        )
      };
    }
  );

  applyOperationOverride(spec, "POST", "/v2/customers/me/cart/items", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CustomerCartItemAddRequest",
      "Variant and quantity to add to the authenticated customer's cart.",
      true
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CustomerCartResponse"
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/customers/me/cart/items/{item_id}", (operation) => {
    operation.parameters = (operation.parameters || []).map((parameter) =>
      parameter.name === "item_id"
        ? {
            ...parameter,
            description: "ID of the cart item",
            schema: { type: "integer" }
          }
        : parameter
    );
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CustomerCartItemUpdateRequest",
      "Updated quantity for the specified cart item.",
      true
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CustomerCartResponse"
    );
  });

  applyOperationOverride(spec, "DELETE", "/v2/customers/me/cart/items/{item_id}", (operation) => {
    operation.parameters = (operation.parameters || []).map((parameter) =>
      parameter.name === "item_id"
        ? {
            ...parameter,
            description: "ID of the cart item",
            schema: { type: "integer" }
          }
        : parameter
    );
    delete operation.requestBody;
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CustomerCartResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/cart/checkout", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CustomerCartCheckoutRequest",
      "Checkout request payload for the authenticated customer's active cart.",
      true
    );
    setOperationJsonResponse(
      operation,
      "201",
      "Created",
      "#/components/schemas/CustomerCartCheckoutResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/customers/me/checkout/addresses", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CheckoutAddressesResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/customers/me/checkout/payment-methods", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CheckoutPaymentMethodsResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/checkout/shipping-options", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CheckoutShippingOptionsRequest",
      "Destination data used to calculate available shipping options.",
      true
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CheckoutShippingOptionsResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/checkout/summary", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CheckoutSummaryRequest",
      "Checkout values used to calculate the current order summary.",
      false
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CheckoutSummaryResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/checkout/confirm", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CheckoutConfirmRequest",
      "Checkout confirmation payload for creating an order from the authenticated customer's cart.",
      true
    );
    setOperationJsonResponse(
      operation,
      "201",
      "Created",
      "#/components/schemas/CheckoutConfirmResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/ses/email-identities", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CreateEmailIdentityRequest",
      "SES email identity creation payload.",
      true
    );
  });

  applyOperationOverride(spec, "GET", "/v2/ses/email-identities", (operation) => {
    const parameterMap = new Map(
      (operation.parameters || []).map((parameter) => [`${parameter.in}:${parameter.name}`, parameter])
    );
    parameterMap.set("query:verified", {
      in: "query",
      name: "verified",
      required: false,
      description: "When `true`, only verified email identities are returned.",
      schema: {
        type: "boolean"
      }
    });
    operation.parameters = Array.from(parameterMap.values());
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/EmailIdentityListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/stores/{store_id}/storefront", (operation) => {
    setOperationText(
      operation,
      "Get Storefront Checkout Settings",
      "Returns the checkout storefront configuration for the specified store."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/stores/{store_id}/storefront", (operation) => {
    setOperationText(
      operation,
      "Update Storefront Checkout Settings",
      "Updates the checkout storefront configuration for the specified store."
    );
    setOperationRequestSchema(operation, "#/components/schemas/StorefrontUpdateRequest", {
      description: "Checkout storefront configuration payload for the specified store.",
      required: false
    });
  });

  applyOperationOverride(spec, "GET", "/v2/stores/{store_id}/storefront-homepage", (operation) => {
    setOperationText(
      operation,
      "Get Storefront Homepage Settings",
      "Returns the homepage storefront configuration for the specified store."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/stores/{store_id}/storefront-homepage", (operation) => {
    setOperationText(
      operation,
      "Update Storefront Homepage Settings",
      "Updates the homepage storefront configuration for the specified store."
    );
    setOperationRequestSchema(operation, "#/components/schemas/StorefrontUpdateRequest", {
      description: "Homepage storefront configuration payload for the specified store.",
      required: false
    });
  });

  applyOperationOverride(spec, "GET", "/v2/stores/{store_id}/storefront/download/custom-html", (operation) => {
    setOperationText(
      operation,
      "Download Storefront Custom HTML",
      "Downloads the custom checkout storefront HTML for the specified store."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/variants/{variant_id}/digital-product-files", (operation) => {
    setOperationText(
      operation,
      "Create a Digital Product File Upload",
      "Creates a digital product file record and returns the upload details for the specified variant."
    );
    setOperationRequestSchema(operation, "#/components/schemas/DigitalProductFileUploadRequest", {
      description: "Digital product file upload metadata for the specified variant.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Digital product file upload metadata for the specified variant."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/warehouses/{id}/generate-ca-origin", (operation) => {
    setOperationText(
      operation,
      "Generate a Courier Aggregator Origin for a Warehouse",
      "Generates the courier aggregator origin data for the specified warehouse."
    );
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/CourierAggregatorOriginRequest",
      "Courier aggregator code payload used to generate the warehouse origin mapping.",
      true
    );
  });

  applyOperationOverride(spec, "GET", "/v2/warehouse-partners/{id}", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/WarehousePartnerResponse"
    );
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/warehouse-partners/{id}", (operation) => {
      operation.requestBody = buildSchemaRefRequestBody(
        "#/components/schemas/WarehousePartnerUpdateRequest",
        "Compliance update payload for the specified warehouse partner.",
        true
      );
      setOperationJsonResponse(
        operation,
        "200",
        "Success",
        "#/components/schemas/WarehousePartnerResponse"
      );
    });
  }

  applyOperationOverride(spec, "POST", "/v2/warehouse-partners/{id}/generate-ca-origin", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/WarehousePartnerResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/warehouses/{warehouse_id}/warehouse-partners", (operation) => {
    operation.tags = ["Warehouse Partners"];
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/WarehousePartnerListResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/warehouses/{warehouse_id}/warehouse-partners", (operation) => {
    operation.tags = ["Warehouse Partners"];
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/WarehousePartnerCreateRequest",
      "Warehouse partner association payload.",
      true
    );
    operation.responses = {
      "200": {
        description: "Success",
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/WarehousePartnerResponse"
            }
          }
        }
      },
      ...Object.fromEntries(
        Object.entries(operation.responses || {}).filter(([status]) => status !== "201")
      )
    };
  });

  applyOperationOverride(spec, "DELETE", "/v2/stores/{store_id}/courier-services", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/StoreCourierServiceRemovalRequest",
      "Courier services to dissociate from the store. This DELETE operation requires a JSON body, and some OpenAPI 3.0 tooling may ignore DELETE request bodies.",
      true
    );
  });

  applyOperationOverride(spec, "DELETE", "/v2/stores/{store_id}/payment-methods", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/StorePaymentMethodRemovalRequest",
      "Payment method association to remove from the store. This DELETE operation requires a JSON body, and some OpenAPI 3.0 tooling may ignore DELETE request bodies.",
      true
    );
  });

  applyOperationOverride(spec, "POST", "/v2/orders/upload", (operation) => {
    setOperationText(
      operation,
      "Upload Orders from CSV",
      "Uploads orders from a CSV file in archive or regular mode. Archive mode imports historical orders as completed records, while regular mode validates against current catalog and inventory data."
    );
    setOperationRequestBodyDescription(
      operation,
      "CSV file, import mode, and timezone used to process the uploaded orders."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/orders/upload-change-status", (operation) => {
    setOperationText(
      operation,
      "Upload CSV to Change Order Status",
      "Uploads a CSV file that applies status updates to multiple orders in one request."
    );
    setOperationRequestBodyDescription(
      operation,
      "CSV file and timezone used to apply bulk order status updates."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/orders/upload-receipt", (operation) => {
    setOperationText(
      operation,
      "Upload Order Receipts from CSV",
      "Uploads a CSV file that updates shipment receipt or tracking identifiers for multiple orders."
    );
    setOperationRequestBodyDescription(
      operation,
      "CSV file containing the order receipt or tracking updates."
    );
  });

  if (spec.components?.parameters?.StoreIDQueryParameter4) {
    spec.components.parameters.StoreIDQueryParameter4.schema = { type: "integer" };
  }

  if (spec.components?.parameters?.BusinessIDQueryParameter) {
    spec.components.parameters.BusinessIDQueryParameter.schema = { type: "integer" };
  }

  applyOperationOverride(spec, "GET", "/v2/orders", (operation) => {
    setOperationQueryParameterSchema(operation, "product_id", { type: "integer" });
    setOperationQueryParameterSchema(operation, "warehouse_id", { type: "integer" });
    setOperationQueryParameterSchema(operation, "courier_id", { type: "integer" });
    setOperationQueryParameterSchema(operation, "handler_id", { type: "integer" });
    setOperationQueryParameterSchema(operation, "advertiser_id", { type: "integer" });
    setOperationQueryParameterSchema(operation, "financial_entity_id", { type: "integer" });
    setOperationQueryParameterSchema(operation, "page_id", { type: "integer" });
  });

  applyOperationOverride(spec, "POST", "/v2/ads/views/{id}/cards", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Metric selection and comparison payload used to build the ad view card summary."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/ads/views/{id}/summary-table", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Dimension, metric, and comparison payload used to build the ad view summary table."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/ads/views", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/AdViewCreateRequest", {
      description: "Ad view payload for the authenticated business.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/ads/views/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/AdViewUpdateRequest", {
        description: "Ad view update payload for the specified ad view.",
        required: false
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/ads/views/{id}/duplicate", (operation) => {
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "POST", "/v2/ads/custom-metrics", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/CustomMetricCreateRequest", {
      description: "Custom metric payload for the authenticated business.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/ads/custom-metrics/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/CustomMetricUpdateRequest", {
        description: "Custom metric update payload for the specified custom metric.",
        required: false
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/inventories/flow", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/InventoryFlowCreateRequest", {
      description: "Inventory flow payload used to apply a non-zero stock movement.",
      required: true
    });
  });

  for (const routePath of [
    "/v2/businesses/fb/adaccounts/{account_id}/campaigns",
    "/v2/businesses/fb/adaccounts/{account_id}/campaigns/{campaign_id}",
    "/v2/businesses/fb/adaccounts/{account_id}/adsets",
    "/v2/businesses/fb/adaccounts/{account_id}/adsets/{adset_id}",
    "/v2/businesses/fb/adaccounts/{account_id}/ads",
    "/v2/businesses/fb/adaccounts/{account_id}/ads/{ad_id}"
  ]) {
    for (const method of ["POST", "PATCH"]) {
      applyOperationOverride(spec, method, routePath, (operation) => {
        setOperationRequestSchema(operation, "#/components/schemas/MetaGraphApiMutationRequest", {
          description: operation.requestBody?.description || "Meta Graph API mutation payload.",
          required: true
        });
      });
    }
  }

  applyOperationOverride(spec, "PATCH", "/v2/businesses/waba/login", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WabaLoginRequest", {
      description: "WABA login callback payload containing the Meta business, WABA, and code values.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{id}/register-phone", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WabaRegisterPhoneRequest", {
      description: "PIN used to register the selected WhatsApp phone number.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/waba/{unique_id}/customers/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WabaCustomerUpdateRequest", {
      description: "Handler, tag, and block-state changes for the selected WABA customer conversation.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{unique_id}/customers/{id}/purchase", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WabaPurchaseEventRequest", {
      description: "Currency and order value used when sending the purchase event for the selected WABA customer.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{unique_id}/quick-replies", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/QuickReplyCreateRequest", {
      description: "Quick reply payload for the selected WABA account.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/waba/{unique_id}/quick-replies/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/QuickReplyUpdateRequest", {
      description: "Quick reply update payload for the selected quick reply.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{waba_unique_id}/customers/{wa_user_id}/messages", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WabaDirectMessageRequest", {
      description: "WhatsApp message payload forwarded to the selected customer conversation.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/customer-tags", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WabaCustomerTagCreateRequest", {
      description: "Customer tag payload for the authenticated business.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/waba/customer-tags/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WabaCustomerTagUpdateRequest", {
      description: "Customer tag update payload for the selected tag.",
      required: false
    });
  });

  applyTextOverrides(spec, [
    [
      "PUT",
      "/v2/partnership-requests/{id}/approve",
      "Approve a Partnership Request",
      "Approves the specified partnership request."
    ],
    [
      "PUT",
      "/v2/partnership-requests/{id}/ban",
      "Ban a Partnership Request",
      "Bans the specified partnership request."
    ],
    [
      "POST",
      "/v2/partnership-requests/{id}/check-action",
      "Check Partnership Request Actions",
      "Returns the actions currently available for the specified partnership request."
    ],
    [
      "PUT",
      "/v2/partnership-requests/{id}/reject",
      "Reject a Partnership Request",
      "Rejects the specified partnership request."
    ],
    [
      "PUT",
      "/v2/partnership-requests/{id}/unban",
      "Unban a Partnership Request",
      "Removes the ban from the specified partnership request."
    ],
    [
      "POST",
      "/v2/businesses/pg-accounts",
      "Create a Business Payment Gateway Account",
      "Creates a payment gateway account for the authenticated business."
    ],
    [
      "POST",
      "/v2/pg-accounts",
      "Create a Payment Gateway Account",
      "Creates a payment gateway account."
    ],
    [
      "POST",
      "/v2/pg-accounts/ipaymu-register",
      "Register an iPaymu Payment Gateway Account",
      "Registers an iPaymu payment gateway account."
    ],
    [
      "POST",
      "/v2/variants/{variant_id}/course-sections",
      "Create a Course Section for a Variant",
      "Creates a course section for the specified variant."
    ],
    [
      "POST",
      "/v2/course-sections/{section_uuid}/course-contents",
      "Create Course Content in a Course Section",
      "Creates a course content item in the specified course section."
    ],
    [
      "POST",
      "/v2/volts/orders",
      "Create a Volt Order",
      "Creates a new Volt order."
    ],
    [
      "POST",
      "/v2/volts/preview",
      "Preview a Volt Purchase",
      "Returns a preview of the Volt purchase before it is created."
    ],
    [
      "POST",
      "/v2/volts/transactions/{id}/retry-apply-spend-cap",
      "Retry Applying a Volt Spend Cap",
      "Retries spend-cap application for the specified Volt transaction."
    ],
    [
      "POST",
      "/v2/wakakas/register",
      "Register a Wakaka Integration",
      "Registers a Wakaka integration for the authenticated business."
    ],
    [
      "GET",
      "/v2/wakakas",
      "Get Wakaka Integration",
      "Returns the Wakaka integration for the authenticated business."
    ],
    [
      "POST",
      "/v2/oauth/billing/reservations",
      "Create an OAuth Billing Reservation",
      "Creates a billing reservation for the authenticated OAuth application."
    ],
    [
      "POST",
      "/v2/oauth/billing/reservations/{id}/release",
      "Release an OAuth Billing Reservation",
      "Releases the specified OAuth billing reservation."
    ],
    [
      "GET",
      "/v2/customers/tags",
      "List Customer Tags",
      "Returns customer tags that are available to the authenticated business."
    ]
  ]);

  applyOperationOverride(spec, "PUT", "/v2/partnership-requests/{id}/approve", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/PartnershipApproveRequest", {
      description: "Approval payload for the specified partnership request.",
      required: false
    });
    setOperationRequestBodyDescription(
      operation,
      "Approval payload for the specified partnership request."
    );
  });

  applyOperationOverride(spec, "PUT", "/v2/partnership-requests/{id}/ban", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Ban payload for the specified partnership request."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/partnership-requests/{id}/check-action", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/PartnershipActionCheckRequest", {
      description:
        "Payload used to evaluate the available actions for the specified partnership request.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Payload used to evaluate the available actions for the specified partnership request."
    );
  });

  applyOperationOverride(spec, "PUT", "/v2/partnership-requests/{id}/reject", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Rejection payload for the specified partnership request."
    );
  });

  applyOperationOverride(spec, "PUT", "/v2/partnership-requests/{id}/unban", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Unban payload for the specified partnership request."
    );
  });

  applyOperationOverride(spec, "DELETE", "/v2/partnership-requests/{id}", (operation) => {
    setOperationText(
      operation,
      "Delete Partnership Request",
      "Deletes the specified partnership request."
    );
    delete operation.requestBody;
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/pg-accounts", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessPgAccountRequest", {
      description: "Payment gateway account payload for the authenticated business.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Payment gateway account payload for the authenticated business."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/pg-accounts", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessPgAccountRequest", {
      description: "Payment gateway account payload.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Payment gateway account payload."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/pg-accounts/ipaymu-register", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/IpaymuRegisterRequest", {
      description: "Registration payload for the iPaymu payment gateway account.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/variants/{variant_id}/course-sections", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Course section payload for the specified variant."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/course-sections/{section_uuid}/course-contents", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Course content payload for the specified course section."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/volts/orders", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/VoltOrderCreateRequest", {
      description: "Volt order payload.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/volts/preview", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/VoltPreviewRequest", {
      description: "Volt purchase preview payload.",
      required: false
    });
    setOperationRequestBodyDescription(
      operation,
      "Volt purchase preview payload."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/licenses/{id}/send", (operation) => {
    setOperationText(
      operation,
      "Send License",
      "Sends the specified license key for the authenticated business."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/volts/transactions/{id}/retry-apply-spend-cap", (operation) => {
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "POST", "/v2/wakakas/register", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WakakaRegisterRequest", {
      description: "Wakaka registration payload.",
      required: true
    });
  });

  applyOperationOverride(spec, "GET", "/v2/customers/tags", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CustomerTagListResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/discount-codes", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/DiscountCodeCreateRequest", {
      description: "Discount code creation payload for the authenticated business.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/discount-codes/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/DiscountCodeUpdateRequest", {
        description: "Discount code update payload for the authenticated business.",
        required: false
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/moota-integrations", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MootaIntegrationRequest", {
      description: "Moota integration token payload for the authenticated business.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/moota-integrations/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/MootaIntegrationRequest", {
        description: "Moota integration token payload for the authenticated business.",
        required: true
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/pages", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/PageCreateRequest", {
      description: "Page creation payload for the authenticated business.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/pages/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/PageUpdateRequest", {
        description: "Page update payload for the authenticated business.",
        required: false
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/pages/{page_id}/page-displays", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/PageDisplayCreateRequest", {
      description: "Page display payload for the specified page.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/stores/{store_id}/channels", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/ChannelCreateRequest", {
      description: "Channel creation payload for the specified store.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/stores/{store_id}/channels/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/ChannelUpdateRequest", {
        description: "Channel update payload for the specified store.",
        required: false
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/warehouses", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WarehouseCreateRequest", {
      description: "Warehouse creation payload for the authenticated business.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/warehouses/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/WarehouseUpdateRequest", {
        description: "Warehouse update payload for the authenticated business.",
        required: false
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/fb-pixels", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/TrackingPixelCreateRequest", {
      description: "Facebook pixel payload for the authenticated business.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/fb-pixels/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/TrackingPixelUpdateRequest", {
      description: "Facebook pixel update payload for the authenticated business.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/tiktok-pixels", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/TrackingPixelCreateRequest", {
      description: "TikTok pixel payload for the authenticated business.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/tiktok-pixels/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/TrackingPixelUpdateRequest", {
      description: "TikTok pixel update payload for the authenticated business.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/kwai-pixels", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/KwaiPixelCreateRequest", {
      description: "Kwai pixel payload for the authenticated business.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/kwai-pixels/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/KwaiPixelUpdateRequest", {
      description: "Kwai pixel update payload for the authenticated business.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/gtm", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/GtmCreateRequest", {
      description: "GTM configuration payload for the authenticated business.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/gtm/{id}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/GtmUpdateRequest", {
      description: "GTM configuration update payload for the authenticated business.",
      required: false
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/variants/{id}/course", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/VariantCourseUpdateRequest", {
      description: "Variant course payload for the specified LMS-enabled variant.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/variants/{variant_id}/course-sections", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/CourseSectionCreateRequest", {
      description: "Course section payload for the specified variant.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/course-sections/{uuid}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/CourseSectionUpdateRequest", {
      description: "Course section update payload for the specified course section.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/course-sections/{section_uuid}/course-contents", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/CourseContentCreateRequest", {
      description: "Course content payload for the specified course section.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/course-contents/{uuid}", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/CourseContentUpdateRequest", {
      description: "Course content update payload for the specified course content.",
      required: false
    });
  });

  applyOperationOverride(
    spec,
    "PATCH",
    "/v2/variants/{variant_id}/course-section-orders",
    (operation) => {
      setOperationRequestSchema(
        operation,
        "#/components/schemas/CourseSectionOrderUpdateRequest",
        {
          description: "Ordered course section UUID list for the specified variant.",
          required: true
        }
      );
      setOperationRequestBodyDescription(
        operation,
        "Ordered course section UUID list for the specified variant."
      );
    }
  );

  applyOperationOverride(
    spec,
    "PATCH",
    "/v2/course-sections/{section_uuid}/course-content-orders",
    (operation) => {
      setOperationRequestSchema(
        operation,
        "#/components/schemas/CourseContentOrderUpdateRequest",
        {
          description: "Ordered course content UUID list for the specified course section.",
          required: true
        }
      );
      setOperationRequestBodyDescription(
        operation,
        "Ordered course content UUID list for the specified course section."
      );
    }
  );

  applyOperationOverride(spec, "GET", "/v2/users/me", (operation) => {
    setOperationSecurity(operation, [{ appLoginJwt: [] }]);
    operation.responses = operation.responses || {};
    operation.responses["403"] = {
      $ref: "#/components/responses/ForbiddenResponse"
    };
  });

  applyOperationOverride(spec, "GET", "/v2/businesses", (operation) => {
    setOperationText(
      operation,
      "List Businesses",
      "Returns the businesses accessible to the authenticated user or current business context."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/oauth", (operation) => {
    setOperationText(
      operation,
      "Get Business OAuth Settings",
      "Returns the OAuth client settings and webhook configuration for the authenticated business. If OAuth credentials are missing, Nexus initializes and persists a client ID and client secret before responding."
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthSettingsResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/balance", (operation) => {
    operation.parameters = [
      {
        name: "sync",
        in: "query",
        required: false,
        description: "When true, synchronizes the business balance before returning it.",
        schema: { type: "boolean" }
      }
    ];
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessBalanceResponse"
    );
  });

  for (const routePath of ["/v2/businesses/balance-history", "/v2/businesses/balance-history/download"]) {
    applyOperationOverride(spec, "GET", routePath, (operation) => {
      operation.parameters = [
        {
          name: "page",
          in: "query",
          required: false,
          description: "Page number for paginated balance history results.",
          schema: { type: "integer", minimum: 1 }
        },
        { $ref: "#/components/parameters/PageSizeQueryParameter" },
        {
          name: "balance_type",
          in: "query",
          required: false,
          description: "Comma-separated balance types to include.",
          schema: { type: "string" }
        },
        {
          name: "created_at_since",
          in: "query",
          required: false,
          description: "Only return balance history created at or after this timestamp.",
          schema: { type: "string", format: "date-time" }
        },
        {
          name: "created_at_until",
          in: "query",
          required: false,
          description: "Only return balance history created before the end of this timestamp's day.",
          schema: { type: "string", format: "date-time" }
        }
      ];
    });
  }

  applyOperationOverride(spec, "GET", "/v2/businesses/balance-history", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessBalanceHistoryListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/balance-history/download", (operation) => {
    operation.parameters = [
      {
        name: "balance_type",
        in: "query",
        required: false,
        description: "Comma-separated balance types to include in the exported CSV.",
        schema: { type: "string" }
      },
      {
        name: "created_at_since",
        in: "query",
        required: false,
        description: "Only export balance history created at or after this timestamp.",
        schema: { type: "string", format: "date-time" }
      },
      {
        name: "created_at_until",
        in: "query",
        required: false,
        description: "Only export balance history created before the end of this timestamp's day.",
        schema: { type: "string", format: "date-time" }
      }
    ];
  });

  for (const [method, routePath, summary, description] of [
    [
      "GET",
      "/v2/businesses/oauth-billing/actions",
      "List OAuth Billing Actions",
      "Returns OAuth billing actions for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/oauth-billing/charges",
      "List OAuth Billing Charges",
      "Returns OAuth billing charges for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/oauth-billing/charges/{id}",
      "Get OAuth Billing Charge",
      "Returns the specified OAuth billing charge for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/oauth-billing/earnings",
      "Get OAuth Billing Earnings",
      "Returns OAuth billing earnings for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/oauth-billing/ledger",
      "List OAuth Billing Ledger Entries",
      "Returns OAuth billing ledger entries for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/oauth-billing/reservations",
      "List OAuth Billing Reservations",
      "Returns OAuth billing reservations for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/oauth-billing/reservations/{id}",
      "Get OAuth Billing Reservation",
      "Returns the specified OAuth billing reservation for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/oauth-billing/settlements",
      "List OAuth Billing Settlements",
      "Returns OAuth billing settlements for the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/oauth-billing/withdrawals",
      "Create OAuth Billing Withdrawal",
      "Creates an OAuth billing withdrawal for the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/oauth/regenerate-secret",
      "Regenerate Business OAuth Client Secret",
      "Regenerates the OAuth client secret for the authenticated business."
    ]
  ]) {
    applyOperationOverride(spec, method, routePath, (operation) => {
      setOperationText(operation, summary, description);
    });
  }

  applyOperationOverride(spec, "POST", "/v2/businesses/oauth-billing/withdrawals", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Withdrawal payload for the authenticated business's OAuth billing balance."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/oauth-billing/actions", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/OAuthBillingActionListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/oauth-billing/earnings", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthBillingEarningsResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/oauth-billing/reservations", (operation) => {
    operation.parameters = [
      { $ref: "#/components/parameters/PageSizeQueryParameter" },
      {
        name: "last_id",
        in: "query",
        required: false,
        description: "UUID cursor for reservation pagination.",
        schema: { type: "string", format: "uuid" }
      },
      {
        name: "oauth_application_id",
        in: "query",
        required: false,
        description: "Filter by OAuth application ID.",
        schema: { type: "integer" }
      },
      {
        name: "oauth_authorized_business_id",
        in: "query",
        required: false,
        description: "Filter by OAuth authorization ID.",
        schema: { type: "integer" }
      },
      {
        name: "merchant_business_id",
        in: "query",
        required: false,
        description: "Filter by merchant business ID.",
        schema: { type: "integer" }
      },
      {
        name: "billing_tag",
        in: "query",
        required: false,
        description: "Filter by billing tag code.",
        schema: { type: "string" }
      },
      {
        name: "action_key",
        in: "query",
        required: false,
        description: "Filter by OAuth billing action key.",
        schema: { type: "string" }
      },
      {
        name: "billing_status",
        in: "query",
        required: false,
        description: "Filter by reservation billing status.",
        schema: {
          type: "string",
          enum: ["active", "consuming", "captured", "released"]
        }
      },
      {
        name: "billing_idempotency_key",
        in: "query",
        required: false,
        description: "Filter by billing idempotency key.",
        schema: { type: "string" }
      }
    ];
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthBillingReservationListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/oauth-billing/reservations/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "string", format: "uuid" });
    setOperationPathParameterDescription(operation, "id", "UUID of the OAuth billing reservation");
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthBillingReservationResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/oauth-billing/charges", (operation) => {
    operation.parameters = [
      { $ref: "#/components/parameters/PageSizeQueryParameter" },
      {
        name: "last_id",
        in: "query",
        required: false,
        description: "UUID cursor for charge pagination.",
        schema: { type: "string", format: "uuid" }
      },
      {
        name: "oauth_application_id",
        in: "query",
        required: false,
        description: "Filter by OAuth application ID.",
        schema: { type: "integer" }
      },
      {
        name: "oauth_authorized_business_id",
        in: "query",
        required: false,
        description: "Filter by OAuth authorization ID.",
        schema: { type: "integer" }
      },
      {
        name: "merchant_business_id",
        in: "query",
        required: false,
        description: "Filter by merchant business ID.",
        schema: { type: "integer" }
      },
      {
        name: "billing_tag",
        in: "query",
        required: false,
        description: "Filter by billing tag code.",
        schema: { type: "string" }
      },
      {
        name: "action_key",
        in: "query",
        required: false,
        description: "Filter by OAuth billing action key.",
        schema: { type: "string" }
      },
      {
        name: "billing_idempotency_key",
        in: "query",
        required: false,
        description: "Filter by billing idempotency key.",
        schema: { type: "string" }
      },
      {
        name: "request_id",
        in: "query",
        required: false,
        description: "Filter by downstream request ID.",
        schema: { type: "string" }
      }
    ];
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthBillingChargeListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/oauth-billing/charges/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "string", format: "uuid" });
    setOperationPathParameterDescription(operation, "id", "UUID of the OAuth billing charge");
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthBillingChargeResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/oauth-billing/ledger", (operation) => {
    operation.parameters = [
      { $ref: "#/components/parameters/PageSizeQueryParameter" },
      {
        name: "last_id",
        in: "query",
        required: false,
        description: "UUID cursor for ledger pagination.",
        schema: { type: "string", format: "uuid" }
      },
      {
        name: "oauth_application_id",
        in: "query",
        required: false,
        description: "Filter by OAuth application ID.",
        schema: { type: "integer" }
      }
    ];
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthBillingLedgerListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/oauth-billing/settlements", (operation) => {
    operation.parameters = [
      { $ref: "#/components/parameters/PageSizeQueryParameter" },
      {
        name: "last_id",
        in: "query",
        required: false,
        description: "UUID cursor for settlement pagination.",
        schema: { type: "string", format: "uuid" }
      },
      {
        name: "settlement_rail",
        in: "query",
        required: false,
        description: "Filter by settlement rail.",
        schema: {
          type: "string",
          enum: ["xendit", "ipaymu"]
        }
      }
    ];
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthBillingSettlementListResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/oauth-billing/withdrawals", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/OAuthBillingWithdrawalRequest", {
      description: "Amount and payout rail for the OAuth billing earnings withdrawal.",
      required: true
    });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthBillingSettlementResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/oauth/regenerate-secret", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthSettingsResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/webhook-events", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessWebhookEventOptionListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/business-subscriptions", (operation) => {
    setOperationText(
      operation,
      "List Business Subscriptions",
      "Returns the authenticated business subscription currently attached to the selected business."
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessSubscriptionListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/business-subscriptions/{id}", (operation) => {
    setOperationText(
      operation,
      "Get Business Subscription",
      "Returns the specified business subscription for the selected business."
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessSubscriptionResponse"
    );
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/business-subscriptions/{id}", (operation) => {
      setOperationText(
        operation,
        "Update Business Subscription",
        "Updates the pricing plan for the specified business subscription."
      );
      setOperationRequestSchema(
        operation,
        "#/components/schemas/BusinessSubscriptionUpdateRequest",
        {
          description:
            "Pricing plan selection payload for the specified business subscription.",
          required: true
        }
      );
      setOperationJsonResponse(
        operation,
        "200",
        "Success",
        "#/components/schemas/BusinessSubscriptionResponse"
      );
    });
  }

  applyOperationOverride(spec, "POST", "/v2/businesses", (operation) => {
    setOperationText(
      operation,
      "Create a Business",
      "Creates a new business for the authenticated user."
    );
    setOperationRequestSchema(operation, "#/components/schemas/BusinessCreateRequest", {
      description: "Business creation payload for the authenticated user.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Business creation payload for the authenticated user."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/business-users/me", (operation) => {
    setOperationText(
      operation,
      "Get the Current Business User",
      "Returns the authenticated user's membership payload for the current business."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/business-users/me", (operation) => {
    setOperationText(
      operation,
      "Update the Current Business User",
      "Updates editable profile fields for the authenticated user's current business membership."
    );
    setOperationRequestSchema(
      operation,
      "#/components/schemas/CurrentBusinessUserUpdateRequest",
      {
        description:
          "Payload used to update the authenticated user's current business membership.",
        required: false
      }
    );
    setOperationRequestBodyDescription(
      operation,
      "Payload used to update the authenticated user's current business membership."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/webhooks", (operation) => {
    setOperationText(
      operation,
      "Update Business Webhook Settings",
      "Creates or updates the authenticated business webhook configuration."
    );
    setOperationRequestSchema(operation, "#/components/schemas/BusinessWebhookSettingsRequest", {
      description:
        "Webhook URL, activation status, and subscribed event list for the authenticated business. `url` is required when creating the webhook for the first time; omitted fields keep their stored values on later updates.",
      required: false
    });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessOAuthSettingsResponse"
    );
  });

  for (const routePath of ["/v2/businesses/pg-accounts/{id}", "/v2/pg-accounts/{id}"]) {
    applyOperationOverride(spec, "PATCH", routePath, (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/BusinessPgAccountRequest", {
        description: "Payment gateway account update payload.",
        required: true
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/payment-accounts", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/PaymentAccountCreateRequest", {
      description: "Payment account payload for the authenticated business.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/payment-accounts/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/PaymentAccountUpdateRequest", {
        description: "Payment account update payload.",
        required: false
      });
    });
  }

  applyOperationOverride(spec, "POST", "/v2/team-members", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/TeamMemberCreateRequest", {
      description: "Invitation payload for creating a team member in the authenticated business.",
      required: true
    });
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/team-members/{id}", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/TeamMemberUpdateRequest", {
        description: "Update payload for the specified team member.",
        required: false
      });
    });
  }

  for (const method of ["POST", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/businesses/xp-account-holder", (operation) => {
      setOperationRequestSchema(operation, "#/components/schemas/XenditAccountHolderRequest", {
        description: "Xendit account holder payload for the authenticated business.",
        required: true
      });
    });
  }

  applyOperationOverride(spec, "GET", "/v2/customers/me/order-statistics", (operation) => {
    setOperationText(
      operation,
      "Get Current Customer Order Statistics",
      "Returns order statistics for the authenticated customer or LMS user."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/notifications/{notification_id}/mark-as-read", (operation) => {
    setOperationText(
      operation,
      "Mark a Notification as Read",
      "Marks the specified notification as read for the authenticated business."
    );
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "POST", "/v2/notifications/mark-all-as-read", (operation) => {
    setOperationText(
      operation,
      "Mark All Notifications as Read",
      "Marks every notification for the authenticated business as read."
    );
    delete operation.requestBody;
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/api-keys/scopes", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessApiKeyScopeCatalogResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/by-unique-id/{unique_id}", (operation) => {
    setOperationText(
      operation,
      "Get a Business by Unique ID",
      "Returns the business record identified by the supplied public business unique ID."
    );
    setOperationPathParameterDescription(
      operation,
      "unique_id",
      "Public unique ID of the business to retrieve."
    );
    setOperationPathParameterSchema(operation, "unique_id", { type: "string" });
  });

  applyOperationOverride(spec, "POST", "/v2/pages/{page_id}/update-tags", (operation) => {
    setOperationText(
      operation,
      "Update Page Tags",
      "Updates tags for the specified page."
    );
    setOperationRequestSchema(operation, "#/components/schemas/TagsUpdateRequest", {
      description: "Tag update payload for the specified page.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Tag update payload for the specified page."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/pages/simplified", (operation) => {
    setOperationText(
      operation,
      "List Simplified Pages",
      "Returns simplified page records for the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/pages/{page_id}/public", (operation) => {
    setOperationText(
      operation,
      "Get Page Public Settings",
      "Returns the public page configuration for the specified page."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/pages/tags", (operation) => {
    setOperationText(
      operation,
      "List Page Tags",
      "Returns page tags for the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/roles/simplified", (operation) => {
    setOperationText(
      operation,
      "List Simplified Roles",
      "Returns simplified role records for the authenticated business."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/auth/sso/discourse", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Discourse SSO nonce and signature payload used to generate the signed login response."
    );
  });

  for (const [path, resourceLabel] of [
    ["/v2/bundles/{bundle_id}/follow-up-chats/generate", "bundle"],
    ["/v2/products/{product_id}/follow-up-chats/generate", "product"],
    ["/v2/stores/{store_id}/follow-up-chats/generate", "store"]
  ]) {
    applyOperationOverride(spec, "POST", path, (operation) => {
      setOperationText(
        operation,
        `Generate Default ${titleize(resourceLabel)} Follow Up Chats`,
        `Generates the default follow up chat templates for the specified ${resourceLabel} from the configured payment-method templates.`
      );
      delete operation.requestBody;
      setBlankSuccessResponse(operation);
    });
  }

  applyOperationOverride(spec, "GET", "/v2/notifications/unread-count", (operation) => {
    setOperationText(
      operation,
      "Get Unread Notification Count",
      "Returns the unread notification count for the authenticated business."
    );
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/NotificationUnreadCountResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/catalog/{custom_domain}/cart/merge", (operation) => {
    setOperationText(
      operation,
      "Merge Guest Cart into Customer Cart",
      "Merges the current guest cart, identified by the guest token cookie, into the authenticated customer's active cart for the selected storefront."
    );
    delete operation.requestBody;
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/CustomerCartResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/transactions/download", (operation) => {
    setOperationText(
      operation,
      "Download Business Transactions",
      "Downloads the authenticated business transaction export."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/ses/credits/calculate", (operation) => {
    setOperationText(
      operation,
      "Calculate SES Credits",
      "Calculates SES credit usage for the supplied request."
    );
    setOperationRequestSchema(operation, "#/components/schemas/SesCreditsCreditRequest", {
      description: "SES credit quantity payload used to calculate pricing.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/ses/credits/orders/preview-items", (operation) => {
    setOperationText(
      operation,
      "Preview SES Credits Order Items",
      "Previews the billing items for an SES credits order."
    );
    setOperationRequestSchema(operation, "#/components/schemas/SesCreditsCreditRequest", {
      description: "SES credit quantity payload used to preview the billing breakdown.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/ses/email-broadcasts/recipient-count", (operation) => {
    setOperationText(
      operation,
      "Count Email Broadcast Recipients",
      "Counts recipients that match the supplied email broadcast recipient filter."
    );
    setOperationRequestBodyDescription(
      operation,
      "Recipient filter payload used to count matching email broadcast recipients."
    );
  });

  for (const routePath of [
    "/v2/variants/{variant_id}/digital-product-files",
    "/v2/variants/{variant_id}/digital-product-files/{id}"
  ]) {
    for (const method of ["GET", "POST", "DELETE"]) {
      applyOperationOverride(spec, method, routePath, (operation) => {
        operation.tags = ["Variants"];
      });
    }
  }

  applyOperationOverride(spec, "GET", "/v2/variants/{id}", (operation) => {
    operation.tags = ["Variants"];
    setOperationText(
      operation,
      "Get a Variant",
      "Returns the specified product variant."
    );
  });

  for (const routePath of [
    "/v2/variants/{variant_id}/knowledge-items",
    "/v2/variants/{variant_id}/knowledge-items/{id}"
  ]) {
    for (const method of ["GET", "POST", "PATCH", "DELETE"]) {
      applyOperationOverride(spec, method, routePath, (operation) => {
        operation.tags = ["Variants"];
      });
    }
  }

  applyOperationOverride(spec, "GET", "/v2/variants/{id}/course", (operation) => {
    setOperationText(
      operation,
      "Get Variant Course",
      "Returns the course structure for the specified LMS-enabled variant."
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/variants/{id}/course", (operation) => {
    setOperationText(
      operation,
      "Update Variant Course",
      "Updates the course structure for the specified LMS-enabled variant."
    );
    setOperationRequestBodyDescription(
      operation,
      "Variant course payload for the specified LMS-enabled variant."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/oauth/billing/reservations", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/OAuthBillingReservationRequest", {
      description: "Billing tag, idempotency key, and action key used to create the reservation.",
      required: true
    });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/OAuthBillingReservationResponse"
    );
    operation.responses = operation.responses || {};
    operation.responses["402"] = {
      $ref: "#/components/responses/PaymentRequiredResponse"
    };
  });

  applyOperationOverride(spec, "POST", "/v2/oauth/billing/reservations/{id}/release", (operation) => {
    delete operation.requestBody;
    setOperationPathParameterSchema(operation, "id", { type: "string", format: "uuid" });
    setOperationPathParameterDescription(operation, "id", "UUID of the OAuth billing reservation");
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/OAuthBillingReservationResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/oauth/billing/reservations/{id}/release", (operation) => {
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/waba/{id}/send-messages", (operation) => {
    operation.requestBody = buildSchemaRefRequestBody(
      "#/components/schemas/WabaTemplateMessageBatchRequest",
      "Multipart CSV upload, template ID, and JSON-encoded component values used to send the WhatsApp message batch.",
      true,
      "multipart/form-data"
    );
    setBlankSuccessResponse(operation);
  });

  applyTextOverrides(spec, [
    [
      "POST",
      "/v2/business-users/me/accept-direct",
      "Accept a Direct Business Invitation",
      "Accepts the pending direct invitation for the authenticated business user."
    ],
    [
      "POST",
      "/v2/businesses/fb/ad-account-top-ups",
      "Create a Facebook Ad Account Top-Up",
      "Creates a Facebook ad account top-up request for the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/fb/ad-account-top-ups/preview-items",
      "Preview Facebook Ad Account Top-Up Items",
      "Previews the billing items for a Facebook ad account top-up."
    ],
    [
      "POST",
      "/v2/businesses/fb/adaccounts/{account_id}/adcreatives",
      "Create a Facebook Ad Creative",
      "Creates a Facebook ad creative in the specified ad account."
    ],
    [
      "POST",
      "/v2/businesses/fb/adaccounts/{account_id}/adimages",
      "Upload a Facebook Ad Image",
      "Uploads an ad image to the specified Facebook ad account."
    ],
    [
      "POST",
      "/v2/businesses/fb/adaccounts/{account_id}/ads",
      "Create a Facebook Ad",
      "Creates a Facebook ad in the specified ad account."
    ],
    [
      "POST",
      "/v2/businesses/fb/adaccounts/{account_id}/adsets",
      "Create a Facebook Ad Set",
      "Creates a Facebook ad set in the specified ad account."
    ],
    [
      "POST",
      "/v2/businesses/fb/adaccounts/{account_id}/campaigns",
      "Create a Facebook Campaign",
      "Creates a Facebook campaign in the specified ad account."
    ],
    [
      "PATCH",
      "/v2/businesses/fb/logout",
      "Disconnect Facebook Login",
      "Disconnects the authenticated business from Facebook."
    ],
    [
      "POST",
      "/v2/businesses/fb/synced-adaccounts/{account_id}/setup",
      "Set Up a Synced Facebook Ad Account",
      "Completes setup for the specified synced Facebook ad account."
    ],
    [
      "POST",
      "/v2/businesses/otp",
      "Send a Business OTP",
      "Sends a one-time password for the authenticated business flow."
    ],
    [
      "POST",
      "/v2/businesses/xp-upload-file",
      "Upload an XP File",
      "Uploads an XP file for the authenticated business."
    ],
    [
      "POST",
      "/v2/chatbot-credits/calculate",
      "Calculate Chatbot Credits",
      "Calculates chatbot credit usage for the supplied request."
    ],
    [
      "POST",
      "/v2/chatbot-credits/orders/preview-items",
      "Preview Chatbot Credit Order Items",
      "Previews the billing items for a chatbot credit order."
    ],
    [
      "POST",
      "/v2/customers/{id}/update-tags",
      "Update Customer Tags",
      "Updates tag assignments for the specified customer."
    ],
    [
      "POST",
      "/v2/customers/upload",
      "Upload Customers from CSV",
      "Uploads customers from a CSV file."
    ],
    [
      "POST",
      "/v2/oauth/authorize/approve",
      "Approve an OAuth Authorization Request",
      "Approves the current OAuth authorization request."
    ],
    [
      "POST",
      "/v2/products/{product_id}/partnership/check-changes",
      "Check Product Partnership Changes",
      "Checks whether the specified product partnership has pending changes."
    ],
    [
      "POST",
      "/v2/team-members/{team_member_id}/resend-invitation",
      "Resend a Team Member Invitation",
      "Resends the invitation for the specified team member."
    ]
  ]);

  applyOperationOverride(spec, "POST", "/v2/business-users/me/accept-direct", (operation) => {
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/payout-target", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessPayoutTargetResponse"
    );
    operation.responses = operation.responses || {};
    operation.responses["404"] = {
      $ref: "#/components/responses/NotFoundResponse"
    };
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/payout-target", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessPayoutTargetRequest", {
      description: "Payout destination payload for the authenticated business.",
      required: true
    });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessPayoutTargetResponse"
    );
  });

  applyOperationOverride(spec, "DELETE", "/v2/businesses/payout-target", (operation) => {
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/xp-balance", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/BusinessXpBalanceResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/xp-transactions", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/XenditTransactionListResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/xp-transactions/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "string" });
    setOperationPathParameterDescription(operation, "id", "XP transaction ID");
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/XenditTransactionResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/xp-reports", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/XenditReportListResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/xp-reports", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/CreateXenditReportRequest", {
      description: "Report type payload used to generate the XP report.",
      required: true
    });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/XenditReportResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/xp-reports/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/XenditReportResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/xp-reports/{id}/sync", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    delete operation.requestBody;
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/XenditReportResponse"
    );
  });

  applyTextOverrides(spec, [
    [
      "GET",
      "/v2/businesses/fb",
      "Get Facebook Integration",
      "Returns the Facebook integration settings for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/fb/ad-account-top-ups",
      "List Facebook Ad Account Top-Ups",
      "Returns Facebook ad account top-up requests for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/fb/ad-account-top-ups/{id}",
      "Get a Facebook Ad Account Top-Up",
      "Returns the specified Facebook ad account top-up request."
    ],
    [
      "POST",
      "/v2/businesses/fb/ad-account-top-ups/{id}/cancel",
      "Cancel a Facebook Ad Account Top-Up",
      "Cancels the specified Facebook ad account top-up request."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts",
      "List Facebook Ad Accounts",
      "Returns Facebook ad accounts available to the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts/{account_id}",
      "Get a Facebook Ad Account",
      "Returns the specified Facebook ad account."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts/{account_id}/adcreatives",
      "List Facebook Ad Creatives",
      "Returns ad creatives for the specified Facebook ad account."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts/{account_id}/ads/{ad_id}",
      "Get a Facebook Ad",
      "Returns the specified Facebook ad."
    ],
    [
      "PATCH",
      "/v2/businesses/fb/adaccounts/{account_id}/ads/{ad_id}",
      "Update a Facebook Ad",
      "Updates the specified Facebook ad."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts/{account_id}/adsets/{adset_id}",
      "Get a Facebook Ad Set",
      "Returns the specified Facebook ad set."
    ],
    [
      "PATCH",
      "/v2/businesses/fb/adaccounts/{account_id}/adsets/{adset_id}",
      "Update a Facebook Ad Set",
      "Updates the specified Facebook ad set."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts/{account_id}/adsets/{adset_id}/ads",
      "List Ads in a Facebook Ad Set",
      "Returns ads for the specified Facebook ad set."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts/{account_id}/campaigns",
      "List Facebook Campaigns",
      "Returns campaigns for the specified Facebook ad account."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts/{account_id}/campaigns/{campaign_id}",
      "Get a Facebook Campaign",
      "Returns the specified Facebook campaign."
    ],
    [
      "PATCH",
      "/v2/businesses/fb/adaccounts/{account_id}/campaigns/{campaign_id}",
      "Update a Facebook Campaign",
      "Updates the specified Facebook campaign."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts/{account_id}/campaigns/{campaign_id}/adsets",
      "List Ad Sets in a Facebook Campaign",
      "Returns ad sets for the specified Facebook campaign."
    ],
    [
      "GET",
      "/v2/businesses/fb/adaccounts/{account_id}/insights",
      "List Facebook Ad Account Insights",
      "Returns insight metrics for the specified Facebook ad account."
    ],
    [
      "POST",
      "/v2/businesses/fb/adaccounts/sync",
      "Sync a Facebook Ad Account",
      "Synchronizes metadata for the specified Facebook ad account."
    ],
    [
      "GET",
      "/v2/businesses/fb/child-bm",
      "Get Facebook Child Business Manager",
      "Returns the child Facebook Business Manager linked to the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/fb/child-bm",
      "Create Facebook Child Business Manager",
      "Creates a child Facebook Business Manager for the authenticated business."
    ],
    [
      "POST",
      "/v2/businesses/fb/child-bm/adaccount",
      "Create a Facebook Ad Account in Child Business Manager",
      "Creates a Facebook ad account inside the authenticated business's child Business Manager."
    ],
    [
      "GET",
      "/v2/businesses/fb/child-bm/timezones",
      "List Child Business Manager Time Zones",
      "Returns supported time zones for the child Facebook Business Manager flow."
    ],
    [
      "GET",
      "/v2/businesses/fb/child-bm/verticals",
      "List Child Business Manager Verticals",
      "Returns supported business verticals for the child Facebook Business Manager flow."
    ],
    [
      "GET",
      "/v2/businesses/fb/customaudiences",
      "List Facebook Custom Audiences",
      "Returns Facebook custom audiences available to the authenticated business."
    ],
    [
      "PATCH",
      "/v2/businesses/fb/login",
      "Connect Facebook Login",
      "Starts the Facebook login flow for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/fb/pages",
      "List Facebook Pages",
      "Returns Facebook pages available to the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/fb/pages/{page_id}",
      "Get a Facebook Page",
      "Returns the specified Facebook page."
    ],
    [
      "GET",
      "/v2/businesses/fb/pages/{page_id}/posts",
      "List Facebook Page Posts",
      "Returns posts for the specified Facebook page."
    ],
    [
      "GET",
      "/v2/businesses/fb/synced-adaccounts",
      "List Synced Facebook Ad Accounts",
      "Returns synced Facebook ad accounts for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/fb/synced-adaccounts/{account_id}",
      "Get a Synced Facebook Ad Account",
      "Returns the specified synced Facebook ad account."
    ],
    [
      "POST",
      "/v2/businesses/files",
      "Create a Business File Record",
      "Creates a file record for the authenticated business."
    ],
    [
      "GET",
      "/v2/businesses/kyc-docs-name-mapping",
      "Get Business KYC Document Name Mapping",
      "Returns the KYC document name mapping used by the authenticated business flows."
    ],
    [
      "GET",
      "/v2/gtm",
      "List GTM Configurations",
      "Returns GTM configurations for the authenticated business."
    ],
    [
      "POST",
      "/v2/gtm",
      "Create a GTM Configuration",
      "Creates a GTM configuration for the authenticated business."
    ],
    [
      "GET",
      "/v2/gtm/{id}",
      "Get a GTM Configuration",
      "Returns the specified GTM configuration."
    ],
    [
      "PATCH",
      "/v2/gtm/{id}",
      "Update a GTM Configuration",
      "Updates the specified GTM configuration."
    ],
    [
      "DELETE",
      "/v2/gtm/{id}",
      "Delete a GTM Configuration",
      "Deletes the specified GTM configuration."
    ]
  ]);

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/ad-account-top-ups", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MetaAdAccountTopUpRequest", {
      description: "Top-up payload for the Facebook ad account.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/ad-account-top-ups/preview-items", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MetaAdAccountTopUpPreviewRequest", {
      description: "Top-up preview payload for the Facebook ad account.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/adaccounts/{account_id}/adcreatives", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MetaGraphApiMutationRequest", {
      description: "Facebook ad creative payload for the specified ad account.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/adaccounts/{account_id}/adimages", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MetaAdImageUploadRequest", {
      contentType: "multipart/form-data",
      description: "Multipart image upload payload for the specified Facebook ad account.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/adaccounts/{account_id}/ads", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MetaGraphApiMutationRequest", {
      description: "Facebook ad payload for the specified ad account.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/adaccounts/{account_id}/adsets", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MetaGraphApiMutationRequest", {
      description: "Facebook ad set payload for the specified ad account.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/adaccounts/{account_id}/campaigns", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MetaGraphApiMutationRequest", {
      description: "Facebook campaign payload for the specified ad account.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/child-bm", (operation) => {
    setOperationRequestSchema(
      operation,
      "#/components/schemas/MetaChildBusinessManagerRequest",
      {
        description:
          "Payload used to create a child Facebook Business Manager for the authenticated business.",
        required: true
      }
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/child-bm/adaccount", (operation) => {
    setOperationRequestSchema(
      operation,
      "#/components/schemas/MetaChildBusinessManagerAdAccountRequest",
      {
        description:
          "Payload used to create a Facebook ad account in the authenticated business's child Business Manager.",
        required: true
      }
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/fb/login", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MetaFbLoginRequest", {
      description: "Payload used to start the Facebook login flow for the authenticated business.",
      required: true
    });
  });

  applyOperationOverride(spec, "PATCH", "/v2/businesses/fb/logout", (operation) => {
    delete operation.requestBody;
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/adaccounts/sync", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MetaSyncAdAccountsRequest", {
      description:
        "Pagination cursor and optional extra field list used to synchronize ad account metadata for the authenticated business.",
      required: false
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/fb/synced-adaccounts/{account_id}/setup", (operation) => {
    setOperationRequestBodyDescription(
      operation,
      "Setup payload for the specified synced Facebook ad account."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/otp", (operation) => {
    setOperationText(
      operation,
      "Send a Business OTP",
      "Sends a one-time password for the authenticated business. The `change_business_owner` purpose is used during ownership transfer flows."
    );
    setOperationSecurity(operation, [{ bearerApiKey: [] }]);
    setOperationResponseRef(operation, "200", "#/components/responses/SuccessMessageResponse");
    setOperationRequestSchema(operation, "#/components/schemas/UserOtpRequest", {
      description: "OTP purpose payload for the authenticated business.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "OTP purpose payload for the authenticated business."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/xp-upload-file", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessXpFileUploadRequest", {
      contentType: "multipart/form-data",
      description: "Multipart XP file upload payload.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/payout", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessClassicPayoutRequest", {
      description: "OTP and amount payload used to create a classic payout.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "OTP and amount payload used to create a classic payout."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/xp-payout", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/BusinessXpPayoutRequest", {
      description: "OTP, amount, and optional XP type payload used to create an XP payout.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "OTP, amount, and optional XP type payload used to create an XP payout."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/chatbot-credits/calculate", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/ChatbotCreditCalculationRequest", {
      description: "Usage payload used to calculate chatbot credit consumption.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Usage payload used to calculate chatbot credit consumption."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/chatbot-credits/orders/preview-items", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/ChatbotCreditCalculationRequest", {
      description: "Preview payload for the chatbot credit order.",
      required: false
    });
    setOperationRequestBodyDescription(
      operation,
      "Preview payload for the chatbot credit order."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/{id}/update-tags", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/TagsUpdateRequest", {
      description: "Customer tag update payload for the specified customer.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Customer tag update payload for the specified customer."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/orders/{id}/update-tags", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/TagsUpdateRequest", {
      description: "Order tag update payload for the specified order.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Order tag update payload for the specified order."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/customers/upload", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/CustomerCsvUploadRequest", {
      contentType: "multipart/form-data",
      description: "Multipart CSV upload payload for importing customers.",
      required: true
    });
    setOperationRequestBodyDescription(
      operation,
      "Multipart CSV upload payload for importing customers."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/oauth/authorize/approve", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/OAuthAuthorizeApproveRequest", {
      description:
        "Approved scopes, webhook settings, billing tags, and session data for the current OAuth authorization request.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/products/{product_id}/partnership/check-changes", (operation) => {
    setOperationRequestSchema(
      operation,
      "#/components/schemas/ProductPartnershipChangeCheckRequest",
      {
        description: "Payload used to check partnership changes for the specified product.",
        required: false
      }
    );
    setOperationRequestBodyDescription(
      operation,
      "Payload used to check partnership changes for the specified product."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/team-members/{team_member_id}/resend-invitation", (operation) => {
    delete operation.requestBody;
    setBlankSuccessResponse(operation);
  });

  applyOperationOverride(spec, "GET", "/v2/oauth/authorize", (operation) => {
    setOperationText(
      operation,
      "Get OAuth Authorization Form",
      "Validates the supplied OAuth authorization request and returns the approval form payload for the authenticated business."
    );
    operation.parameters = [
      {
        name: "client_id",
        in: "query",
        required: true,
        description: "OAuth client ID of the application requesting access.",
        schema: { type: "string" }
      },
      {
        name: "redirect_uri",
        in: "query",
        required: true,
        description: "Redirect URI that must match the application's registered callback URL.",
        schema: { type: "string", format: "uri" }
      },
      {
        name: "state",
        in: "query",
        required: true,
        description: "Opaque state value that will be echoed back after approval.",
        schema: { type: "string" }
      },
      {
        name: "response_type",
        in: "query",
        required: true,
        description: "OAuth response type. Only `code` is supported.",
        schema: { type: "string", enum: ["code"] }
      },
      {
        name: "code_challenge",
        in: "query",
        required: true,
        description: "PKCE code challenge generated by the client.",
        schema: { type: "string" }
      },
      {
        name: "code_challenge_method",
        in: "query",
        required: true,
        description: "PKCE code challenge method used by the client.",
        schema: { type: "string", enum: ["S256", "plain"] }
      }
    ];
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/OAuthAuthorizationFormResponse"
    );
  });

  applyOperationOverride(spec, "POST", "/v2/businesses/files", (operation) => {
    setOperationText(
      operation,
      "Initialize a Business File Upload",
      "Creates a pending business file record and returns the presigned upload URL for the authenticated business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/BusinessFileUploadInitRequest", {
      description:
        "Filename, MIME type, and content length used to initialize a business file upload.",
      required: true
    });
  });

  applyOperationOverride(spec, "GET", "/v2/customers/me/subscription-items/{id}/downgrade", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/SubscriptionVariantOptionsResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/customers/me/subscription-items/{id}/upgrade", (operation) => {
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/SubscriptionVariantOptionsResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/fb/pages", (operation) => {
    setOperationText(
      operation,
      "List Connected Facebook Pages",
      "Returns Facebook Pages that are currently available to the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/fb/pages/{page_id}", (operation) => {
    setOperationText(
      operation,
      "Get a Connected Facebook Page",
      "Returns the specified Facebook Page for the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/fb/pages/{page_id}/posts", (operation) => {
    setOperationText(
      operation,
      "List Facebook Page Posts",
      "Returns posts for the specified Facebook Page available to the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/fb/synced-adaccounts", (operation) => {
    setOperationText(
      operation,
      "List Synced Facebook Ad Accounts",
      "Returns Facebook ad accounts that are already synced to the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/fb/synced-adaccounts/{account_id}", (operation) => {
    setOperationText(
      operation,
      "Get a Synced Facebook Ad Account",
      "Returns the specified synced Facebook ad account for the authenticated business."
    );
  });

  applyOperationOverride(spec, "GET", "/v2/businesses/enabled-payments", (operation) => {
    setOperationText(
      operation,
      "Get Enabled E-Payments for the Current Business",
      "Returns the enabled e-payment methods for the authenticated business context."
    );
  });

  applyOperationOverride(spec, "POST", "/v2/subscription-items/{id}/upgrade", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/SubscriptionItemChangeRequest", {
      description: "Variant selection payload used to upgrade the specified subscription item.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/subscription-items/{id}/downgrade", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/SubscriptionItemChangeRequest", {
      description: "Variant selection payload used to downgrade the specified subscription item.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/subscription-items/{id}/upgrade", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/SubscriptionItemChangeRequest", {
      description: "Variant selection payload used to upgrade the specified subscription item.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/customers/me/subscription-items/{id}/downgrade", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/SubscriptionItemChangeRequest", {
      description: "Variant selection payload used to downgrade the specified subscription item.",
      required: true
    });
  });

  applyOperationOverride(spec, "POST", "/v2/mailketing-integrations", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/MailketingIntegrationRequest", {
      description: "Mailketing identifier and API token payload for the authenticated business.",
      required: true
    });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/MailketingIntegrationResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/mailketing-integrations/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/MailketingIntegrationResponse"
    );
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/mailketing-integrations/{id}", (operation) => {
      setOperationPathParameterSchema(operation, "id", { type: "integer" });
      setOperationRequestSchema(operation, "#/components/schemas/MailketingIntegrationRequest", {
        description: "Mailketing identifier and API token payload for the authenticated business.",
        required: true
      });
      setOperationJsonResponse(
        operation,
        "200",
        "Success",
        "#/components/schemas/MailketingIntegrationResponse"
      );
    });
  }

  applyOperationOverride(spec, "DELETE", "/v2/mailketing-integrations/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
  });

  applyOperationOverride(spec, "GET", "/v2/mailketing-integrations/{mailketing_integration_id}/lists", (operation) => {
    setOperationPathParameterSchema(operation, "mailketing_integration_id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/MailketingListArrayResponse"
    );
  });

  applyOperationOverride(spec, "PATCH", "/v2/mailketing-integrations/{mailketing_integration_id}/sync", (operation) => {
    setOperationPathParameterSchema(operation, "mailketing_integration_id", { type: "integer" });
  });

  applyOperationOverride(spec, "POST", "/v2/whatsapp-integrations", (operation) => {
    setOperationRequestSchema(operation, "#/components/schemas/WhatsappIntegrationRequest", {
      description: "Provider configuration payload for the authenticated business WhatsApp integration.",
      required: true
    });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/WhatsappIntegrationResponse"
    );
  });

  applyOperationOverride(spec, "GET", "/v2/whatsapp-integrations/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/WhatsappIntegrationResponse"
    );
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/whatsapp-integrations/{id}", (operation) => {
      setOperationPathParameterSchema(operation, "id", { type: "integer" });
      setOperationRequestSchema(operation, "#/components/schemas/WhatsappIntegrationRequest", {
        description: "Provider configuration payload for the authenticated business WhatsApp integration.",
        required: true
      });
      setOperationJsonResponse(
        operation,
        "200",
        "Success",
        "#/components/schemas/WhatsappIntegrationResponse"
      );
    });
  }

  applyOperationOverride(spec, "DELETE", "/v2/whatsapp-integrations/{id}", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
  });

  applyOperationOverride(spec, "POST", "/v2/whatsapp-integrations/{id}/check-status", (operation) => {
    setOperationPathParameterSchema(operation, "id", { type: "integer" });
  });

  applyOperationOverride(spec, "PUT", "/v2/ses/email-identities/{id}", (operation) => {
    setOperationText(
      operation,
      "Update an Email Identity",
      "Updates the specified SES email identity for the authenticated business."
    );
    setOperationRequestSchema(operation, "#/components/schemas/EmailIdentityUpdateRequest", {
      description: "SES email identity fields to update for the authenticated business.",
      required: false
    });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/EmailIdentityResponse"
    );
  });

  for (const method of ["PUT", "PATCH"]) {
    applyOperationOverride(spec, method, "/v2/notifications/{id}", (operation) => {
      setOperationText(
        operation,
        "Set Notification Read State",
        "Sets the read state of the specified notification for the authenticated business."
      );
      setOperationPathParameterSchema(operation, "id", { type: "integer" });
      setOperationRequestSchema(operation, "#/components/schemas/NotificationUpdateRequest", {
        description: "Notification read-state payload for the authenticated business.",
        required: true
      });
      setOperationJsonResponse(
        operation,
        "200",
        "Success",
        "#/components/schemas/NotificationResponse"
      );
    });
  }

  applyOperationOverride(spec, "POST", "/v2/notifications/{notification_id}/mark-as-read", (operation) => {
    setOperationPathParameterSchema(operation, "notification_id", { type: "integer" });
    setOperationPathParameterDescription(operation, "notification_id", "ID of the notification");
  });

  applyOperationOverride(spec, "POST", "/v2/chatbot/analyze-conversation", (operation) => {
    setOperationText(
      operation,
      "Analyze a Chatbot Conversation",
      "Analyzes the supplied chatbot conversation payload and returns the inferred conversation state, response, usage, and order context."
    );
    setOperationRequestSchema(operation, "#/components/schemas/ChatbotConversationAnalysisRequest", {
      description: "Conversation payload to analyze.",
      required: true
    });
    setOperationJsonResponse(
      operation,
      "200",
      "Success",
      "#/components/schemas/ChatbotConversationAnalysisResponse"
    );
  });
}

function buildLookup(mapObject) {
  return new Map(Object.entries(mapObject).map(([name, value]) => [canonicalize(value), name]));
}

function inferResponseComponentBaseName(response, statusCode) {
  const schema = response?.content?.["application/json"]?.schema;
  const schemaRefName = extractSchemaComponentName(schema?.$ref);
  if (schemaRefName) {
    return statusCode === "200" ? schemaRefName : `${schemaRefName}${statusCode}`;
  }

  const payloadRefName = extractSchemaComponentName(schema?.properties?.data?.$ref);
  if (payloadRefName) {
    const base = payloadRefName.endsWith("Response") ? payloadRefName : `${payloadRefName}Response`;
    return statusCode === "200" ? base : `${base}${statusCode}`;
  }

  const listItemRefName = extractSchemaComponentName(
    schema?.properties?.data?.properties?.results?.items?.$ref
  );
  if (listItemRefName) {
    return statusCode === "200" ? `${listItemRefName}ListResponse` : `${listItemRefName}ListResponse${statusCode}`;
  }

  return statusCode === "200" ? "PromotedResponse" : `PromotedResponse${statusCode}`;
}

function inferRequestBodyComponentBaseName(requestBody) {
  const [contentType] = Object.keys(requestBody?.content || {});
  const schemaRefName = extractSchemaComponentName(
    requestBody?.content?.[contentType || "application/json"]?.schema?.$ref
  );

  if (schemaRefName) {
    return schemaRefName.endsWith("Body") ? schemaRefName : `${schemaRefName}Body`;
  }

  return contentType === "multipart/form-data" ? "MultipartRequestBody" : "JsonRequestBody";
}

function inferParameterComponentBaseName(parameter) {
  return `${componentize(parameter.name)}${componentize(parameter.in)}Parameter`;
}

function promoteRepeatedRequestBodies(spec) {
  const requestBodies = ensureObject(ensureObject(spec, "components"), "requestBodies");
  const existingNames = new Set(Object.keys(requestBodies));
  const usage = new Map();

  for (const { operation } of iterateOperations(spec)) {
    if (!operation.requestBody || operation.requestBody.$ref) {
      continue;
    }

    const key = canonicalizeOmittingKeys(operation.requestBody, ["example", "examples"]);
    const occurrences = usage.get(key) || [];
    occurrences.push(operation);
    usage.set(key, occurrences);
  }

  for (const operations of usage.values()) {
    if (operations.length < 2) {
      continue;
    }

    const [first] = operations;
    const name = uniqueComponentName(existingNames, inferRequestBodyComponentBaseName(first.requestBody));
    requestBodies[name] = first.requestBody;

    for (const operation of operations) {
      operation.requestBody = { $ref: `#/components/requestBodies/${name}` };
    }
  }
}

function promoteRepeatedParameters(spec) {
  const parameters = ensureObject(ensureObject(spec, "components"), "parameters");
  const existingNames = new Set(Object.keys(parameters));
  const usage = new Map();

  const collectParameterOccurrences = (holder) => {
    if (!Array.isArray(holder?.parameters)) {
      return;
    }

    for (let index = 0; index < holder.parameters.length; index += 1) {
      const parameter = holder.parameters[index];
      if (!parameter || parameter.$ref) {
        continue;
      }

      const key = canonicalizeOmittingKeys(parameter, ["example", "examples"]);
      const occurrences = usage.get(key) || [];
      occurrences.push({ holder, index, parameter });
      usage.set(key, occurrences);
    }
  };

  for (const pathItem of Object.values(spec.paths || {})) {
    collectParameterOccurrences(pathItem);
  }

  for (const { operation } of iterateOperations(spec)) {
    collectParameterOccurrences(operation);
  }

  for (const occurrences of usage.values()) {
    if (occurrences.length < 2) {
      continue;
    }

    const name = uniqueComponentName(existingNames, inferParameterComponentBaseName(occurrences[0].parameter));
    parameters[name] = occurrences[0].parameter;

    for (const occurrence of occurrences) {
      occurrence.holder.parameters[occurrence.index] = {
        $ref: `#/components/parameters/${name}`
      };
    }
  }
}

function promoteRepeatedResponses(spec) {
  const responses = ensureObject(ensureObject(spec, "components"), "responses");
  const existingNames = new Set(Object.keys(responses));
  const usage = new Map();

  for (const { operation } of iterateOperations(spec)) {
    for (const [statusCode, response] of Object.entries(operation.responses || {})) {
      if (!response || response.$ref || response.headers) {
        continue;
      }

      const key = canonicalizeOmittingKeys(response, ["example", "examples"]);
      const occurrences = usage.get(key) || [];
      occurrences.push({ operation, statusCode, response });
      usage.set(key, occurrences);
    }
  }

  for (const occurrences of usage.values()) {
    if (occurrences.length < 2) {
      continue;
    }

    const { statusCode, response } = occurrences[0];
    const name = uniqueComponentName(existingNames, inferResponseComponentBaseName(response, statusCode));
    responses[name] = response;

    for (const occurrence of occurrences) {
      occurrence.operation.responses[occurrence.statusCode] = {
        $ref: `#/components/responses/${name}`
      };
    }
  }
}

function resolveParameterReference(spec, parameter) {
  const match = parameter?.$ref?.match(/^#\/components\/parameters\/(.+)$/);
  return match ? spec.components?.parameters?.[match[1]] || null : parameter;
}

function dedupeParameterHolders(spec, holder) {
  if (!Array.isArray(holder?.parameters) || holder.parameters.length < 2) {
    return;
  }

  const deduped = [];
  const seen = new Set();

  for (let index = holder.parameters.length - 1; index >= 0; index -= 1) {
    const parameter = holder.parameters[index];
    const resolved = resolveParameterReference(spec, parameter);
    const key =
      resolved?.in && resolved?.name
        ? `${resolved.in}:${resolved.name}`
        : canonicalize(parameter);

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.unshift(parameter);
  }

  holder.parameters = deduped;
}

function dedupePromotedParameters(spec) {
  for (const pathItem of Object.values(spec.paths || {})) {
    dedupeParameterHolders(spec, pathItem);
  }

  for (const { operation } of iterateOperations(spec)) {
    dedupeParameterHolders(spec, operation);
  }
}

function normalizePageSizeParameters(spec) {
  const parameters = spec.components?.parameters;
  if (!parameters) {
    return;
  }

  parameters.PageSizeQueryParameter = {
    description: "Number of items per page (default: 25, max: 25)",
    in: "query",
    name: "page_size",
    required: false,
    schema: {
      example: 25,
      maximum: 25,
      type: "integer"
    }
  };

  const aliases = ["PageSizeQueryParameter3", "PageSizeQueryParameter4"];
  const aliasRefs = new Map(
    aliases
      .filter((name) => parameters[name])
      .map((name) => [`#/components/parameters/${name}`, "#/components/parameters/PageSizeQueryParameter"])
  );

  if (aliasRefs.size === 0) {
    return;
  }

  const rewriteHolder = (holder) => {
    if (!Array.isArray(holder?.parameters)) {
      return;
    }

    holder.parameters = holder.parameters.map((parameter) =>
      parameter?.$ref && aliasRefs.has(parameter.$ref)
        ? { $ref: aliasRefs.get(parameter.$ref) }
        : parameter
    );
  };

  for (const pathItem of Object.values(spec.paths || {})) {
    rewriteHolder(pathItem);
  }

  for (const { operation } of iterateOperations(spec)) {
    rewriteHolder(operation);
  }

  for (const alias of aliases) {
    delete parameters[alias];
  }
}

function isSchemaLikeObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const schemaKeys = new Set([
    "$ref",
    "type",
    "properties",
    "items",
    "allOf",
    "anyOf",
    "oneOf",
    "required",
    "enum",
    "format",
    "nullable",
    "additionalProperties",
    "title",
    "description"
  ]);

  return Object.keys(value).some((key) => schemaKeys.has(key));
}

function isSharedPeriodUnitSchema(schema) {
  return (
    schema?.type === "string" &&
    Array.isArray(schema.enum) &&
    schema.enum.length === 4 &&
    schema.enum.join("|") === "day|week|month|year"
  );
}

function replaceInlineSchema(schema, schemaLookup, schemaNames) {
  if (Array.isArray(schema)) {
    return schema.map((item) => replaceInlineSchema(item, schemaLookup, schemaNames));
  }

  if (!schema || typeof schema !== "object") {
    return schema;
  }

  if (schema.$ref) {
    return schema;
  }

  const normalized = Object.fromEntries(
    Object.entries(schema).map(([key, value]) => [
      key,
      replaceInlineSchema(value, schemaLookup, schemaNames)
    ])
  );

  if (!isSchemaLikeObject(normalized)) {
    return normalized;
  }

  if (isSharedPeriodUnitSchema(normalized)) {
    return { $ref: "#/components/schemas/PeriodUnit" };
  }

  const singleInnerSchema =
    (Array.isArray(normalized.oneOf) && normalized.oneOf.length === 1 && normalized.oneOf[0]) ||
    (Array.isArray(normalized.allOf) && normalized.allOf.length === 1 && normalized.allOf[0]);

  if (normalized.nullable && singleInnerSchema) {
    const innerMatch =
      singleInnerSchema.$ref || schemaLookup.get(canonicalize(singleInnerSchema));

    if (typeof innerMatch === "string") {
      const ref = innerMatch.startsWith("#/components/schemas/")
        ? innerMatch
        : `#/components/schemas/${innerMatch}`;

      return {
        type: "object",
        allOf: [{ $ref: ref }],
        nullable: true
      };
    }
  }

  if (typeof normalized.title === "string" && schemaNames.has(normalized.title)) {
    return { $ref: `#/components/schemas/${normalized.title}` };
  }

  const match = schemaLookup.get(canonicalize(normalized));
  return match ? { $ref: `#/components/schemas/${match}` } : normalized;
}

function normalizeNestedComponentSchema(schema, schemaLookup, schemaNames) {
  if (Array.isArray(schema)) {
    return schema.map((item) => normalizeNestedComponentSchema(item, schemaLookup, schemaNames));
  }

  if (!schema || typeof schema !== "object" || schema.$ref) {
    return schema;
  }

  const normalized = {};

  for (const [key, value] of Object.entries(schema)) {
    if (key === "properties" && value && typeof value === "object" && !Array.isArray(value)) {
      normalized[key] = Object.fromEntries(
        Object.entries(value).map(([propertyName, propertySchema]) => [
          propertyName,
          replaceInlineSchema(
            normalizeNestedComponentSchema(propertySchema, schemaLookup, schemaNames),
            schemaLookup,
            schemaNames
          )
        ])
      );
      continue;
    }

    if (["items", "additionalProperties", "oneOf", "allOf", "anyOf", "not"].includes(key)) {
      const child = normalizeNestedComponentSchema(value, schemaLookup, schemaNames);
      normalized[key] = replaceInlineSchema(child, schemaLookup, schemaNames);
      continue;
    }

    normalized[key] = normalizeNestedComponentSchema(value, schemaLookup, schemaNames);
  }

  return normalized;
}

function normalizeComponentReuse(spec) {
  const schemas = spec.components?.schemas || {};
  const responses = spec.components?.responses || {};
  const parameters = spec.components?.parameters || {};
  const requestBodies = spec.components?.requestBodies || {};
  const schemaLookup = buildLookup(schemas);
  const schemaNames = new Set(Object.keys(schemas));
  const responseLookup = buildLookup(responses);

  for (const [schemaName, schema] of Object.entries(schemas)) {
    if (schemaName !== "PeriodUnit" && schema && typeof schema === "object" && !schema.$ref) {
      schemas[schemaName] = normalizeNestedComponentSchema(schema, schemaLookup, schemaNames);
    }
  }

  for (const parameter of Object.values(parameters)) {
    if (parameter?.schema) {
      parameter.schema = replaceInlineSchema(parameter.schema, schemaLookup, schemaNames);
    }

    if (parameter?.content) {
      for (const mediaType of Object.values(parameter.content)) {
        if (mediaType?.schema) {
          mediaType.schema = replaceInlineSchema(mediaType.schema, schemaLookup, schemaNames);
        }
      }
    }
  }

  for (const requestBody of Object.values(requestBodies)) {
    if (requestBody?.content) {
      for (const mediaType of Object.values(requestBody.content)) {
        if (mediaType?.schema) {
          mediaType.schema = replaceInlineSchema(mediaType.schema, schemaLookup, schemaNames);
        }
      }
    }
  }

  for (const pathItem of Object.values(spec.paths || {})) {
    for (const parameter of pathItem?.parameters || []) {
      if (parameter?.schema) {
        parameter.schema = replaceInlineSchema(parameter.schema, schemaLookup, schemaNames);
      }

      if (parameter?.content) {
        for (const mediaType of Object.values(parameter.content)) {
          if (mediaType?.schema) {
            mediaType.schema = replaceInlineSchema(mediaType.schema, schemaLookup, schemaNames);
          }
        }
      }
    }
  }

  for (const { operation } of iterateOperations(spec)) {
    for (const parameter of operation.parameters || []) {
      if (parameter?.schema) {
        parameter.schema = replaceInlineSchema(parameter.schema, schemaLookup, schemaNames);
      }

      if (parameter?.content) {
        for (const mediaType of Object.values(parameter.content)) {
          if (mediaType?.schema) {
            mediaType.schema = replaceInlineSchema(mediaType.schema, schemaLookup, schemaNames);
          }
        }
      }
    }

    if (operation.requestBody?.content) {
      for (const mediaType of Object.values(operation.requestBody.content)) {
        if (mediaType?.schema) {
          mediaType.schema = replaceInlineSchema(mediaType.schema, schemaLookup, schemaNames);
        }
      }
    }

    for (const [statusCode, response] of Object.entries(operation.responses || {})) {
      const directMatch = responseLookup.get(canonicalize(response));
      if (directMatch) {
        operation.responses[statusCode] = { $ref: `#/components/responses/${directMatch}` };
        continue;
      }

      if (response.content) {
        for (const mediaType of Object.values(response.content)) {
          if (mediaType?.schema) {
            mediaType.schema = replaceInlineSchema(mediaType.schema, schemaLookup, schemaNames);
          }
        }

        const normalizedMatch = responseLookup.get(canonicalize(response));
        if (normalizedMatch) {
          operation.responses[statusCode] = {
            $ref: `#/components/responses/${normalizedMatch}`
          };
        }
      }
    }
  }
}

function promoteSchemaBackedResponses(spec) {
  const responses = ensureObject(ensureObject(spec, "components"), "responses");
  const existingNames = new Set(Object.keys(responses));
  const promotedByKey = new Map();

  for (const { operation } of iterateOperations(spec)) {
    for (const [statusCode, response] of Object.entries(operation.responses || {})) {
      if (response?.$ref || response?.headers) {
        continue;
      }

      const mediaTypes = response?.content ? Object.keys(response.content) : [];
      if (mediaTypes.length !== 1 || mediaTypes[0] !== "application/json") {
        continue;
      }

      const schemaRef = response.content?.["application/json"]?.schema?.$ref;
      const match = schemaRef?.match(/^#\/components\/schemas\/([A-Za-z0-9_.-]+Response)$/);
      if (!match) {
        continue;
      }

      const [, schemaName] = match;
      const baseName = statusCode === "200" ? schemaName : `${schemaName}${statusCode}`;
      const promotionKey = `${statusCode}:${schemaRef}`;
      const componentName =
        promotedByKey.get(promotionKey) ||
        (existingNames.has(baseName) ? baseName : uniqueComponentName(existingNames, baseName));
      const description = statusCode === "201" ? "Created" : "Success";

      responses[componentName] = {
        description,
        content: {
          "application/json": {
            schema: {
              $ref: schemaRef
            }
          }
        }
      };
      promotedByKey.set(promotionKey, componentName);

      operation.responses[statusCode] = {
        $ref: `#/components/responses/${componentName}`
      };
    }
  }
}
function dedupeOperationIds(spec) {
  const seen = new Map();

  for (const { routePath, method, operation } of iterateOperations(spec)) {
    const operationId = operation.operationId;
    if (!operationId) {
      continue;
    }

    const occurrences = seen.get(operationId) || [];
    occurrences.push({ routePath, method, operation });
    seen.set(operationId, occurrences);
  }

  for (const [operationId, occurrences] of seen.entries()) {
    if (occurrences.length < 2) {
      continue;
    }

    for (const occurrence of occurrences) {
      const pathSuffix = occurrence.routePath
        .replace(/^\/v2\//, "")
        .replace(/[{}]/g, "")
        .replace(/\//g, ".")
        .replace(/[^A-Za-z0-9_.-]/g, "-");

      occurrence.operation.operationId = `${operationId}.${pathSuffix}.${occurrence.method.toLowerCase()}`;
    }
  }
}

function collectRefs(value, refs = new Set()) {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectRefs(item, refs);
    }

    return refs;
  }

  if (!value || typeof value !== "object") {
    return refs;
  }

  if (typeof value.$ref === "string") {
    refs.add(value.$ref);
  }

  for (const nested of Object.values(value)) {
    collectRefs(nested, refs);
  }

  return refs;
}

function removeUnusedInferredRequestSchemas(spec) {
  const schemas = spec.components?.schemas;
  if (!schemas) {
    return;
  }

  const refs = collectRefs(spec.paths || {});

  for (const schemaName of Object.keys(schemas)) {
    if (
      schemaName.startsWith("Inferred") &&
      !refs.has(`#/components/schemas/${schemaName}`)
    ) {
      delete schemas[schemaName];
    }
  }
}

function collectReachableComponentRefs(spec) {
  const reachableSchemas = new Set();
  const reachableResponses = new Set();
  const reachableParameters = new Set();
  const reachableRequestBodies = new Set();
  const schemas = spec.components?.schemas || {};
  const responses = spec.components?.responses || {};
  const parameters = spec.components?.parameters || {};
  const requestBodies = spec.components?.requestBodies || {};
  const queue = [...collectRefs(spec.paths || {})];

  while (queue.length > 0) {
    const ref = queue.pop();
    let match;

    if ((match = ref.match(/^#\/components\/schemas\/(.+)$/))) {
      const schemaName = match[1];
      if (reachableSchemas.has(schemaName) || !schemas[schemaName]) {
        continue;
      }

      reachableSchemas.add(schemaName);
      for (const nestedRef of collectRefs(schemas[schemaName], new Set())) {
        queue.push(nestedRef);
      }
      continue;
    }

    if ((match = ref.match(/^#\/components\/responses\/(.+)$/))) {
      const responseName = match[1];
      if (reachableResponses.has(responseName) || !responses[responseName]) {
        continue;
      }

      reachableResponses.add(responseName);
      for (const nestedRef of collectRefs(responses[responseName], new Set())) {
        queue.push(nestedRef);
      }
      continue;
    }

    if ((match = ref.match(/^#\/components\/parameters\/(.+)$/))) {
      const parameterName = match[1];
      if (reachableParameters.has(parameterName) || !parameters[parameterName]) {
        continue;
      }

      reachableParameters.add(parameterName);
      for (const nestedRef of collectRefs(parameters[parameterName], new Set())) {
        queue.push(nestedRef);
      }
      continue;
    }

    if ((match = ref.match(/^#\/components\/requestBodies\/(.+)$/))) {
      const requestBodyName = match[1];
      if (reachableRequestBodies.has(requestBodyName) || !requestBodies[requestBodyName]) {
        continue;
      }

      reachableRequestBodies.add(requestBodyName);
      for (const nestedRef of collectRefs(requestBodies[requestBodyName], new Set())) {
        queue.push(nestedRef);
      }
    }
  }

  return { reachableSchemas, reachableResponses, reachableParameters, reachableRequestBodies };
}

function removeUnusedComponents(spec) {
  const schemas = spec.components?.schemas;
  const responses = spec.components?.responses;
  const parameters = spec.components?.parameters;
  const requestBodies = spec.components?.requestBodies;

  if (!schemas && !responses && !parameters && !requestBodies) {
    return;
  }

  const {
    reachableSchemas,
    reachableResponses,
    reachableParameters,
    reachableRequestBodies
  } = collectReachableComponentRefs(spec);

  if (schemas) {
    for (const schemaName of Object.keys(schemas)) {
      if (!reachableSchemas.has(schemaName)) {
        delete schemas[schemaName];
      }
    }
  }

  if (responses) {
    for (const responseName of Object.keys(responses)) {
      if (!reachableResponses.has(responseName)) {
        delete responses[responseName];
      }
    }
  }

  if (parameters) {
    for (const parameterName of Object.keys(parameters)) {
      if (!reachableParameters.has(parameterName)) {
        delete parameters[parameterName];
      }
    }
  }

  if (requestBodies) {
    for (const requestBodyName of Object.keys(requestBodies)) {
      if (!reachableRequestBodies.has(requestBodyName)) {
        delete requestBodies[requestBodyName];
      }
    }
  }
}

const spec = parse(fs.readFileSync(specPath, "utf8"));

restoreCorruptedSelfRefSchemas(spec);
ensureSharedComponents(spec);
removeDocumentedAliasPaths(spec);
removeDocumentedPublicPaths(spec);
removeIgnoredOperations(spec);

const { addedOperations, routes } = syncRoutes(spec);

removeUnexpectedDocumentedOperations(spec, routes);
normalizeRouteOperations(spec, routes);
applyRouteSpecificOverrides(spec);
applySpecMetadataOverrides(spec);
normalizeDocumentationTextFields(spec);
normalizeRequestBodyDescriptions(spec);
normalizePathParameterSchemas(spec);
normalizeDateTimeFormats(spec);
relaxDeleteRequestBodies(spec);
syncTopLevelTags(spec);
normalizeComponentReuse(spec);
promoteSchemaBackedResponses(spec);
promoteRepeatedResponses(spec);
promoteRepeatedRequestBodies(spec);
promoteRepeatedParameters(spec);
normalizePageSizeParameters(spec);
dedupePromotedParameters(spec);
removeUnusedComponents(spec);
dedupeOperationIds(spec);

fs.writeFileSync(specPath, stringify(spec, { lineWidth: 0 }));

const routeKinds = routes.reduce(
  (acc, route) => {
    const kind = classifyRouteKind(route);
    acc[kind] = (acc[kind] || 0) + 1;
    return acc;
  },
  {}
);

console.log(`added_operations ${addedOperations}`);
console.log(`business_routes ${routeKinds.business || 0}`);
console.log(`customer_routes ${routeKinds.customer || 0}`);
console.log(`oauth_only_routes ${routeKinds.oauth_only || 0}`);
console.log(`user_routes ${routeKinds.user || 0}`);
