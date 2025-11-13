# eva-safety (Enterprise Edition)

Enterprise content safety toolkit for EVA 2.0:
- Detectors: PII (email, phone, SSN, IP, credit card w/ Luhn), secrets (AWS, GitHub, OpenAI, JWT), toxicity lexicon, jailbreak heuristic
- Policy engine: rules with actions (block, sanitize, flag, allow), severity, categories
- Redaction utilities: length-preserving masking, partial masks (e.g., credit cards last-4)
- Middleware: framework-agnostic handler to sanitize incoming structures
- Zero runtime dependencies; Enterprise toolchain: ESLint v9 flat config, Prettier, Vitest coverage ≥80%, Husky + lint-staged

Quick usage
```ts
import { getDefaultPolicy, PolicyEngine } from "./dist/policy/engine.js";

const engine = new PolicyEngine(getDefaultPolicy());

// Evaluate text and optionally sanitize
const ev = engine.evaluate("Contact me at john.doe@example.com. AKIA1234567890ABCD is a key.");
if (ev.blocked) {
  console.log("Blocked for:", ev.findings.map(f => f.category));
} else {
  console.log("Sanitized:", ev.sanitizedText);
}
```

Middleware example (framework-agnostic style)
```ts
import { safetyMiddleware } from "./dist/middleware/safety.js";
const mw = safetyMiddleware({ policy: getDefaultPolicy() });
server.use(async (req,res,next) => mw(req,res,next));
```

Coverage
- Vitest thresholds: 80% statements/funcs, 70% branches
- Non-executable barrels excluded

License
MIT