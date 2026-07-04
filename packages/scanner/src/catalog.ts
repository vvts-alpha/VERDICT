// General-purpose validator catalog. applicable() launches only the relevant checks based on the screen/API (§7.3).

import type { Validator } from "./validator.js";
import { exposedFile } from "./validators/exposed-file.js";
import { authRequired } from "./validators/auth-required.js";
import { corsMisconfig } from "./validators/cors.js";

export const CATALOG: Validator[] = [exposedFile, authRequired, corsMisconfig];
