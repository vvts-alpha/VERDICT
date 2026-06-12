// 汎用 validator カタログ。applicable() で画面/API に応じ該当チェックのみ起動(§7.3)。

import type { Validator } from "./validator.js";
import { exposedFile } from "./validators/exposed-file.js";
import { authRequired } from "./validators/auth-required.js";
import { corsMisconfig } from "./validators/cors.js";

export const CATALOG: Validator[] = [exposedFile, authRequired, corsMisconfig];
