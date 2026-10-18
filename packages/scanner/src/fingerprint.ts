// Technology-stack fingerprinting (deterministic, no LLM). From the response's headers/Cookie/meta/script-src
// it structurally extracts the "name + version" of server, middleware, language, framework, CMS, and frontend libraries.
// Of the known-vuln matching, **JS libraries are annotated deterministically via the VULN_JS_LIBS catalog**, while server/middleware/language
// just collect versions, evaluated by pilot's A06 stage (the LLM's CVE knowledge). Collection is reliable; evaluation is knowledge-dependent.

import { VULN_JS_LIBS, versionLeq } from "./passive.js";

export type TechKind = "server" | "language" | "framework" | "cms" | "frontend-lib" | "backend-lib";

export interface TechComponent {
  kind: TechKind;
  name: string;
  /** the version obtained (e.g. "2.4.41"). null if there's only a banner with no version. */
  version: string | null;
  /** detection source (header name / "cookie" / "meta generator" / "script src"). */
  source: string;
  /** the raw clue (basis for the report/evidence). */
  evidence: string;
  /** note when it matches a known-vulnerable version (JS library catalog only; empty means unmatched = evaluated at the LLM stage). */
  knownVuln?: string;
}

export interface TechSample {
  url: string;
  headers: Record<string, string>;
  body: string;
}

/** "Apache/2.4.41 (Ubuntu)" / "nginx/1.18.0" / "PHP/7.4.3" → { name, version } */
function splitBanner(v: string): { name: string; version: string | null } {
  const m = /^([A-Za-z][\w.+-]*?)[/ ]v?(\d+(?:\.\d+){0,3})/.exec(v.trim());
  if (m) return { name: m[1]!, version: m[2]! };
  const first = v.trim().split(/[\s(;,]/)[0] ?? v.trim();
  return { name: first, version: null };
}

// header → kind (splitBanner splits the banner into name+version)
const BANNER_HEADERS: { header: string; kind: TechKind }[] = [
  { header: "server", kind: "server" },
  { header: "x-powered-by", kind: "framework" },
  { header: "via", kind: "server" },
];

// headers that carry the version directly (the value itself is the version)
const VERSION_VALUE_HEADERS: { header: string; kind: TechKind; name: string }[] = [
  { header: "x-aspnet-version", kind: "framework", name: "ASP.NET" },
  { header: "x-aspnetmvc-version", kind: "framework", name: "ASP.NET MVC" },
  { header: "x-generator", kind: "cms", name: "(generator)" },
  { header: "microsoftsharepointteamservices", kind: "cms", name: "Microsoft SharePoint" },
];

// Set-Cookie name → framework/language (no version, but reveals "what it's built with")
const COOKIE_TECH: { re: RegExp; kind: TechKind; name: string }[] = [
  { re: /\bPHPSESSID\b/i, kind: "language", name: "PHP" },
  { re: /\bJSESSIONID\b/i, kind: "language", name: "Java (servlet container)" },
  { re: /\bconnect\.sid\b/i, kind: "framework", name: "Express / Node.js" },
  { re: /\blaravel_session\b/i, kind: "framework", name: "Laravel (PHP)" },
  { re: /\bci_session\b/i, kind: "framework", name: "CodeIgniter (PHP)" },
  { re: /\b_session_id\b/i, kind: "framework", name: "Ruby on Rails" },
  { re: /\bASP\.NET_SessionId\b/i, kind: "framework", name: "ASP.NET" },
  { re: /\bcsrftoken\b/i, kind: "framework", name: "Django" },
];

function scriptRefs(body: string): string[] {
  const out: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) if (m[1]) out.push(m[1]);
  return out;
}

/**
 * Extract and deduplicate technology components from one or more response samples.
 * JS libraries are matched against VULN_JS_LIBS; a known-vulnerable version gets a knownVuln annotation (deterministic).
 */
export function fingerprintTech(samples: ReadonlyArray<TechSample>): TechComponent[] {
  const byKey = new Map<string, TechComponent>();
  const add = (c: TechComponent): void => {
    const key = `${c.kind}|${c.name.toLowerCase()}|${c.version ?? ""}`;
    if (!byKey.has(key)) byKey.set(key, c);
  };

  for (const s of samples) {
    const h = s.headers;
    // banner headers (Server / X-Powered-By / Via)
    for (const { header, kind } of BANNER_HEADERS) {
      const v = h[header];
      if (!v) continue;
      // X-Powered-By may have multiple values like "PHP/7.4.3" or "Express"
      for (const part of v.split(",")) {
        const { name, version } = splitBanner(part);
        if (!name) continue;
        add({ kind, name, version, source: header, evidence: `${header}: ${v}`.slice(0, 200) });
      }
    }
    // headers whose value is the version itself
    for (const { header, kind, name } of VERSION_VALUE_HEADERS) {
      const v = h[header];
      if (v && /\d/.test(v)) {
        const nm = name === "(generator)" ? splitBanner(v).name || "generator" : name;
        add({ kind, name: nm, version: splitBanner(v).version ?? v.trim().slice(0, 40), source: header, evidence: `${header}: ${v}`.slice(0, 200) });
      }
    }
    // Set-Cookie name → framework lineage
    const setCookie = h["set-cookie"] ?? "";
    if (setCookie) {
      for (const c of COOKIE_TECH) {
        if (c.re.test(setCookie)) add({ kind: c.kind, name: c.name, version: null, source: "cookie", evidence: `Set-Cookie name matched ${c.re.source}` });
      }
    }
    // <meta name="generator" content="WordPress 6.4">
    const meta = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(s.body);
    if (meta?.[1]) {
      const { name, version } = splitBanner(meta[1]);
      add({ kind: "cms", name: name || meta[1], version, source: "meta generator", evidence: `<meta generator>: ${meta[1]}`.slice(0, 200) });
    }
    // frontend libraries (name+version from the script src filename; knownVuln if a known-vulnerable version)
    for (const ref of scriptRefs(s.body)) {
      for (const lib of VULN_JS_LIBS) {
        const m = lib.re.exec(ref);
        const ver = m?.[1];
        if (!ver) continue;
        add({
          kind: "frontend-lib",
          name: lib.name,
          version: ver,
          source: "script src",
          evidence: ref.slice(0, 200),
          ...(versionLeq(ver, lib.maxVuln) ? { knownVuln: lib.note } : {}),
        });
      }
    }
    // SharePoint hive paths (/_layouts/15/, corev15.css) identify the PRODUCT, not a patch version.
    // 2016 / 2019 / Subscription / Online still serve the 15 hive for compatibility — not "SharePoint 2013".
    if (
      /\/_layouts\/\d+\//.test(s.body) ||
      /corev\d+\.css/i.test(s.body) ||
      /\/_catalogs\/masterpage\//i.test(s.body)
    ) {
      add({
        kind: "cms",
        name: "Microsoft SharePoint",
        version: null,
        source: "path",
        evidence: "/_layouts/ or corevN.css (hive path is not a patch version)",
      });
    }
  }
  return [...byKey.values()];
}

// ── Backend-library guessing (body-side signals) ──────────────────────────────
// Bug-bounty reality: the interesting n-days live in BACKEND libraries — image/doc parsers,
// serialization stacks, template engines — that never appear in headers. These extractors pull
// lib names (and versions when leaked) out of response bodies: stack traces, module paths,
// framework error pages, lockfile fragments, and parser-specific error strings.
// Semantics: every hit is a GUESS (the body merely mentioned the lib) — a lead for n-day hunting,
// not a confirmed install. A leaked `version` (debug page, lockfile, jar filename) upgrades the
// lead into an OSV-matchable component; name-only hits stay "version unknown".
// `source` strength: "error-page"/"lockfile" > "stack-trace" > "module-path"/"error-message".

interface LibSig {
  name: string;
  re: RegExp;
  source: string;
  /** custom version pattern — group 1 is the version (default: "<name>[-@/ =]v?x.y.z" near the hit). */
  vre?: RegExp;
}

// Version shape: x.y[.z[.w]] + optional -/+suffix (rc1, beta.2). No leading '.' — ".jar" etc. is not a version suffix.
const VER = "(\\d+\\.\\d+(?:\\.\\d+){0,3}(?:[-+][\\w.-]+)?)";
const ver = (name: string): RegExp =>
  new RegExp(`${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\\-/@= ]+v?${VER}`, "i");

const BACKEND_LIB_SIGS: LibSig[] = [
  // ── image/media parsers (the classic n-day class) ──
  { name: "sharp", re: /node_modules[\\/]sharp|Error:\s*sharp:|\bsharp@|libvips/i, source: "module-path" },
  { name: "ImageMagick", re: /ImageMagick|imagick|MagickWand|magick\s+(?:identify|convert|mogrify)|delegate failed/i, source: "error-message" },
  { name: "GraphicsMagick", re: /GraphicsMagick|gm\s+\d+\.\d+/i, source: "error-message" },
  { name: "Ghostscript", re: /Ghostscript|gswin32|gsdll|Error: \/undefined in/i, source: "error-message" },
  { name: "Pillow (PIL)", re: /\bPIL\.|Pillow|UnidentifiedImageError|cannot identify image file|site-packages[\\/]PIL\//i, source: "error-message", vre: /Pillow[-= ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)|PIL\/([\d.]+)/i },
  { name: "imageio", re: /site-packages[\\/]imageio|imageio\.core/i, source: "module-path" },
  { name: "libwebp", re: /libwebp|WebPDecode|WEBP support|webpinfo/i, source: "error-message" },
  { name: "libjpeg(-turbo)", re: /libjpeg(?:-turbo)?|JpegError|Unsupported marker type|jpeg_getc|Bogus/i, source: "error-message" },
  { name: "libpng", re: /libpng|iCCP: |IDAT: CRC error|libpng warning/i, source: "error-message" },
  { name: "giflib", re: /giflib|DGifOpen/i, source: "error-message" },
  { name: "ExifTool", re: /ExifTool|exiftool(?:\.pl)?\b/i, source: "error-message" },
  { name: "FFmpeg", re: /\bffmpeg|FFmpeg|avcodec|Invalid data found when processing input|moov atom/i, source: "error-message" },
  { name: "jimp", re: /node_modules[\\/]jimp|jimp@|Jimp\.read/i, source: "module-path" },
  // ── document / archive / office parsers ──
  { name: "Apache PDFBox", re: /org\.apache\.pdfbox|PDFBox|pdfbox-[\d.]+\.jar/i, source: "stack-trace", vre: /pdfbox[-/ ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)|pdfbox-app-([\d.]+)/i },
  { name: "PDFKit", re: /node_modules[\\/]pdfkit|PDFKit\b/i, source: "module-path" },
  { name: "pdf-lib", re: /node_modules[\\/]pdf-lib|pdf-lib@/i, source: "module-path" },
  { name: "iText", re: /com\.itextpdf|iText(?:Sharp)?|itext7?-/i, source: "stack-trace", vre: /itext\d?[-/ ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)|itextpdf-([\d.]+)/i },
  { name: "poppler", re: /poppler|pdftotext|pdftoppm|pdftocairo/i, source: "error-message", vre: /poppler[-/ ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/i },
  { name: "MuPDF", re: /mupdf|MuPDF|\bfitz\b|python-fitz/i, source: "error-message" },
  { name: "Apache Tika", re: /org\.apache\.tika|Apache Tika|TikaException|tika-core/i, source: "stack-trace" },
  { name: "Apache POI", re: /org\.apache\.poi|POIXMLException|poi-ooxml/i, source: "stack-trace" },
  { name: "LibreOffice", re: /\bsoffice|LibreOffice|unoconv|org\.openoffice|com\.sun\.star/i, source: "error-message" },
  { name: "PhpSpreadsheet", re: /PhpOffice|PhpSpreadsheet|phpspreadsheet/i, source: "module-path" },
  { name: "ZXing", re: /com\.google\.zxing|ZXing|zxing\.|NotFoundException.*zxing/i, source: "stack-trace" },
  { name: "qpdf", re: /\bqpdf\b|qpdf::/i, source: "error-message" },
  { name: "ZipArchive (PHP)", re: /ZipArchive|zip\.php|libzip/i, source: "error-message" },
  { name: "rubyzip", re: /rubyzip|Zip::File|zip\/zip\.rb/i, source: "module-path" },
  { name: "SharpZipLib", re: /ICSharpCode\.SharpZipLib|SharpZipLib/i, source: "module-path" },
  // ── XML / YAML / serialization (XXE + deserialization classes) ──
  { name: "lxml", re: /site-packages[\\/]lxml|\blxml\b|lxml\.etree/i, source: "module-path" },
  { name: "libxml2", re: /libxml2|xmlParseDocument|XML_ERR_|libxml error/i, source: "error-message" },
  { name: "Xerces", re: /org\.apache\.xerces|xerces|SAXParseException.*xerces/i, source: "stack-trace" },
  { name: "Saxon", re: /net\.sf\.saxon|\bsaxon|saxonb/i, source: "stack-trace" },
  { name: "jsoup", re: /org\.jsoup|jsoup-/i, source: "stack-trace", vre: /jsoup[-/ ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/i },
  { name: "SnakeYAML", re: /org\.yaml\.snakeyaml|snakeyaml|SnakeYAML|yaml\.load\(|Yaml\.load/i, source: "stack-trace", vre: /snakeyaml[-/ ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/i },
  { name: "Jackson (databind)", re: /com\.fasterxml\.jackson|jackson-databind|JsonMappingException|jackson\.core/i, source: "stack-trace", vre: /jackson[\w.-]*[-/ ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/i },
  { name: "fastjson", re: /com\.alibaba\.fastjson|fastjson/i, source: "stack-trace", vre: /fastjson[-/ ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/i },
  { name: "XStream", re: /com\.thoughtworks\.xstream|XStream|xstream-/i, source: "stack-trace", vre: /xstream[-/ ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/i },
  { name: "Gson", re: /com\.google\.gson|JsonSyntaxException|gson-/i, source: "stack-trace" },
  { name: "protobuf", re: /com\.google\.protobuf|protobuf|InvalidProtocolBufferException/i, source: "stack-trace" },
  { name: "Java deserialization", re: /java\.io\.ObjectInputStream|\.readObject\(\)|ObjectInputFilter|ClassNotFoundException.{0,80}readObject/i, source: "stack-trace" },
  { name: "PHP unserialize", re: /unserialize\(\):|__PHP_Incomplete_Class|__wakeup|phar:\/\//i, source: "error-message" },
  { name: "Python pickle", re: /pickle\.loads|cPickle|__reduce__|Invalid pickle|pickle\.load\b/i, source: "error-message" },
  { name: "PyYAML", re: /site-packages[\\/]yaml|yaml\.safe_load|yaml\.load|pyyaml/i, source: "module-path" },
  // ── template engines (SSTI class) ──
  { name: "Jinja2", re: /jinja2|Jinja2|jinja2\.exceptions|site-packages[\\/]jinja2/i, source: "stack-trace", vre: /Jinja2[-= ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/i },
  { name: "Freemarker", re: /freemarker\.template|freemarker|FreeMarker/i, source: "stack-trace" },
  { name: "Thymeleaf", re: /org\.thymeleaf|thymeleaf/i, source: "stack-trace" },
  { name: "Apache Velocity", re: /org\.apache\.velocity|velocity\.template|VelocityException/i, source: "stack-trace" },
  { name: "Twig", re: /Twig\\|twig\/twig|Twig_Error|Twig\\Error/i, source: "module-path" },
  { name: "Smarty", re: /Smarty|smarty\/libs|SmartyException/i, source: "module-path" },
  { name: "Pug (Jade)", re: /node_modules[\\/]pug|node_modules[\\/]jade|\bjade:/i, source: "module-path" },
  { name: "EJS", re: /node_modules[\\/]ejs|ejs\.render/i, source: "module-path" },
  { name: "Handlebars", re: /node_modules[\\/]handlebars|Handlebars\.compile|handlebars\/lib/i, source: "module-path" },
  { name: "Mako", re: /mako\.template|site-packages[\\/]mako|Mako/i, source: "module-path" },
  // ── ORM / DB drivers ──
  { name: "Sequelize", re: /sequelize|Sequelize[A-Z]|sequelize\.errors/i, source: "stack-trace" },
  { name: "Mongoose", re: /mongoose|MongoError|CastError|mquery/i, source: "stack-trace" },
  { name: "Prisma", re: /@prisma|PrismaClient|prisma\/client|PrismaClientKnownRequestError/i, source: "stack-trace" },
  { name: "TypeORM", re: /typeorm|QueryFailedError/i, source: "stack-trace" },
  { name: "Knex", re: /node_modules[\\/]knex|knex\.js/i, source: "module-path" },
  { name: "SQLAlchemy", re: /sqlalchemy|sqlalchemy\.exc|site-packages[\\/]sqlalchemy/i, source: "stack-trace" },
  { name: "Hibernate", re: /org\.hibernate|HibernateException|hibernate-core/i, source: "stack-trace" },
  { name: "ActiveRecord", re: /ActiveRecord::|activerecord/i, source: "stack-trace" },
  { name: "Eloquent (Laravel DB)", re: /Illuminate\\Database|Eloquent|QueryException.*Illuminate/i, source: "stack-trace" },
  { name: "Doctrine", re: /Doctrine\\|doctrine\/orm|DoctrineException/i, source: "stack-trace" },
  { name: "psycopg", re: /psycopg2?|psycopg\.errors|psycopg\.pool/i, source: "stack-trace" },
  { name: "mysql driver", re: /node_modules[\\/]mysql2?|com\.mysql\.(?:cj\.)?jdbc|MySqlException|mysql\.connector/i, source: "stack-trace" },
  { name: "node-postgres (pg)", re: /node_modules[\\/]pg\/|pg-pool|error:.{0,40}relation.{0,40}does not exist/i, source: "stack-trace" },
  { name: "Npgsql", re: /Npgsql|NpgsqlException/i, source: "stack-trace" },
  { name: "Entity Framework", re: /System\.Data\.Entity|Entity Framework|Microsoft\.EntityFrameworkCore/i, source: "stack-trace" },
  { name: "Gorm", re: /gorm\.io|gorm: |github\.com\/go-gorm/i, source: "stack-trace" },
  // ── logging / infra / http internals (JNDI, deser chains, SSRF helpers) ──
  { name: "Log4j", re: /log4j|org\.apache\.logging\.log4j|LoggingException/i, source: "stack-trace", vre: /log4j[\w.-]*[-/ ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/i },
  { name: "commons-fileupload", re: /org\.apache\.commons\.fileupload|FileUploadException|commons-fileupload/i, source: "stack-trace" },
  { name: "commons-collections", re: /commons-collections|org\.apache\.commons\.collections/i, source: "stack-trace" },
  { name: "OkHttp", re: /okhttp3?\.|OkHttpClient|okhttp-/i, source: "stack-trace" },
  { name: "Apache HttpClient", re: /org\.apache\.http\.|HttpClientException|httpclient-/i, source: "stack-trace" },
  { name: "Guzzle", re: /GuzzleHttp|guzzlehttp|Guzzle\\|guzzle/i, source: "module-path" },
  { name: "requests (Python)", re: /site-packages[\\/]requests|requests\.exceptions|urllib3\./i, source: "module-path" },
  { name: "Netty", re: /io\.netty|netty-/i, source: "stack-trace" },
  { name: "Jetty", re: /org\.eclipse\.jetty|jetty-/i, source: "stack-trace" },
  { name: "Undertow", re: /io\.undertow|undertow-/i, source: "stack-trace" },
  { name: "Werkzeug", re: /werkzeug|Werkzeug|werkzeug\.debugger/i, source: "module-path", vre: /Werkzeug[-= ]+v?(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/i },
  { name: "Express", re: /node_modules[\\/]express\/|Cannot (?:GET|POST|PUT|PATCH|DELETE|HEAD) \//i, source: "stack-trace" },
  { name: "Fastify", re: /node_modules[\\/]fastify|fastify\./i, source: "module-path" },
  { name: "Koa", re: /node_modules[\\/]koa|koa-router/i, source: "module-path" },
  { name: "Symfony", re: /Symfony\\Component|symfony\/framework|Symfony Exception/i, source: "stack-trace" },
  { name: "Laravel", re: /laravel\/framework|Illuminate\\|facade\\?ignition|IgnitionException/i, source: "stack-trace" },
  { name: "Phoenix", re: /Phoenix\.|phoenixframework|PhoenixErrorView/i, source: "stack-trace" },
  { name: "Spring", re: /org\.springframework|spring-core|spring-web|springframework/i, source: "stack-trace" },
  // ── framework error pages (strongest signal — often WITH version) ──
  { name: "Django", re: /Django Version:\s*([\d.]+)|You're seeing this error because you have DEBUG|django\.core\.exceptions|DisallowedHost at/i, source: "error-page", vre: /Django Version:\s*([\d.]+)/i },
  { name: "Ruby on Rails", re: /Action Controller: Exception caught|Rails\.root:|ActionDispatch::|Rails is not currently installed/i, source: "error-page" },
  { name: "Spring Boot", re: /Whitelabel Error Page|There was an unexpected error \(type=/i, source: "error-page" },
  { name: "ASP.NET", re: /Server Error in '\/' Application|\[HttpException|System\.Web\.HttpException|ASP\.NET is configured to show verbose/i, source: "error-page", vre: /Microsoft .NET Framework Version:\s*([\d.]+)/i },
  { name: "Symfony", re: /Symfony\\Component\\Debug|Symfony Exception|Symfony.*Profiler/i, source: "error-page" },
  { name: "Next.js", re: /__NEXT_DATA__|next\/dist\/server|Application error: a server-side exception/i, source: "error-page" },
];

/** Generic module-path extractors per ecosystem — only names in the interest allowlist are kept
 *  (any npm stack trace would otherwise flood the output with every transitive dep). */
const MODULE_PATH_RULES: ReadonlyArray<{ re: RegExp; source: string; allow?: RegExp }> = [
  {
    re: /node_modules[\\/]((?:@[\w.-]+\/)?[\w.-]+)/g,
    source: "module-path",
    allow: /^(sharp|pdfkit|pdf-lib|jimp|puppeteer|playwright|multer|busboy|formidable|xml2js|js-yaml|ejs|pug|handlebars|mustache|nunjucks|fast-xml-parser|libxmljs|iconv-lite|tar|adm-zip|jszip|yauzl|unzipper|exceljs|papaparse|archiver|decompress|minizlib|cheerio|sanitize-html|isomorphic-dompurify|sequelize|mongoose|knex|typeorm|prisma|mysql2?|pg|sqlite3|better-sqlite3|mongodb|mssql|oracledb|cassandra-driver|redis|ioredis|elasticsearch|amqplib|kafkajs|jsonwebtoken|passport|bcrypt|argon2|ws|socket\.io|express|koa|fastify|hapi|@prisma|@aws-sdk|firebase-admin|node-html-parser|marked|markdown-it|showdown|xlsx|node-xlsx|csv-parse|yauzl|tar-stream|image-size|probe-image-size|exifr|heic-convert|gm|imagemagick|fluent-ffmpeg|tesseract\.js|pdf-parse|pdfjs-dist|mammoth|docxtemplater|html-pdf|puppeteer-core)$/i,
  },
  {
    re: /site-packages[\\/]([\w.-]+)/g,
    source: "module-path",
    allow: /^(PIL|pillow|lxml|yaml|PyYAML|requests|urllib3|flask|django|sqlalchemy|jinja2|celery|gunicorn|werkzeug|pymongo|psycopg2?|mysql|mysqlclient|redis|boto3|cryptography|paramiko|reportlab|weasyprint|cairosvg|pdfminer|openpyxl|xlrd|beautifulsoup4|bs4|scrapy|xmltodict|defusedxml|markupsafe|itsdangerous|oauthlib|pyjwt|pydantic|fastapi|uvicorn|starlette|aiohttp|httpx|selenium|numpy|pandas|scipy|matplotlib|imageio|opencv|cv2|wand|fitz|PyMuPDF|pypdf|PyPDF2|pdfrw|borb|xhtml2pdf|python-docx|python-pptx|openpyxl|xlwt|odf|striprtf|textract|tika|nltk|spacy|yaml_load|ruamel|msgpack|cbor|avro|thrift|protobuf|grpcio|ldap3|pywin32|shodan|impacket)$/i,
  },
  {
    re: /vendor[\\/]([\w.-]+[\\/][\w.-]+)/g,
    source: "module-path",
    allow: /^(guzzlehttp|monolog|symfony|laravel|illuminate|doctrine|phpmailer|phpoffice|intervention|imagine|dompdf|mpdf|tecnickcom|spatie|league|twig|smarty|swiftmailer|phpseclib|predis|stripe|firebase|vlucas|nesbot|ramsey|lcobucci|webmozart|sebastian|phpunit|mockery|fzaninotto|barryvdh|maatwebsite|yajra|spatie\/laravel-|knplabs|friendsofphp|composer|autoload)$/i,
  },
  { re: /([\w.-]+)-(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)\.jar\b/g, source: "stack-trace" }, // Java artifact names carry versions
  { re: /gems[\\/]([\w.-]+)-(\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/g, source: "module-path" }, // Ruby gems: gems/name-version
  { re: /\.nuget[\\/]packages[\\/]([\w.-]+)[\\/](\d+\.\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?)/gi, source: "module-path" }, // NuGet
  { re: /go[\\/]pkg[\\/]mod[\\/]([a-z0-9./_-]+)@v?([\d.]+)/g, source: "module-path" }, // Go modules
];

/** Leaked lockfile shapes — the richest source: EXACT versions for every dependency. Only parsed
 *  when the body plausibly IS a lockfile (prevents matching random JSON/XML/HTML). */
function extractLockfileLibs(body: string, add: (name: string, version: string | null, source: string, evidence: string) => void): void {
  // package-lock.json / yarn.lock: "node_modules/name": { "version": "x.y.z" }
  if (/"lockfileVersion"|"node_modules\//.test(body)) {
    const re = /"node_modules\/([^"]+)"\s*:\s*\{[^}]*?"version"\s*:\s*"([^"]+)"/gs;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) add(m[1]!, m[2]!, "lockfile", `node_modules/${m[1]} → ${m[2]}`);
    const yarnRe = /"?([^\s"']+)@[^\s"']*"?:\s*\n\s*version\s+"?([^"\s]+)"?/g;
    while ((m = yarnRe.exec(body)) !== null) add(m[1]!, m[2]!, "lockfile", `${m[1]} → ${m[2]}`);
    return;
  }
  // requirements.txt / constraints: "name==1.2.3" lines
  if (/^[a-zA-Z][\w.-]*(==|>=|~=)[\d.*]+/m.test(body) && /^([a-zA-Z][\w.-]*(==|>=|~=)[\d.*]+\s*){3,}/m.test(body)) {
    const re = /^\s*([a-zA-Z][\w.-]+)\s*(==|>=|~=)\s*([\d.*]+)/gm;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) add(m[1]!, m[3]!, "lockfile", `${m[1]}${m[2]}${m[3]}`);
    return;
  }
  // composer.lock: { "name": "vendor/pkg", "version": "v1.2.3" }
  if (/"packages"\s*:\s*\[/.test(body) && /"name"\s*:\s*"[\w.-]+\/[\w.-]+"/.test(body)) {
    const re = /"name"\s*:\s*"([\w.-]+\/[\w.-]+)"[^}]*?"version"\s*:\s*"v?([^"]+)"/gs;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) add(m[1]!, m[2]!, "lockfile", `${m[1]} → ${m[2]}`);
    return;
  }
  // Gemfile.lock: "    name (1.2.3)" entries under GEM/DEPENDENCIES
  if (/^(GEM|GIT|PATH|DEPENDENCIES)\s*$/m.test(body) && /^\s+[\w.-]+\s*\(\d+/m.test(body)) {
    const re = /^\s{2,}([\w.-]+)\s*\((\d+\.[\d.a-z-]*)\)/gm;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) add(m[1]!, m[2]!, "lockfile", `${m[1]} (${m[2]})`);
    return;
  }
  // pom.xml / manifest jars: <artifactId>x</artifactId><version>y</version> adjacent pairs
  if (/<artifactId>[\w.-]+<\/artifactId>[\s\S]{0,400}?<version>[\d.]/.test(body)) {
    const re = /<artifactId>([\w.-]+)<\/artifactId>\s*<version>([\d.]+)<\/version>/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) add(m[1]!, m[2]!, "lockfile", `${m[1]} → ${m[2]}`);
  }
}

/** Extract backend-library GUESSES from a response body (stack traces, module paths, error pages,
 *  parser-specific error strings, lockfile fragments). Deduped by name+version. Every hit is a
 *  lead for n-day hunting — name-only = "version unknown"; callers must not claim confirmation. */
export function extractBackendLibs(body: string, max = 48): TechComponent[] {
  const byKey = new Map<string, TechComponent>();
  const add = (name: string, version: string | null, source: string, evidence: string): void => {
    if (byKey.size >= max) return;
    const nm = name.trim();
    if (!nm || nm.length > 80) return;
    const key = `${nm.toLowerCase()}|${version ?? ""}`;
    if (byKey.has(key)) return;
    // a versioned hit replaces a name-only entry of the same lib
    const bare = byKey.get(`${nm.toLowerCase()}|`);
    if (version && bare) byKey.delete(`${nm.toLowerCase()}|`);
    byKey.set(key, { kind: "backend-lib", name: nm, version, source, evidence: evidence.slice(0, 200) });
  };
  const text = body.slice(0, 512 * 1024); // bodies can be huge — signatures live in the first half-MB

  for (const sig of BACKEND_LIB_SIGS) {
    const m = sig.re.exec(text);
    if (!m) continue;
    // version: dedicated pattern first, then "<name>[-@/ =]x.y.z" within 80 chars of the match
    let version: string | null = null;
    if (sig.vre) {
      const vm = sig.vre.exec(text);
      if (vm?.[1] || vm?.[2]) version = (vm[1] ?? vm[2])!;
    }
    if (!version) {
      const near = text.slice(Math.max(0, (m.index ?? 0) - 40), (m.index ?? 0) + m[0].length + 80);
      const base = sig.name.split(/[ (]/)[0]!;
      if (base.length >= 3) {
        const vm = ver(base).exec(near);
        if (vm?.[1]) version = vm[1];
      }
    }
    const snip = text.slice(Math.max(0, (m.index ?? 0) - 40), (m.index ?? 0) + m[0].length + 60).replace(/\s+/g, " ").trim();
    add(sig.name, version, sig.source, snip);
  }
  for (const rule of MODULE_PATH_RULES) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      let name = m[1]!.replace(/\\/g, "/");
      // jar names may be fully-qualified (org.yaml.snakeyaml) — keep the artifact segment
      if (/^(?:org|com|net|io|javax?|edu)\.[\w.-]+$/.test(name)) name = name.split(".").pop()!;
      if (rule.allow && !rule.allow.test(name)) continue;
      add(name, m[2] ?? null, rule.source, m[0].slice(0, 200));
    }
  }
  extractLockfileLibs(text, (name, version, source, evidence) => add(name, version, source, evidence));
  return [...byKey.values()];
}

function lowerHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

function compsOf(headers: Record<string, string>, body: string): TechComponent[] {
  return fingerprintTech([{ url: "https://local/", headers: lowerHeaders(headers), body: body ?? "" }]);
}

/** True when fingerprinting the response yields at least one component WITH a version (Apache/2.4.41, jquery-1.12.4).
 *  `Server: BigIP` / a cookie name / a product family with no version is false. */
export function hasVersionedComponent(headers: Record<string, string>, body: string): boolean {
  return compsOf(headers, body).some((c) => Boolean(c.version));
}

/** Does the writeup cite this fingerprinted version (full string, or major.minor)? */
function writeupCitesVersion(writeup: string, version: string): boolean {
  if (!version) return false;
  if (writeup.includes(version)) return true;
  const mm = /^(\d+\.\d+)/.exec(version);
  if (!mm) return false;
  const esc = mm[1]!.replace(/\./g, "\\.");
  return new RegExp(`(?<!\\d)${esc}(?!\\d)`).test(writeup);
}

/** Product-family CVE history with no version (F5 BIG-IP + CVE-2020-5902 "may apply") is not A06.
 *  A hive path (/_layouts/15/) is not a version — the writeup must cite a version that fingerprinting actually extracted. */
const VERSIONLESS_WRITEUP =
  /undisclosed version|version\s+(?:is\s+|was\s+)?(?:not\s+|un)disclosed|no version (?:is |was )?(?:leaked|disclosed)|version remains unknown|\bunknown version\b|version unknown|product family has|patch level (?:could not|cannot|unverified)/i;

export function isVersionlessComponentLead(writeup: string, headers: Record<string, string>, body: string): boolean {
  if (VERSIONLESS_WRITEUP.test(writeup)) return true;
  const versioned = compsOf(headers, body).filter((c) => c.version);
  if (versioned.length === 0) return true;
  return !versioned.some((c) => writeupCitesVersion(writeup, c.version!));
}

/** Format TechComponent[] into a human-readable table (for the LLM prompt / report). */
export function formatTechInventory(components: ReadonlyArray<TechComponent>): string[] {
  return components.map(
    (c) =>
      `- [${c.kind}] ${c.name}${c.version ? ` ${c.version}` : " (version unknown)"} — via ${c.source}` +
      (c.knownVuln ? `  ⚠ KNOWN: ${c.knownVuln}` : ""),
  );
}

/** Detected stack → hints for the attack classes to target (deterministic, pentest knowledge). Used to inject the early
 *  fingerprint result into the plan so the methodology is tech-aware. Empty array = no specific hints (keep the structure-based plan). */
export function stackAttackHints(components: ReadonlyArray<TechComponent>): string[] {
  const hay = components.map((c) => `${c.name} ${c.kind}`).join(" | ").toLowerCase();
  const hints: string[] = [];
  const add = (re: RegExp, hint: string): void => {
    if (re.test(hay)) hints.push(hint);
  };
  add(
    /jinja|flask|django|twig|freemarker|velocity|thymeleaf|handlebars|nunjucks|mako|smarty|\berb\b/,
    "TEMPLATE ENGINE present → run probe_ssti on EVERY reflected/rendered param (even when HTML-escaped); SSTI is RCE-class here, so plan ssti on any screen with reflected input.",
  );
  add(
    /\bphp\b|laravel|codeigniter|symfony/,
    "PHP → plan path-traversal/LFI (incl. php://filter source read), type-juggling on loose compares (==, auth checks), and unserialize() deserialization on any serialized/base64 input.",
  );
  add(/rails|ruby/, "Rails/Ruby → plan mass-assignment (inject extra model attrs e.g. role/admin), ERB SSTI, and Marshal deserialization.");
  add(
    /express|node\.js|next\.js|nest/,
    "Node/Express → plan prototype pollution (__proto__/constructor in JSON & query), NoSQL injection ($gt/$ne/$where operators), and SSTI if pug/handlebars render user input.",
  );
  add(/spring|\bjava\b|tomcat|jsp|servlet/, "Java/Spring → plan SpEL SSTI (${...} / #{...} / T(...)), Java deserialization, and probe exposed /actuator (env/heapdump) endpoints.");
  add(/wordpress|drupal|joomla/, "CMS → probe known-CVE endpoints (xmlrpc.php, wp-json/, admin-ajax.php) and enumerate plugin/theme versions for CVEs.");
  add(/asp\.net|\biis\b|kestrel/, "ASP.NET/IIS → plan ViewState (__VIEWSTATE) deserialization, path-traversal, and Razor SSTI.");
  // ── backend-lib guesses → n-day attack classes ──
  add(
    /imagemagick|graphicsmagick|ghostscript/i,
    "IMAGE/PS PIPELINE → try polyglot uploads (valid image + appended payload), MVG/MSL delegate abuse, and Ghostscript -dSAFER sandbox-bypass classes. Check exact version against ImageMagick/Ghostscript CVE history.",
  );
  add(
    /\bsharp\b|libvips|libjpeg|libpng|libwebp|giflib|\bjimp\b|imageio|heic-convert|turbojpeg/i,
    "IMAGE CODEC LIBRARY → classic n-day class (e.g. libwebp heap overflow). Probe upload endpoints with malformed/truncated images; if a version is found, match OSV exactly.",
  );
  add(
    /\bffmpeg\b|avcodec|fluent-ffmpeg/i,
    "FFMPEG → SSRF / local-file-read via HLS concat & subtitle demuxers (CVE-2016-1898 class) on any video/audio/preview endpoint.",
  );
  add(/exiftool|exifr/i, "ExifTool/metadata parser → DjVu-injected-code RCE class (CVE-2021-22204) and metadata-injection quirks.");
  add(
    /pdfbox|itext|poppler|mupdf|pdfkit|pdf-lib|qpdf|dompdf|tcpdf|mpdf|reportlab|weasyprint|pdfminer|pypdf|pdf-parse|pdfjs/i,
    "PDF PARSER → SSRF via embedded resources/annotations, XXE in XMP/metadata, JavaScript-action processing, and parser n-days. Check version for known CVEs.",
  );
  add(
    /apache poi|poixml|openpyxl|exceljs|phpspreadsheet|python-docx|python-pptx|libreoffice|unoconv|mammoth|docxtemplater|xlsx/i,
    "OFFICE-DOC PARSER → XXE inside OOXML parts, zip-bombs (billion-laughs class), external-entity and formula-injection leaks.",
  );
  add(/apache tika|\btika\b/i, "Apache Tika → SSRF via parser plugins; multiple n-day classes (CVE-2015-3271 and later).");
  add(
    /lxml|libxml2|xerces|saxon|xml2js|fast-xml-parser|libxmljs|xmltodict|defusedxml|python-docx|dom4j|jaxp|stax|xercesimpl/i,
    "XML STACK → XXE variants: external DTD fetch, parameter entities, XInclude, entity expansion. Probe every XML-bearing param (incl. SOAP/office-upload paths).",
  );
  add(
    /snakeyaml|pyyaml|yaml\.load|js-yaml|ruamel/i,
    "YAML PARSER → unsafe-load object construction (yaml.load / !!python/object) — deserialization RCE class on config/upload endpoints.",
  );
  add(
    /jackson|gson|fastjson|xstream|objectinputstream|readobject|serializationutils|commons-collections/i,
    "JAVA SERIALIZATION STACK → polymorphic-type/unsafe deserialization (fastjson autotype, Jackson polymorphic, native readObject + gadget chains).",
  );
  add(/unserialize\(\)|php_incomplete|phar:|pickle|cpickle|marshal\.load|__reduce__|ysoserial/i, "NATIVE DESERIALIZER → object-injection (phar:/pickle/PHP-serialize gadget chains).");
  add(/log4j/i, "LOG4J → JNDI-lookup class (Log4Shell): probe ${jndi:ldap://} strings in every reflected/logged field (UA, referer, JSON values, form fields).");
  add(/zxing|tesseract/i, "Barcode/OCR parser → image-parser n-days and format quirks on any scan/upload surface.");
  return hints;
}
