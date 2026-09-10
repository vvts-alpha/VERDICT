const { test } = require("node:test");
const assert = require("node:assert/strict");
const { ensureReleaseTag, validatePublishedRelease, publishVerifiedRelease } = require("./release-publish.cjs");

function fixture() {
  const expected = { id: 42, tag: "v2026.9.12", sourceCommit: "a".repeat(40), repository: "example/verdict" };
  const reference = { ref: `refs/tags/${expected.tag}`, object: { type: "commit", sha: expected.sourceCommit } };
  const release = { id: expected.id, tag_name: expected.tag, target_commitish: expected.sourceCommit, draft: false, prerelease: false,
    html_url: `https://github.com/${expected.repository}/releases/tag/${expected.tag}`,
    assets: [{ name: "VERDICT.Setup.2026.9.12.exe", browser_download_url: `https://github.com/${expected.repository}/releases/download/${expected.tag}/VERDICT.Setup.2026.9.12.exe` }] };
  return { expected, reference, release, repo: `repos/${expected.repository}` };
}

test("creates the exact release tag without confusing another tag sharing its prefix", () => {
  const { expected, reference, repo } = fixture();
  const references = [{ ...reference, ref: `${reference.ref}-old` }];
  ensureReleaseTag((endpoint, method, data) => {
    if (endpoint.includes("matching-refs")) return references;
    assert.equal(method, "POST");
    const created = { ref: data.ref, object: { type: "commit", sha: data.sha } };
    references.push(created);
    return created;
  }, repo, expected.tag, expected.sourceCommit);
  assert.deepEqual(references[1], reference);
});

test("an existing tag at another commit is rejected without moving it", () => {
  const { expected, reference, repo } = fixture();
  reference.object.sha = "b".repeat(40);
  let writes = 0;
  assert.throws(() => ensureReleaseTag((_endpoint, method) => {
    if (method) writes++;
    return [reference];
  }, repo, expected.tag, expected.sourceCommit), /untested commit/);
  assert.equal(writes, 0);
});

test("publishing replaces a draft's temporary tag and verifies the real latest download URL", () => {
  const { expected, reference, release, repo } = fixture();
  let state = { ...release, tag_name: "untagged-fixture", draft: true };
  const published = publishVerifiedRelease((endpoint, method, data) => {
    if (endpoint.includes("/git/ref/")) return reference;
    if (method === "PATCH") {
      state = { ...state, ...data };
      state.html_url = `https://github.com/${expected.repository}/releases/tag/${state.tag_name}`;
      state.assets = release.assets.map(asset => ({ ...asset, browser_download_url: `https://github.com/${expected.repository}/releases/download/${state.tag_name}/${asset.name}` }));
    }
    return state;
  }, repo, expected);
  assert.equal(published.tag_name, expected.tag);
  assert.equal(published.draft, false);
  assert.equal(published.assets[0].browser_download_url, release.assets[0].browser_download_url);
});

for (const [name, mutate] of [
  ["temporary tag", release => { release.tag_name = "untagged-fixture"; }],
  ["wrong commit", release => { release.target_commitish = "main"; }],
  ["different latest release", release => { release.id++; }],
  ["unpublished draft", release => { release.draft = true; }],
  ["prerelease", release => { release.prerelease = true; }],
  ["stale release URL", release => { release.html_url += "-old"; }],
  ["stale installer URL", release => { release.assets[0].browser_download_url = "https://github.com/example/verdict/releases/download/untagged-fixture/VERDICT.Setup.2026.9.12.exe"; }],
]) test(`publication verification rejects ${name}`, () => {
  const { expected, reference, release } = fixture();
  mutate(release);
  assert.throws(() => validatePublishedRelease(release, reference, expected));
});

test("publication fails if the remote ignores the requested tag", () => {
  const { expected, reference, release, repo } = fixture();
  assert.throws(() => publishVerifiedRelease(endpoint => endpoint.includes("/git/ref/") ? reference : { ...release, tag_name: "untagged-fixture" }, repo, expected), /unexpected tag/);
});

test("publication detects a tag moved after the publish request", () => {
  const { expected, reference, release, repo } = fixture();
  let reads = 0;
  assert.throws(() => publishVerifiedRelease(endpoint => {
    if (!endpoint.includes("/git/ref/")) return release;
    return ++reads === 1 ? reference : { ...reference, object: { type: "commit", sha: "b".repeat(40) } };
  }, repo, expected), /untested commit/);
});
