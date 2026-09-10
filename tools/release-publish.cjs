const assert = require("node:assert/strict");

function validateTag(reference, tag, sourceCommit) {
  assert.equal(reference.ref, `refs/tags/${tag}`, "Release tag name differs");
  assert.equal(reference.object.type, "commit", "Release tag must directly identify the tested commit");
  assert.equal(reference.object.sha, sourceCommit, "Release tag points to an untested commit");
}

function ensureReleaseTag(api, repo, tag, sourceCommit) {
  const matches = api(`${repo}/git/matching-refs/tags/${tag}`);
  const existing = matches.find(reference => reference.ref === `refs/tags/${tag}`);
  const reference = existing ?? api(`${repo}/git/refs`, "POST", { ref: `refs/tags/${tag}`, sha: sourceCommit });
  validateTag(reference, tag, sourceCommit);
}

function validatePublishedRelease(release, reference, expected) {
  validateTag(reference, expected.tag, expected.sourceCommit);
  assert.equal(release.id, expected.id, "Release did not become latest");
  assert.equal(release.tag_name, expected.tag, "Published release has an unexpected tag");
  assert.equal(release.target_commitish, expected.sourceCommit, "Published release source differs");
  assert.equal(release.draft, false, "Release is still a draft");
  assert.equal(release.prerelease, false, "Stable release was marked as a prerelease");
  const base = `https://github.com/${expected.repository}/releases`;
  assert.equal(release.html_url, `${base}/tag/${expected.tag}`, "Published release URL differs");
  for (const asset of release.assets) {
    assert.equal(asset.browser_download_url, `${base}/download/${expected.tag}/${encodeURIComponent(asset.name)}`, "Published download URL differs");
  }
}

function publishVerifiedRelease(api, repo, expected) {
  const reference = api(`${repo}/git/ref/tags/${expected.tag}`);
  validateTag(reference, expected.tag, expected.sourceCommit);
  // Repeat the identity on publication: a draft may otherwise retain GitHub's temporary untagged identity.
  const published = api(`${repo}/releases/${expected.id}`, "PATCH", {
    tag_name: expected.tag, target_commitish: expected.sourceCommit, draft: false, prerelease: false, make_latest: "true",
  });
  validatePublishedRelease(published, reference, expected);
  const latest = api(`${repo}/releases/latest`);
  validatePublishedRelease(latest, api(`${repo}/git/ref/tags/${expected.tag}`), expected);
  return latest;
}

module.exports = { ensureReleaseTag, validatePublishedRelease, publishVerifiedRelease };
