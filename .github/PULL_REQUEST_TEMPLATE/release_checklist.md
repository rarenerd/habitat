Here are all the steps for the release process. Create a new PR at the beginning and check them off as you go.
In the course of the release, you'll create and merge several other PRs. They should all be
separate from this one. This PR exists to track progress on the release and ensure all the steps
are carried out.
When you're done, have someone review and merge the PR along with any fixes to the release process automation
or documentation.
The only file changes this PR should contain are changes for the *next* release. If there are none,
this PR may have no file changes at all. Merge it anyway to make it clear that the release process
is done and that no updates were made for next time.

- [ ] [Check if release will cause downtime and if so appropriately announce it](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#if-your-release-is-going-to-cause-downtime)
- [ ] Release new launcher or confirm there have been no launcher changes since the [last stable version](https://bldr.habitat.sh/#/pkgs/core/hab-launcher/latest)
- [ ] Declare merge freeze and update slack status
- [ ] [Create PR](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#prepare-master-branch-for-release) to update [`VERSION`](https://github.com/habitat-sh/habitat/blob/master/VERSION)
- [ ] Fix up any miscategorization in [CHANGELOG.md](https://github.com/habitat-sh/habitat/blob/master/CHANGELOG.md) and add to PR updating [`VERSION`](https://github.com/habitat-sh/habitat/blob/master/VERSION)
- [ ] [Merge PR](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#prepare-master-branch-for-release) to update [`VERSION`](https://github.com/habitat-sh/habitat/blob/master/VERSION)
- [ ] [Create blog announcement PR](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#submit-a-release-notes-blog-post-pr) and solicit team member input
- [ ] AppVeyor run success
- [ ] [Buildkite](https://buildkite.com/chef/habitat-sh-habitat-master-release) run success
- [ ] [Validate](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#validate-the-release) [darwin binaries](https://bintray.com/habitat/stable/hab-x86_64-darwin)
- [ ] [Validate](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#validate-the-release) [linux binaries](https://bintray.com/habitat/stable/hab-x86_64-linux)
- [ ] [Validate](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#validate-the-release) [windows binaries](https://bintray.com/habitat/stable/hab-x86_64-windows)
- [ ] Declare merge thaw and update slack status
- [ ] Merge blog announcement PR
- [ ] [Update builder bootstrap bundle](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#update-builder-bootstrap-bundle)
- [ ] [Update homebrew tap](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#update-homebrew-tap)
- [ ] [Update chocolately package](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#rerun-chocolatey-validation-tests)
- [ ] [Publish release](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#publish-release) on GitHub
- [ ] [Update `hab-backline` to release version in acceptance environment](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#update-the-acceptance-environment-with-the-new-hab-backline)
- [ ] [Update docs](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#update-the-docs)
- [ ] [Bump version](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#bump-version) to new `-dev` version
- [ ] [Update `hab-backline` to new `-dev` version in acceptance environment](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#update-the-acceptance-environment-with-the-new-hab-backline-1)
- [ ] [Promote builder worker](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#promote-the-builder-worker) and confrm build uses new version
- [ ] Post announcement in [Chef discourse](https://discourse.chef.io/c/habitat)
- [ ] Post announcement in [Habitat forums](https://forums.habitat.sh/c/announcements)
- [ ] Tweet announcement from `@habitatsh`
- [ ] [Update `Cargo.lock`](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#update-cargolock) for [`habitat`](https://github.com/habitat-sh/habitat)
- [ ] [Update `Cargo.lock`](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#update-cargolock) for [`core`](https://github.com/habitat-sh/core)
- [ ] [Update `Cargo.lock`](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md#update-cargolock) for [`builder`](https://github.com/habitat-sh/builder)
- [ ] Add fixes to the release automation and/or [`RELEASE.md`](https://github.com/habitat-sh/habitat/blob/master/RELEASE.md)
- [ ] Merge this PR