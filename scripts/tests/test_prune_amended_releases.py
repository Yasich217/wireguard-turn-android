import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

path = pathlib.Path(__file__).resolve().parents[1] / "prune-amended-releases.py"
spec = importlib.util.spec_from_file_location("release_cleanup", path)
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


class AmendedReleaseCleanupTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = pathlib.Path(self.directory.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.tree = self.git("mktree", data="")
        self.base = self.commit("base")
        self.old = self.commit("original release", self.base)
        self.head = self.commit("amended release", self.base)
        self.old_tag = "v2.2.20-685-11111111"
        self.current_tag = "v2.2.20-686-22222222"
        self.git("tag", self.old_tag, self.old)
        self.git("tag", self.current_tag, self.head)

    def git(self, *args, data=None):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], input=data, text=True,
            capture_output=True, check=True,
        ).stdout.strip()

    def commit(self, message, *parents):
        args = ["commit-tree", self.tree, "-m", message]
        for parent in parents:
            args += ["-p", parent]
        return self.git(*args)

    def select(self, releases, head=None):
        return cleanup.superseded_releases(
            releases, head or self.head, self.current_tag, self.repo
        )

    def test_selects_the_replaced_sibling_only(self):
        tag = "v2.2.20-684-33333333"
        self.git("tag", tag, self.base)
        old = {"id": 1, "tag_name": self.old_tag}
        releases = [old, {"id": 2, "tag_name": self.current_tag}, {"id": 3, "tag_name": tag}]
        self.assertEqual(self.select(releases), [old])

    def test_preserves_other_branches_and_current_commit_aliases(self):
        other = self.commit("other root")
        other_head = self.commit("other branch release", other)
        other_tag = "v2.2.20-684-44444444"
        alias = "v2.2.20-686-55555555"
        self.git("tag", other_tag, other_head)
        self.git("tag", alias, self.head)
        self.assertEqual(self.select([{"tag_name": other_tag}, {"tag_name": alias}]), [])

    def test_preserves_drafts_prereleases_unknown_and_missing_tags(self):
        for release in [
            {"tag_name": self.old_tag, "draft": True},
            {"tag_name": self.old_tag, "prerelease": True},
            {"tag_name": "manual-release"},
            {"tag_name": "v2.2.20-685-66666666"},
        ]:
            with self.subTest(release=release):
                self.assertEqual(self.select([release]), [])

    def test_preserves_releases_when_current_commit_is_a_merge(self):
        merge = self.commit("merge release", self.base, self.old)
        self.assertEqual(self.select([{"tag_name": self.old_tag}], merge), [])


if __name__ == "__main__":
    unittest.main()
