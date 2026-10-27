package domain

import "testing"

func TestComponent(t *testing.T) {
	cases := []struct {
		f    Finding
		kind ComponentKind
		key  string
	}{
		{Finding{Type: "ubuntu", Pkg: "linux-libc-dev", InstalledVersion: "6.8.0-124.124", FixedVersion: "6.8.0-147.147"}, ComponentOS, "6.8.0-124.124"},
		// The fixed version differs per CVE; the kernel stays one component.
		{Finding{Type: "ubuntu", Pkg: "linux-libc-dev", InstalledVersion: "6.8.0-124.124", FixedVersion: "6.8.0-134.134"}, ComponentOS, "6.8.0-124.124"},
		{Finding{Type: "rocky", Pkg: "openssl-libs", InstalledVersion: "1:3.0.7-27.el9", FixedVersion: "1:3.0.7-28.el9"}, ComponentOS, "1:3.0.7-27.el9"},
		{Finding{Type: "gobinary", Target: "usr/bin/dockerd", Pkg: "stdlib"}, ComponentBinary, "/usr/bin/dockerd"},
		{Finding{Type: "composer-vendor", Target: "PHP", PkgPath: "var/www/shop/vendor/composer/installed.json"}, ComponentApp, "/var/www/shop"},
		{Finding{Type: "node-pkg", Target: "Node.js", PkgPath: "home/u/front/node_modules/@a/b/node_modules/c/package.json"}, ComponentApp, "/home/u/front"},
		{Finding{Type: "python-pkg", Target: "Python", PkgPath: "usr/lib/python3/dist-packages/urllib3-2.0.7.dist-info/METADATA"}, ComponentApp, "/usr/lib/python3"},
		{Finding{Type: "python-pkg", Target: "Python", PkgPath: "srv/api/.venv/lib/python3.12/site-packages/x-1.dist-info/METADATA"}, ComponentApp, "/srv/api"},
		{Finding{Type: "python-pkg", Target: "Python", PkgPath: "home/u/.cache/uv/archive-v0/abc/aiohttp-3.14.3.dist-info/METADATA"}, ComponentApp, "/home/u/.cache"},
		{Finding{Type: "jar", Target: "Java", PkgPath: "opt/api/app.jar"}, ComponentApp, "/opt/api/app.jar"},
		{Finding{Type: "jar", Target: "Java", PkgPath: "home/u/.m2/repository/at/yawk/lz4/lz4-java-1.10.1.jar"}, ComponentApp, "/home/u/.m2"},
		{Finding{Type: "composer", Target: "var/www/blog/composer.lock"}, ComponentApp, "/var/www/blog"},
	}
	for _, c := range cases {
		kind, key := c.f.Component()
		if kind != c.kind || key != c.key {
			t.Errorf("%+v: got %s %q, want %s %q", c.f, kind, key, c.kind, c.key)
		}
	}
}

func TestKeyStableWithoutPkgPath(t *testing.T) {
	a := Finding{CVE: "CVE-1", Pkg: "p", InstalledVersion: "1", Target: "t"}
	b := a
	b.PkgPath = "x/y"
	if string(a.Key()) == string(b.Key()) {
		t.Fatal("PkgPath must change the key")
	}
}
