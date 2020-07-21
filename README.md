# About
Script to crawl crbugs (Chromium Issues), which parses pages from `https://chromereleases.googleblog.com/` and `https://crbug.com/`, then will save all to local database as python Pickle format and generate an Markdown file for human reading.

# Install
```
pip install beautifulsoup4
git clone https://github.com/lmy375/crbug
```

# Usage

```
$ python3 crbug.py
[+] 106 posts, 819 cves, 1364 issues loaded.
[+] Updated. Found 0 new post(s).
[+] 211 issues are still restricted.
[+] Open: Issue 1065298: UAF in base::SupportsUserData::SetUserData (cdsrc2...@gmail.com)
[+] Open: Issue 1065186: UAF in libglesv2!gl::Texture::onUnbindAsSamplerTexture (pa...@blackowlsec.com)
[+] Open: Issue 1064519: Security: DevTools doesn't fully validate channel messages it receives (derce...@gmail.com)
[+] Open: Issue 1061933: aec3_fuzzer: Container-overflow in webrtc::FilterAnalyzer::AnalyzeRegion (ClusterFuzz)
[+] Open: Issue 1059577: Security: Possible to escape sandbox via devtools_page (derce...@gmail.com)
[+] Open: Issue 1055933: heap-use-after-free : ProfileIOData::FromResourceContext (crash-fe...@system.gserviceaccount.com)
[+] Open: Issue 1053939: V8 correctness failure in configs: x64,ignition:x64,ignition_turbo_opt (ClusterFuzz)
[+] Open: Issue 1040755: Security:  Another "universal" XSS via copy&paste (mic...@bentkowski.info)
[+] Stop at Issue 901654 (Permission denied.)
[+] 8 issues opened.
[+] Save db to ./db.pickle.
[+] Save markdown to ./crbug.md.
```
