from pathlib import Path
import plistlib
import shutil
import sys

root = Path(sys.argv[1])
app = sys.argv[2]
ent = root / f"Apps/{app}/Mac.entitlements"
values = plistlib.loads(ent.read_bytes())
values["com.apple.security.network.client"] = True
ent.write_bytes(plistlib.dumps(values))
src = root / "Sources"
shutil.copyfile("apple-port/probe/RuntimeSmoke.swift", src / "RuntimeSmoke.swift")
view = src / "AppleGameApp.swift"
text = view.read_text()
needle = ".task { game.start() }"
assert text.count(needle) == 1
view.write_text(text.replace(needle, ".task { game.start(); await RuntimeSmoke.shared.run(game.webView, problem: { game.problem }) }"))
session = src / "GameSession.swift"
text = session.read_text()
needle = "configuration.websiteDataStore = .default()"
assert text.count(needle) == 1
session.write_text(text.replace(needle, needle + """
        configuration.userContentController.add(RuntimeSmoke.shared, name: "appleRuntimeSmoke")
        configuration.userContentController.addUserScript(WKUserScript(
            source: RuntimeSmoke.script, injectionTime: .atDocumentStart, forMainFrameOnly: true))
"""))
