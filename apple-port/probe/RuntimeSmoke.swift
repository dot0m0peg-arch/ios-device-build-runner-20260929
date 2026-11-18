import Darwin
import Foundation
import WebKit

@MainActor
final class RuntimeSmoke: NSObject, WKScriptMessageHandler {
    static let captureErrors = """
      window.applePortErrors = [];
      window.applePortDrawCount = 0;
      addEventListener('error', event => {
        if (window.applePortErrors.length < 10)
          window.applePortErrors.push(String(event.message || event.target?.src || 'load error'));
      }, true);
      addEventListener('unhandledrejection', event => {
        if (window.applePortErrors.length < 10)
          window.applePortErrors.push(String(event.reason));
      });
      addEventListener('securitypolicyviolation', event => {
        if (window.applePortErrors.length < 10)
          window.applePortErrors.push(event.violatedDirective + ' ' + event.blockedURI);
      });
      const seen = new WeakSet();
      const output = HTMLCanvasElement.prototype.getContext;
      HTMLCanvasElement.prototype.getContext = function() {
        const context = Reflect.apply(output, this, arguments);
        if (context && typeof context.isContextLost === 'function' && !seen.has(context)) {
          seen.add(context);
          for (const key of ['drawArrays','drawElements','drawArraysInstanced','drawElementsInstanced']) {
            const draw = context[key];
            if (typeof draw !== 'function') continue;
            context[key] = function() {
              if (this.canvas.clientWidth > 0 && this.canvas.clientHeight > 0 && !this.isContextLost())
                window.applePortDrawCount++;
              return Reflect.apply(draw, this, arguments);
            };
          }
        }
        return context;
      };
      """

    static let inspect = """
      (() => {
        let storage = false;
        try {
          const name = '__apple_ci_storage__';
          localStorage.setItem(name, 'ok');
          storage = localStorage.getItem(name) === 'ok';
          localStorage.removeItem(name);
        } catch {}
        return JSON.stringify({title: document.title, ready: document.readyState,
          drawn: window.applePortDrawCount > 8, draws: window.applePortDrawCount,
          storage, errors: window.applePortErrors || []});
      })()
      """


    static let shared = RuntimeSmoke()
    private var last = "No runtime report arrived."

    static var script: String {
        captureErrors + """
          setInterval(() => {
            try {
              window.webkit.messageHandlers.appleRuntimeSmoke.postMessage(
          """ + inspect + """
              );
            } catch (error) {
              window.webkit.messageHandlers.appleRuntimeSmoke.postMessage(
                JSON.stringify({exception: String(error), title: document.title}));
            }
          }, 400);
          """
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame, let encoded = message.body as? String else { return }
        last = encoded
        guard let report = try? JSONSerialization.jsonObject(with: Data(encoded.utf8)) as? [String: Any],
              report["drawn"] as? Bool == true, report["storage"] as? Bool == true
        else { return }
        print("APPLE_RUNTIME_SMOKE_PASS " + encoded)
        exit(EXIT_SUCCESS)
    }

    func run(_ view: WKWebView, problem: @escaping () -> String?) async {
        do { try await Task.sleep(for: .seconds(70)) }
        catch { return }
        print("APPLE_RUNTIME_SMOKE_FAIL " + last)
        print("APPLE_RUNTIME_NATIVE title=\(view.title ?? "nil") url=\(view.url?.absoluteString ?? "nil") loading=\(view.isLoading) problem=\(problem() ?? "nil")")
        exit(EXIT_FAILURE)
    }
}
