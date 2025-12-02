//! Browser API stubs for JavaScript execution.

use rquickjs::Context;

/// Initializes browser API stubs in the JavaScript context.
///
/// Creates window, document, navigator, localStorage, and console objects
/// to prevent errors when scripts try to use browser APIs.
pub(crate) fn initialize_browser_stubs(context: &Context, js_property: &str) {
    let init_code = r#"
        // Create window object in global scope
        globalThis.window = {};
        globalThis.global = globalThis.window;
        globalThis.self = globalThis.window;
        
        // Stub document object to prevent errors when scripts try to use it
        globalThis.document = {
            createElement: function() { return {}; },
            body: {},
            location: {},
            getElementById: function() { return null; },
            getElementsByTagName: function() { return []; },
            getElementsByClassName: function() { return []; },
            querySelector: function() { return null; },
            querySelectorAll: function() { return []; }
        };
        
        // Stub navigator
        globalThis.navigator = {
            userAgent: 'Mozilla/5.0',
            platform: 'Linux x86_64'
        };
        
        // Stub localStorage (empty object, no-op methods)
        globalThis.localStorage = {
            getItem: function() { return null; },
            setItem: function() {},
            removeItem: function() {},
            clear: function() {}
        };
        
        // Stub console to prevent errors
        globalThis.console = {
            log: function() {},
            error: function() {},
            warn: function() {},
            info: function() {}
        };
    "#;

    context.with(|ctx| {
        if let Err(e) = ctx.eval::<rquickjs::Value, _>(init_code) {
            log::debug!(
                "Failed to initialize browser stubs for property '{}': {e}",
                js_property
            );
        }
    });
}

