# Email signature compatibility and QA checklist

This checklist was reconstructed from the available project brief. Record observed results for each client and version. A browser preview or passing API test does not establish mail-client compatibility.

## Fixtures and application checks

- Use fictitious contact details. Include accented and escaped text, a long company name, mailto and tel links, a narrow image with meaningful alt text, divider, spacer, and a hidden block.
- Import a table with inline styles, plus scripts, event attributes, CSS URLs, relative URLs, and a remote image. Check that the preview makes no outbound requests and the saved original can be reviewed. Rebuild it before export.
- Reorder by keyboard and drag, duplicate and hide blocks, undo and redo, switch records with unsaved edits, and save a template copy. Compare draft HTML with the current editor.
- Publish, then change the profile and save another draft. Compare the published HTML byte for byte. Publish again and verify the snapshot changes.
- On a restored scratch database, start the app twice and verify legacy records, profiles, assets, and existing snapshots. Test the production backup and rollback procedure on copies.
- Check network isolation from the proxy, a disallowed LAN source, and outside the private network. On the public image host verify a valid GET and HEAD, a missing asset, a non-media path, a traversal-like path, and a non-GET/HEAD method.

## Mail-client matrix

For each target, install or paste the exported signature using the client’s normal signature editor, send a message and a reply/forward, and inspect the received message and source. Check narrow windows, light/dark appearance, images allowed and blocked, alt text, font fallback, spacing, clipping, image dimensions, links, and markup changes after editing or forwarding.

| Target | Variants to record | Status |
| --- | --- | --- |
| Gmail | Web and relevant mobile apps | Pending |
| Outlook | Classic Windows, new Outlook, web, and Mac where used | Pending |
| Apple Mail | macOS and iOS/iPadOS where used | Pending |
| iCloud Mail | Web | Pending |
| Proton Mail | Web and relevant mobile apps | Pending |
| Thunderbird | Desktop | Pending |

For each result record the date, client/version, OS, installation method, fixture or snapshot ID, expected and observed behavior, and a redacted screenshot or message source when useful. Mark each case **Pass**, **Pass with limitations**, **Fail**, or **Not run**. Rerun affected cases after changing the renderer, asset host, or installation steps.
