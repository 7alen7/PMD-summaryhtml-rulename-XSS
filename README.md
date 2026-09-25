# Stored XSS in the summaryhtml report via unescaped rule name

## What this shows

PMD's `summaryhtml` report format prints a table of rule names and violation counts.
The renderer writes each rule name straight into the HTML with no escaping. A rule
whose name contains markup is emitted verbatim, so a report opened in a browser
executes the script.

This is the same weakness class as CVE-2026-28338 (stored XSS in PMD's HTML
renderers), in a renderer and a field the fix for that advisory did not cover. The
main HTML renderer escapes the rule name; the summary renderer does not.

## Attacker model

The rule name comes from the ruleset, not from the analyzed source. This reproduces
when the ruleset used for analysis is attacker-influenced, for example a ruleset
checked out from an untrusted pull request in CI, or any workflow that runs a
ruleset from an untrusted source. Where the ruleset is fixed and trusted, this
field is not attacker-controlled.

## Affected software

- Component: `net.sourceforge.pmd:pmd-core` (`SummaryHTMLRenderer`)
- Versions: through 7.27.0 and current `main`. Not covered by the CVE-2026-28338 fix
  (PR #6475, released in 7.22.0). No fix released.
- Root cause: `SummaryHTMLRenderer.renderSummary` calls `writer.write(ruleName)`
  with no `StringEscapeUtils.escapeHtml4`, where `ruleName` is `rule.getName()` read
  verbatim from the ruleset XML.

## Prerequisites

- Linux or macOS, `bash`, `curl`, `unzip`
- Java 8+ on the PATH
- Network access on first run to download PMD, or set `PMD_BIN`

## Run it

```
./run.sh
```

Or with an existing PMD:

```
PMD_BIN=/path/to/pmd-bin-7.27.0/bin/pmd ./run.sh
```

## Expected vs observed

Expected: the rule name is HTML-escaped before being written into the report, the
same way the main HTML renderer escapes it.

Observed: `work/report.html` contains the summary cell
`<td><script>alert(document.domain)</script></td>` with the rule name unescaped.
Opening `work/report.html` in a browser runs the script. The script prints
`[RESULT] VULNERABLE` when it finds the unescaped `<script>` in the report.

## Cleanup

Everything is under `work/` (recreated each run) and, if downloaded,
`pmd-bin-7.27.0/` plus `pmd.zip`.

## Fix

Escape the rule name in `SummaryHTMLRenderer.renderSummary` with
`StringEscapeUtils.escapeHtml4`, matching the main HTML renderer.
