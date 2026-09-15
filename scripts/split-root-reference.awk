# Splits gomarkdoc's single root-package page into topic pages.
#
# Usage: awk -v outdir=DIR -v site=https://docs.dnsid.ai -f split-root-reference.awk MAPFILE RAW.md
#
# MAPFILE lines are "Symbol page-slug", covering every top-level section of the
# raw gomarkdoc output ("Constants" and "Variables" are section names). A
# section whose symbol is missing from the map fails the run, so newly exported
# identifiers must be assigned a page before docs regenerate (fail closed).
#
# The package preamble (import line + package doc) goes to the "dnsid" page.
# The "## Index" section is dropped: each topic page is small enough to scan,
# and the index's intra-page links would all need rewriting anyway.
#
# gomarkdoc links sections as (<#Anchor>) against <a name="Anchor"> anchors,
# including nested ones (methods, constructors, constants). Every anchor's
# destination page is recorded while routing sections, then links whose target
# lives on another page are rewritten to absolute site URLs.

FNR == NR {
    if (NF >= 2) pagefor[$1] = $2
    next
}

# --- routing ---------------------------------------------------------------

/^## Index$/ { skipping = 1; next }

/^## / {
    skipping = 0
    if ($0 ~ /^## (Constants|Variables)$/) {
        sym = $2
    } else if (match($0, /^## (type|func) \[[A-Za-z0-9_]+\]/)) {
        sym = $0
        sub(/^## (type|func) \[/, "", sym)
        sub(/\].*$/, "", sym)
    } else {
        sym = "UNPARSED: " $0
    }
    cur = pagefor[sym]
    if (cur == "") { missing[sym] = 1; cur = "dnsid" }
}

skipping { next }

{
    page = (cur == "") ? "dnsid" : cur
    line = $0
    rest = line
    while (match(rest, /<a name="[^"]+"/)) {
        anchor = substr(rest, RSTART + 9, RLENGTH - 10)
        anchorpage[anchor] = page
        rest = substr(rest, RSTART + RLENGTH)
    }
    n[page]++
    buf[page, n[page]] = line
    if (!(page in seen)) { seen[page]; order[++npages] = page }
}

# --- emit ------------------------------------------------------------------

function rewrite(line, page,    out, rest, pos, cpos, sym, tgt) {
    out = ""
    rest = line
    while ((pos = index(rest, "(<#")) > 0) {
        out = out substr(rest, 1, pos - 1)
        rest = substr(rest, pos + 3)
        cpos = index(rest, ">)")
        if (cpos == 0) { out = out "(<#"; break }
        sym = substr(rest, 1, cpos - 1)
        rest = substr(rest, cpos + 2)
        tgt = anchorpage[sym]
        if (tgt != "" && tgt != page)
            out = out "(<" site "/reference/go/" tgt "#" sym ">)"
        else
            out = out "(<#" sym ">)"
    }
    return out rest
}

END {
    bad = 0
    for (sym in missing) {
        printf "split-root-reference.awk: unmapped section %s — add it to the root-page map in gen-docs.sh\n", sym > "/dev/stderr"
        bad = 1
    }
    if (bad) exit 1
    for (i = 1; i <= npages; i++) {
        page = order[i]
        file = outdir "/body-" page ".md"
        for (j = 1; j <= n[page]; j++)
            print rewrite(buf[page, j], page) > file
        close(file)
    }
}
