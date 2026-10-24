---
name: Periscope
description: A read-only ledger of BunkerWeb instances: ruled lines, aligned columns, status as text, every alert inside its own instance.
colors:
  graphite-ground: "#0e0e0f"
  graphite-surface: "#17171a"
  graphite-raised: "#202024"
  graphite-seam: "#2e2e33"
  ink: "#ececec"
  ink-muted: "#a0a0a0"
  copper: "#ea9358"
  copper-ink: "#140a02"
  ok-green: "#4fc58f"
  warn-amber: "#f0c040"
  crit-coral: "#ff7566"
  off-slate: "#a3a3a3"
  paper-ground: "#f1f1ef"
  paper-surface: "#ffffff"
  paper-raised: "#f6f6f4"
  paper-seam: "#d9d9d4"
  paper-ink: "#111111"
  paper-ink-muted: "#575754"
  paper-copper: "#a84d14"
  paper-ok: "#166a3d"
  paper-warn: "#7d5a00"
  paper-crit: "#b3261e"
  paper-off: "#5d5d5a"
typography:
  page-title:
    fontFamily: "Office Code Pro, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "1.5rem"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  section-title:
    fontFamily: "Office Code Pro, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "1.0625rem"
    fontWeight: 500
    letterSpacing: "-0.02em"
  kpi-figure:
    fontFamily: "Office Code Pro, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "1.5rem"
    fontWeight: 500
    lineHeight: 1.25
    letterSpacing: "-0.02em"
    fontFeature: "tabular-nums"
  kpi-figure-first:
    fontFamily: "Office Code Pro, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "2rem"
    fontWeight: 500
    lineHeight: 1.25
    letterSpacing: "-0.02em"
  instance-name:
    fontFamily: "Office Code Pro, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "1rem"
    fontWeight: 500
    letterSpacing: "-0.02em"
  body:
    fontFamily: "Switzer, Segoe UI, system-ui, -apple-system, Arial, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Office Code Pro, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "0.8125rem"
    fontWeight: 500
    lineHeight: 1.4
  cell:
    fontFamily: "Switzer, Segoe UI, system-ui, -apple-system, Arial, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  tag:
    fontFamily: "Office Code Pro, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "0.75rem"
    fontWeight: 500
  data:
    fontFamily: "Office Code Pro, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "0.875em"
    fontWeight: 400
rounded:
  container: "4px"
  field: "3px"
  focus: "2px"
spacing:
  xs: "0.25rem"
  sm: "0.5rem"
  md: "0.75rem"
  lg: "1.25rem"
  xl: "2rem"
components:
  menu-item:
    textColor: "{colors.ink-muted}"
    padding: "0.4rem 0.7rem"
    height: "2.75rem"
  menu-item-current:
    textColor: "{colors.ink}"
  status:
    textColor: "{colors.crit-coral}"
    typography: "{typography.label}"
  ledger-row:
    textColor: "{colors.ink}"
    padding: "0.85rem 0.9rem"
    height: "3.25rem"
  button-primary:
    backgroundColor: "{colors.copper}"
    textColor: "{colors.copper-ink}"
    rounded: "{rounded.field}"
    height: "2.5rem"
  input:
    backgroundColor: "{colors.graphite-surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.field}"
    height: "2.5rem"
---

# Design System: Periscope

## Overview

**Creative North Star: "The Ledger"**

Periscope reads like a ledger, not a dashboard of floating cards: one strip of figures, then one table of instances whose columns run straight from the first row to the last. A reader scans down a column to compare and across a row to understand an instance. Every alert is a tinted line inside the instance it belongs to; there is no separate alert feed. Light is the default theme (neutral paper), dark is a reader choice with the same structure.

The system avoids the look of generated dashboards: floating rounded cards, pill chips, shadows, hover lift, big hero numbers. It keeps what makes a page fast to read: a left index with one drawn icon per page, a small periscope mark, tinted state chips with a glyph and a word, and a faint wash on problem rows so the instance to check is visible at a glance.

**Key Characteristics:**
- Neutral paper ground, white single-level surfaces, 1px seams, 3-4px corners. No shadows, no gradients.
- Status as glyph + word + state colour, softly tinted. Copper only for action, place and the brand mark.
- Switzer for reading, Office Code Pro for data (names, figures, hosts, versions, times).
- Problem instances sort first and carry their alerts on the row; every row starts collapsed.
- Light and dark themes share one token set (`data-bs-theme`); the page starts light.

## Colors

Ink and paper: neutral greys with no tint, one copper accent, and four status hues. Hue means state; copper means "act here" or "you are here". There is no decorative colour.

### Primary
- **Copper** (#a84d14 light / #ea9358 dark): current menu icon, the brand ring, links, the primary button fill, field focus border, the 2px focus outline (2px offset), selection tint. It is not a status colour and stays rare, a few small marks per screen.

### Secondary (status)
- **OK Green** (#166a3d / #4fc58f): healthy, valid, online, block mode. The OK chip is quiet: ink text with a green icon and no fill.
- **Warn Amber** (#7d5a00 / #f0c040): degraded, expires soon, failover, detect mode, and the tinted state of the first KPI when the count is above zero. It is deliberately yellower than copper.
- **Crit Coral** (#b3261e / #ff7566): unreachable, offline, expired, critical, destructive actions.
- **Off Slate** (#5d5d5a / #a3a3a3): disabled, unknown, starting.

### Neutral
- **Paper Ground** (#f1f1ef) / **Graphite Ground** (#0e0e0f): page background.
- **White** (#ffffff) / **Graphite Surface** (#17171a): sidebar, KPI strip, instance rows, tables, fields.
- **Paper Raised** (#f6f6f4) / **Graphite Raised** (#202024): current menu item, role tags, table header, hover rows, inline code.
- **Paper Seam** (#d9d9d4) / **Graphite Seam** (#2e2e33): every border and divider.
- **Ink** (#111111 / #ececec) and **Ink Muted** (#575754 / #a0a0a0): text and secondary text.

Contrast checked on ground, surface and raised in both themes: ink 13.7 to 18.9, muted 6.2 to 7.4, copper 5.0 to 8.1, status inks 4.7 to 11.3.

### Named Rules
**The Hue Means State Rule.** Green, amber, coral and slate are used only for state. Copper is only for interaction and place, and is never used for a status or a badge.
**The Soft Tint Rule.** A status appears as a glyph and a word in the state colour on a 9-14% tint of that colour with a 28-32% ring, with 3px corners. Never a solid fill, never a pill. Problem rows take a 5% wash.
**The Never Colour Alone Rule.** A status colour always comes with its glyph shape and a word.

## Typography

**Text font:** Switzer (400, 500, 600), self-hosted from `/static/fonts`, falling back to Segoe UI, system-ui, Arial. It carries what the reader reads: menu, labels, body, table cells.
**Machine font:** Office Code Pro (400, 500, 600+), self-hosted, falling back to ui-monospace, Cascadia Mono, Consolas. It carries what the system says: page and section titles, instance and worker names, key figures, status chips, tags, table headers, hostnames, IPs, versions, errors.

**Character:** Two voices, one rule: mono is the system speaking, sans is the reader reading. Hierarchy comes from size and a weight of 500, never from bold mono. The pairing follows the HyperOtter project's logic (a sans with a mono voice) with Office Code Pro as the mono. Compact by design: body 0.9375rem, table cells 0.875rem, labels 0.8125rem.

### Hierarchy
- **Page title** (mono, 500, 1.5rem, tracking -0.02em): one per page.
- **Section title** (mono, 500, 1.0625rem, margin 2.25rem above): "Instances".
- **KPI figure** (mono, 500, 1.5rem, line 1.25, tracking -0.02em; the first KPI is 2rem): tabular figures.
- **Instance name** (mono, 500, 1rem; 1.0625rem for warn rows, 1.1875rem for crit rows).
- **Body** (Switzer 400, 0.9375rem, line 1.5). The root size stays at 100% on every screen width.
- **Label** (mono 500, 0.8125rem): chips, KPI captions, worker header, table headers (sentence case, muted). **Small** is 0.8125rem; **tags** and badges are 0.75rem, 500.
- **Cell** (Switzer 400, 0.875rem): table cells and alert lines. **Tag** (mono 500, 0.75rem): role tags and badges.
- **Data** (mono, 0.875em): hostnames, ports, error text.

### Named Rules
**The Tabular Figures Rule.** Tables, KPI figures, instance counts and fact values use `tabular-nums` so refreshing numbers do not shift.

## Layout

A 15.5rem index on the left (sticky, white surface, hairline on its right edge) and a fluid page on a grey ground capped at 92rem. The top-right of every page holds the language switch as two plain words. The dashboard order is page title, figures strip, section title, ledger.

The figures strip is one bordered white block of six cells split by 1px seams; the first cell (instances to check) is wider and its number larger, and it takes a faint amber wash when above zero. The ledger is a single bordered white block with a raised-grey header row, whose columns are declared once and shared by the header and every summary row: state (8.5rem), instance (9-12rem), alerts (fluid), last OK (6.5rem), version (5rem), latency (4.5rem), workers (4rem), chevron. Numeric columns are right aligned. Rows are separated by 1px seams.

The ledger has three modes. From 80rem it shows every column. Between 68rem and 80rem it drops version and latency from the row (they move into the opened row) and the figures strip puts its first cell on its own line. Below 68rem the index becomes a sticky top bar (brand and three icon buttons on one row, a horizontally scrolling item row below), the ledger header disappears, summary rows collapse to state, name and alerts, and the numbers move into the opened body. Tables (instances, users, services, bans, certificates, jobs; not the plugin matrix, whose columns are dynamic) stack as labelled blocks under 48rem. The figures strip is a grid with 1px gaps, so cells never leave orphan borders. Every number in a ledger row carries a visually hidden label, and a polite live region announces changes in alerts and healthy instances; the figures strip and the ledger are swapped in place when those change.

## Elevation & Depth

Flat. No shadows and no hover lift. Depth is tonal: grey ground, white surfaces, raised grey for headers and hovers, and 1px seams.

### Named Rules
**The One Container Rule.** A block of related content (the figures, the ledger, a table) is one bordered white surface with 4px corners. Containers are never nested inside each other.
**The No Motion for Show Rule.** The only movement is the chevron turning when a row opens. No hover lift, no dimming of siblings, no entrance animation.

## Shapes

Square-leaning. Containers, fields and buttons use 3-4px corners; status chips, alert chips and tags use 3px; there are no pills. Status is a soft tinted fill with a 1px ring, a drawn glyph (circle-check ok, triangle warn, octagon crit, dashed circle off) and a word. Icons are drawn on a 20px grid with a 1.6 stroke, round caps and joins, in one family. The brand mark is a small drawn periscope, in copper.

## Components

### Index (menu)
White rail with the periscope mark and the word Periscope on top, one drawn icon per page, and the admin items below a hairline. The current page is bold ink on a raised grey with a 1px ring and a copper icon. Items are 2.75rem tall. Theme, account and sign out sit in the foot, each with its icon.

### Language switch
Two plain words, English and Français. The current one is ink, bold, with a 2px copper underline.

### Status chip
Glyph and word in the state colour on a 12% tint with a 32% ring, 3px corners, 0.875rem 500. The OK chip is quieter: ink text, a 9% green tint and a green glyph.

### Alert line
A 3px-cornered tinted line (11% tint, 28% ring) with the glyph and the sentence. Up to two sit on a ledger row; the rest go to a list in the opened body, with a "+N" marker.

### Tag
Small boxed label (0.75rem, 500, muted on the raised grey with a 1px ring): "scheduler", "worker", and the block, detect, draft and active modes.

### Figures strip
Mono figures at 1.5rem (2rem for the first), a 0.8125rem caption above, and a small note below when relevant. The first cell lists the affected instances as links.

### Ledger row
A `details` element. The summary is a grid row: state chip, name (mono, 1rem) with its role tag, up to two alert lines, then right-aligned mono figures. Critical rows take a 5% coral wash and warn rows a 5% amber wash; names go to 600. Hover darkens the row by 4%. All rows start collapsed.

### Opened row
Two columns: facts as a seam-separated list (services and certificates; version, latency and last collection only on narrow screens) and the workers as ruled lines: state chip, name, host:port and type, last seen. A down or failover worker takes a 6% wash of its state colour.

### Buttons and fields
Primary is a copper fill (dark ink text on dark, white on light), 2.5rem tall, 3px radius, weight 500. Outline variants use the seam border and the raised grey on hover; danger and warning outlines use their state colour and sit at least 1.25rem from a neighbour. Fields are surface-filled with a 1px seam and a copper border plus a 2px soft ring on focus.

### Tables
One bordered white container with 4px corners, a raised-grey header row of muted 600 sentence-case labels with a drawn sort glyph in a real button, row seams, and a hover tint.

## Do's and Don'ts

### Do:
- **Do** align every repeated value in a shared grid so columns run straight from row to row.
- **Do** carry state with a glyph, a word and a colour, and nothing else.
- **Do** keep copper for action, place and the brand mark only: links, the primary button, the current page icon, focus.
- **Do** use mono only for data (names, figures, hosts, versions, times) and Switzer for everything the reader reads.
- **Do** keep a 2.75rem minimum height on menu items and the language switch (2.5rem on other controls) and a visible 2px focus outline with 2px offset.
- **Do** keep destructive actions at least 1.25rem from any neighbouring control and behind a confirmation.

### Don't:
- **Don't** nest containers, or use rounded pills, shadows, hover lift, sibling dimming or entrance animation.
- **Don't** use copper for a status, or green, amber or coral for interaction.
- **Don't** use an eyebrow, a decorative icon outside the page icons and the brand mark, or a coloured stripe on one side of a row.
- **Don't** copy HyperOtter's palette or mascot; only its sans-plus-mono logic is shared.

Not canonized (defects the build carries, not rules): no separate display face yet (titles, figures and names all use the mono); the ledger header is hidden from assistive technology, the row numbers carry their own visually hidden labels instead; the periscope mark is a first drawing and can be refined.
