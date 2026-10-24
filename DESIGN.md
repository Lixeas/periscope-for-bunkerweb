---
name: Periscope
description: A read-only ledger of BunkerWeb instances: ruled lines, aligned columns, status as text, every alert inside its own instance.
colors:
  forest-ground: "#0f1c17"
  forest-surface: "#15261f"
  forest-raised: "#1b3028"
  forest-seam: "#2a4237"
  mist: "#e7f1ec"
  mist-muted: "#9db4a9"
  teal-bright: "#45c9a2"
  teal-bright-ink: "#04201a"
  leaf: "#28a964"
  ochre: "#c98805"
  coral: "#ed6d5a"
  slate-mist: "#9db4a9"
  moss-ground: "#f3f7f5"
  moss-surface: "#ffffff"
  moss-raised: "#eaf1ee"
  moss-seam: "#d5e0db"
  moss-ink: "#17251f"
  moss-ink-muted: "#4b5d55"
  teal-deep: "#136f5c"
  moss-ok: "#1d7a48"
  moss-warn: "#906104"
  moss-crit: "#ca2e16"
  moss-off: "#566860"
  fill-ok: "#3d7a5b"
  fill-warn: "#b98a2b"
  fill-warn-ink: "#1c1200"
  fill-crit: "#b4544a"
  fill-off: "#64726b"
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
    textColor: "{colors.mist-muted}"
    padding: "0.4rem 0.7rem"
    height: "2.75rem"
  menu-item-current:
    textColor: "{colors.mist}"
  status:
    backgroundColor: "{colors.fill-crit}"
    textColor: "#ffffff"
    rounded: "{rounded.focus}"
    typography: "{typography.label}"
  ledger-row:
    textColor: "{colors.mist}"
    padding: "0.85rem 0.9rem"
    height: "3.25rem"
  button-primary:
    backgroundColor: "{colors.teal-bright}"
    textColor: "{colors.teal-bright-ink}"
    rounded: "{rounded.field}"
    height: "2.5rem"
  input:
    backgroundColor: "{colors.forest-surface}"
    textColor: "{colors.mist}"
    rounded: "{rounded.field}"
    height: "2.5rem"
---

# Design System: Periscope

## Overview

**Creative North Star: "The Ledger"**

Periscope reads like a ledger, not a dashboard of floating cards: one strip of figures, then one table of instances whose columns run straight from the first row to the last. A reader scans down a column to compare and across a row to understand an instance. Every alert is a solid status line inside the instance it belongs to; there is no separate alert feed. Light is the default theme (pale green-tinted ground), dark is a reader choice with the same structure.

The system avoids the look of generated dashboards: floating rounded cards, pill chips, shadows, hover lift, big hero numbers. It keeps what makes a page fast to read: a left index with one drawn icon per page, a small periscope mark, solid status chips with a glyph and a word, and a 3px bar on the left edge of problem rows so the instance to check is visible at a glance.

**Key Characteristics:**
- Green-tinted neutral ground, single-level surfaces, 1px seams, 3-4px corners. No shadows, no gradients.
- Status as glyph + word on a solid muted fill, identical in both themes. Teal only for action, place and the brand mark.
- Switzer for reading, Office Code Pro for data (names, figures, hosts, versions, times).
- Problem instances sort first and carry their alerts on the row; every row starts collapsed.
- Light and dark themes share one token set (`data-bs-theme`); the page starts light.

## Colors

Forest and moss: neutrals tinted toward green, one green-teal accent, and four status hues. Hue means state; teal means "act here" or "you are here". There is no decorative colour.

### Primary
- **Teal** (#136f5c light / #45c9a2 dark; ink on it #ffffff / #04201a): current menu icon, the brand ring, links, the primary button fill, field focus border, the 2px focus outline (2px offset), selection tint. It is not a status colour (the OK fill is a different, greyer green) and stays rare, a few small marks per screen.

### Secondary (status)
Status has two layers. **Fills** are defined once in `:root` and are identical in both themes; they colour chips, alert chips, badges, the problem-row bar and the figure top bar. **Text colours** vary slightly per theme and are used for plain text (figure number, mode tags, notes, outline buttons, worker washes).

| State | Fill (both themes) | Ink on fill | Text light / dark |
|---|---|---|---|
| OK | **Fill OK** #3d7a5b | #ffffff | **Leaf** #1d7a48 / #28a964 |
| Warn | **Fill Warn** #b98a2b | #1c1200 | **Ochre** #906104 / #c98805 |
| Crit | **Fill Crit** #b4544a | #ffffff | **Coral** #ca2e16 / #ed6d5a |
| Off | **Fill Off** #64726b | #ffffff | **Slate** #566860 / #9db4a9 |

OK is healthy, valid, online, block mode. Warn is degraded, expires soon, failover, detect mode, and the top bar of the first figure when above zero. Crit is unreachable, offline, expired, critical, destructive actions. Off is disabled, unknown, starting.

### Neutral
- **Moss Ground** (#f3f7f5) / **Forest Ground** (#0f1c17): page background.
- **White** (#ffffff) / **Forest Surface** (#15261f): sidebar, figures strip, instance rows, tables, fields.
- **Moss Raised** (#eaf1ee) / **Forest Raised** (#1b3028): current menu item, role tags, table header, hover rows, inline code.
- **Moss Seam** (#d5e0db) / **Forest Seam** (#2a4237): every border and divider.
- **Moss Ink** (#17251f) / **Mist** (#e7f1ec) and **Moss Ink Muted** (#4b5d55) / **Mist Muted** (#9db4a9): text and secondary text.

Contrast checked on ground, surface and raised in both themes: text 12.1 to 15.9, muted 6.1 to 8.0, teal 5.3 to 8.5, status text colours 4.6 to 5.9. Ink on the status fills: OK 5.1, warn 5.9, crit 4.9, off 5.1; teal button 6.1 (light) and 8.3 (dark). The fills are not asked to meet contrast against the ground; the word inside carries the meaning.

### Named Rules
**The Hue Means State Rule.** Green, ochre, coral and slate are used only for state. Teal is only for interaction and place, and is never used for a status or a badge.
**The Solid Muted Fill Rule.** A status is a glyph and a word in the fill's ink on one solid muted fill (`--st-*`), with 3px corners, the same in both themes. No ring, no tint, never a pill. Problem rows have no tint: only a 3px inset left bar in the status colour.
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

A 15.5rem index on the left (sticky, surface colour, hairline on its right edge) and a fluid page on a green-tinted ground capped at 92rem. The top-right of every page holds the theme switch and the avatar menu (signed-out pages hold the language dropdown instead). Layout and sizing are identical in both themes; the theme changes colour only. The dashboard order is page title, figures strip, section title, ledger.

The figures strip is one bordered white block of six cells split by 1px seams; the first cell (instances to check) is wider and its number larger, and it takes a 3px inset top bar in warn when above zero. The ledger is a single bordered white block with a raised-tint header row, whose columns are declared once and shared by the header and every summary row: state (8.5rem), instance (9-12rem), alerts (fluid), last OK (6.5rem), version (5rem), latency (4.5rem), workers (4rem), chevron. Numeric columns are right aligned. Rows are separated by 1px seams.

The ledger has three modes. From 80rem it shows every column. Between 68rem and 80rem it drops version and latency from the row (they move into the opened row) and the figures strip puts its first cell on its own line. Below 68rem the index becomes a sticky top bar (brand and the language button on one row, a horizontally scrolling item row below), the ledger header disappears, summary rows collapse to state, name and alerts, and the numbers move into the opened body. Tables (instances, users, services, bans, certificates, jobs; not the plugin matrix, whose columns are dynamic) stack as labelled blocks under 48rem. The figures strip is a grid with 1px gaps, so cells never leave orphan borders. Every number in a ledger row carries a visually hidden label, and a polite live region announces changes in alerts and healthy instances; the figures strip and the ledger are swapped in place when those change.

## Elevation & Depth

Flat. No shadows and no hover lift. Depth is tonal: tinted ground, lighter surfaces, raised tint for headers and hovers, and 1px seams.

### Named Rules
**The One Container Rule.** A block of related content (the figures, the ledger, a table) is one bordered white surface with 4px corners. Containers are never nested inside each other.
**The Functional Motion Rule.** Movement only confirms a state change: the chevron turning (0.15s), dropdowns popping in (0.16s), an opened instance body fading in (0.22s), 120ms hover and colour transitions, a 1px press on `.btn:active`, and the theme switch. No hover lift, no dimming of siblings, no decorative entrance animation.

### Motion
One authored moment: an instance row whose state changed on a live refresh fades from an accent wash (22% accent on the surface) to transparent over 2.2s (`.just-changed`). Theme change cross-fades page colours over about 0.3s (`html.theme-anim`). Under `prefers-reduced-motion` all movement and fades are removed; the changed row keeps a static 1px accent ring until the next refresh.

## Shapes

Square-leaning. Containers, fields and buttons use 3-4px corners; status chips, alert chips and tags use 3px; there are no pills. Status is a solid muted fill, a drawn glyph (circle-check ok, triangle warn, octagon crit, dashed circle off) and a word. Icons are drawn on a 20px grid with a 1.6 stroke, round caps and joins, in one family. The brand mark is a small drawn periscope, in teal.

## Components

### Index (menu)
White rail with the periscope mark and the word Periscope on top, one drawn icon per page, and Instances (admin only) below a hairline. The current page is bold ink on a raised tint with a 1px ring and a teal icon. Items are 2.75rem tall. The foot holds only the language dropdown; account, sign out, users, audit and theme are not in the rail.

### Language dropdown
A native `details` in the rail foot (top right on signed-out pages) that opens upward with a pop-in. The button and each option show an inline SVG flag and the language name: English with the United Kingdom flag, Français with the France flag. The current option is bold with a 2px accent bar on its left. Closes on outside click and Escape.

### Theme switch
Top bar, top right. A `role="switch"` button with a 3.5rem pill track (the one pill in the system, because it is a switch), a sun and a moon fixed and centred on the two knob positions, and an accent knob that slides 28px. Only the knob moves; the active icon takes the accent ink.

### Avatar menu
To the right of the theme switch: a 2.5rem circle with the user's initial on an accent fill. It opens a dropdown with the account name (link to /account) and Sign out below it. A soft 3px accent ring shows on hover and while open. Closes on outside click and Escape.

### Account tabs
My account, Users and Audit (the last two admin only) are shared by /account, /admin/users and /admin/audit. They are plain links, not JS tabs, on a 1px seam with a 2px accent underline on the current one; they wrap onto a second line rather than scroll.

### Status chip
Glyph and word in the fill's ink on a solid `--st-*` fill, 3px corners, 0.875rem 500, no ring. OK, crit and off use white ink, warn uses #1c1200. Badges (0.75rem) share the same fills.

### Alert line
A 3px-cornered solid status fill (same ink rules) with the glyph and the sentence. Up to two sit on a ledger row; the rest go to a list in the opened body, with a "+N" marker.

### Tag
Small boxed label (0.75rem, 500, muted on the raised tint with a 1px ring): "scheduler", "worker", and the block, detect, draft and active modes.

### Figures strip
Mono figures at 1.5rem (2rem for the first), a 0.8125rem caption above, and a small note below when relevant. The first cell lists the affected instances as links.

### Ledger row
A `details` element. The summary is a grid row: state chip, name (mono, 1rem) with its role tag, up to two alert lines, then right-aligned mono figures. Critical and warn rows have no tint, only a 3px inset left bar in the status fill; names go to 600. Hover shades the row by 4%. All rows start collapsed.

### Opened row
Two columns: facts as a seam-separated list (services and certificates; version, latency and last collection only on narrow screens) and the workers as ruled lines: state chip, name, host:port and type, last seen. A down or failover worker takes a 6% wash of its state colour.

### Buttons and fields
Primary is a teal fill (dark teal ink on dark, white on light), 2.5rem tall, 3px radius, weight 500. Outline variants use the seam border and the raised tint on hover; danger and warning outlines use their state colour and sit at least 1.25rem from a neighbour. Fields are surface-filled with a 1px seam and a teal border plus a 2px soft ring on focus.

### Tables
One bordered white container with 4px corners, a raised-tint header row of muted 600 sentence-case labels with a drawn sort glyph in a real button, row seams, and a hover tint.

## Do's and Don'ts

### Do:
- **Do** align every repeated value in a shared grid so columns run straight from row to row.
- **Do** carry state with a glyph, a word and a solid status fill, and nothing else.
- **Do** keep teal for action, place and the brand mark only: links, the primary button, the current page icon, focus.
- **Do** use mono only for data (names, figures, hosts, versions, times) and Switzer for everything the reader reads.
- **Do** keep a 2.75rem minimum height on menu items, tabs and the language dropdown (2.5rem on other controls) and a visible 2px focus outline with 2px offset.
- **Do** keep destructive actions at least 1.25rem from any neighbouring control and behind a confirmation.

### Don't:
- **Don't** nest containers, or use rounded pills (the theme switch track is the single exception), shadows, hover lift, sibling dimming or decorative entrance animation.
- **Don't** use teal for a status, or green, ochre or coral for interaction.
- **Don't** use an eyebrow, a decorative icon outside the page icons and the brand mark, or a tinted instance row. The 3px inset bar on problem rows and the top bar on the first figure are the only edge marks.
- **Don't** copy HyperOtter's palette or mascot; only its sans-plus-mono logic is shared.

Not canonized (defects the build carries, not rules): no separate display face yet (titles, figures and names all use the mono); the ledger header is hidden from assistive technology, the row numbers carry their own visually hidden labels instead; the periscope mark is a first drawing and can be refined.
