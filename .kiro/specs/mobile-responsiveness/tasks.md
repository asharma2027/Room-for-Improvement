# Implementation Plan: Mobile Responsiveness

## Overview

Make the "Room for Improvement" UChicago housing guide fully responsive on mobile devices (320px–768px). The implementation is CSS-first: append mobile media queries to `public/css/styles.css` and make minimal EJS template changes for the hamburger menu and card view. Four breakpoints are used: 480px, 600px, 768px, and 900px. No new npm dependencies are required.

## Tasks

- [x] 1. Add viewport meta tag and set up base responsive infrastructure
  - [x] 1.1 Add viewport meta tag to layout
    - Verify `views/partials/head.ejs` or `views/layouts/layout.ejs` includes `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
    - If missing, add it to the `<head>` section of `views/layouts/layout.ejs`
    - _Requirements: 7.4 (body font floor), 3.1 (SVG scaling)_
  - [x] 1.2 Add global mobile spacing and typography media queries to `public/css/styles.css`
    - Append `@media (max-width: 768px)` block with: `main { padding: var(--spacing-xl) 1rem; }`, `h1 { font-size: 1.75rem; }`, `.stat-card, .feature-item { padding: 1.25rem; }`, `footer { padding: 1rem; }`
    - Append `@media (max-width: 480px)` block with: `body { font-size: 1rem; }`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [x] 2. Implement mobile hamburger menu navigation
  - [x] 2.1 Add hamburger toggle button and overlay markup to `views/partials/nav.ejs`
    - Add a `<button class="hamburger-toggle" aria-label="Toggle navigation" aria-expanded="false" aria-controls="nav-links">` element with a three-line CSS icon inside `<nav>` before the `<ul>`
    - Add class `.nav-links` to the existing `<ul>` and add `id="nav-links"`
    - Add a `.nav-overlay` backdrop `<div>` for click-outside-to-close
    - Add inline `<script>` to toggle `.open` class on hamburger click, close on link click, outside click, or Escape key — matching the existing inline script pattern in the nav partial
    - _Requirements: 1.1, 1.2, 1.3, 1.6, 1.7_
  - [x] 2.2 Add hamburger menu CSS styles to `public/css/styles.css`
    - At `≤768px`: hide `.nav-links` (`display: none`), show `.hamburger-toggle`
    - When `.nav-links.open`: display as vertical overlay panel with `position: fixed`, full-width, sliding from top below the header
    - Nav search input renders full-width inside the overlay
    - Each nav link gets `min-height: 48px` with vertical padding
    - Hamburger toggle button gets `min-width: 44px; min-height: 44px`
    - Above 768px: `.hamburger-toggle` hidden, `.nav-links` displayed normally
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 16.1, 16.2_

- [x] 3. Checkpoint
  - Ensure the hamburger menu works at all breakpoints, navigation links are accessible, and desktop layout is unchanged. Ask the user if questions arise.

- [x] 4. Implement responsive card view for room tables
  - [x] 4.1 Add `data-label` attributes to `<td>` elements in `views/housePage.ejs`
    - Add `data-label="Room"`, `data-label="Floor"`, `data-label="Type"`, `data-label="Tags"`, `data-label="Culture"`, `data-label="Noise"` to each `<td>` in the room table rows
    - Preserve existing `onclick` handlers and data attributes on `<tr>` elements
    - _Requirements: 2.1, 2.2, 2.3_
  - [x] 4.2 Add `data-label` attributes to `<td>` elements in `views/rooms.ejs`
    - Add `data-label="Room"`, `data-label="Dorm"`, `data-label="House"`, `data-label="Floor"`, `data-label="Type"`, `data-label="Tags"`, `data-label="Culture"`, `data-label="Noise"` to each `<td>` in the rooms table rows
    - Preserve existing `onclick` handlers and data attributes on `<tr>` elements
    - _Requirements: 2.1, 2.2, 2.3_
  - [x] 4.3 Add card view CSS styles to `public/css/styles.css`
    - At `≤768px`: `#room-table thead, #rooms-table thead { display: none; }`, `#room-table tr, #rooms-table tr { display: block; margin-bottom: 1rem; border-radius: var(--radius-md); box-shadow: var(--shadow-sm); padding: 1rem; }`, `#room-table td, #rooms-table td { display: block; padding: 0.5rem 0; }` with `td::before { content: attr(data-label); font-weight: 700; display: block; margin-bottom: 0.25rem; }`
    - `.tags-container` within cards gets `max-width: 100%`
    - Tag elements (`.tag`) in card view get `min-height: 32px`
    - Above 768px: standard horizontal table layout preserved
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 16.3_

- [x] 5. Implement responsive campus map styles
  - [x] 5.1 Add campus map responsive CSS to `public/css/styles.css`
    - At `≤600px`: increase `.dorm-group text` font sizes by factor of 1.3, increase tap target area of `.dorm-group` elements to minimum 44×44px
    - At `≤480px`: add styles for map legend repositioning below the map, map header bar `white-space: normal` for text wrapping
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 10.4_
  - [x] 5.2 Add small JavaScript snippet for SVG legend repositioning at ≤480px
    - In `views/explore.ejs` or via CSS, use `matchMedia` to adjust SVG legend `<g>` positioning below the map at ≤480px
    - Consistent with existing inline script pattern in explore.ejs
    - _Requirements: 3.5_

- [x] 6. Implement touch-optimized filter controls
  - Add responsive CSS to `public/css/styles.css` for the `.room-filters` container
  - At `≤768px`: `.room-filters { flex-direction: column; }`, tag buttons get `min-height: 44px`, filter dropdown panels get `width: 100%`, select elements get `min-height: 44px; font-size: 16px` (prevents iOS zoom), clear button gets `width: 100%` at bottom of stack
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 16.1_

- [x] 7. Implement responsive word clouds
  - Add responsive CSS to `public/css/styles.css`
  - At `≤768px`: `.word-cloud-row { flex-direction: column; }` (single column), `.word-cloud-canvas { height: 180px; }`
  - At `≤480px`: `.word-cloud-fallback .wc-word { min-font-size: 14px; }` (fallback word minimum)
  - Ensure `.word-cloud-fallback` displays readable text when canvas fails
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [x] 8. Implement responsive preview pills and house banner
  - Add responsive CSS to `public/css/styles.css`
  - At `≤768px`: `.preview-pill { position: static; display: flex; flex-direction: column; }`, minimum touch target height 44px, `.house-board-btn { width: 100%; }`
  - At `≤480px`: banner padding reduced to `1.5rem`, house name font size to `1.75rem`
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 16.1_

- [x] 9. Implement responsive stats row
  - Add responsive CSS to `public/css/styles.css`
  - At `≤768px`: `.house-stats-row { flex-wrap: wrap !important; }` (overriding inline `flex-wrap: nowrap`), inline search form gets `width: 100%; flex-basis: 100%` on its own row
  - At `≤480px`: `.house-stat-lbl { font-size: 0.65rem; }`, `.house-stat-val { font-size: 1rem; }`
  - _Requirements: 8.1, 8.2, 8.3, 17.2_

- [x] 10. Checkpoint
  - Ensure card view, map, filters, word clouds, preview pills, and stats row all render correctly at 320px, 480px, 600px, 768px, and 1024px. Ensure desktop layout is unchanged. Ask the user if questions arise.

- [x] 11. Implement responsive rankings board
  - Add responsive CSS to `public/css/styles.css`
  - Existing 900px and 600px breakpoints already handle grid columns — verify they work correctly
  - At `≤768px`: emblem strip gets `overflow-x: auto` for horizontal scrolling, `.ranking-scroll { max-height: 320px; }`
  - _Requirements: 9.1, 9.2, 9.3, 9.4_

- [x] 12. Implement responsive explore page
  - Add responsive CSS to `public/css/styles.css`
  - At `≤768px`: search bar container `flex-direction: column`, search bar inline style overrides: `min-width: 0 !important; flex: 1 1 100% !important;`
  - At `≤600px`: `.dorm-rankings-grid { grid-template-columns: 1fr; }` (adjust existing 700px breakpoint to 600px)
  - At `≤480px`: map header bar `white-space: normal` for text wrapping
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 17.1_

- [x] 13. Implement responsive room review form
  - Add responsive CSS to `public/css/styles.css`
  - At `≤768px`: `.sd-strip` radio options get increased gap spacing (minimum 44px between tap targets), form grid switches to `grid-template-columns: 1fr`, `.culture-chips .chip-label { min-height: 44px; }`, `.v2-tag-grid { grid-template-columns: 1fr; }`
  - At `≤480px`: `.sd-sublabel { display: none; }`
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 16.1_

- [x] 14. Implement responsive room detail page
  - Add responsive CSS to `public/css/styles.css`
  - At `≤768px`: room detail header `flex-direction: column; align-items: flex-start`, `.ratings-table td { padding: 0.5rem; }`, ratings table `width: 100%`
  - At `≤480px`: `.custom-room-name { font-size: 2rem; }`
  - _Requirements: 12.1, 12.2, 12.3_

- [x] 15. Implement responsive landing page
  - Add responsive CSS to `public/css/styles.css`
  - At `≤768px`: `.landing-hero { padding: 2rem 1rem; }`, `.landing-hero h1 { font-size: 1.75rem; }`, `.features-grid { grid-template-columns: 1fr; }`, cascading selects `width: 100%`
  - At `≤480px`: `.landing-buttons { flex-direction: column; }` with full-width buttons
  - _Requirements: 13.1, 13.2, 13.3, 13.4_

- [x] 16. Implement responsive authentication pages
  - Add responsive CSS to `public/css/styles.css`
  - At `≤480px`: `.form-container { margin: 0 1rem; }`
  - All viewports: form inputs maintain `font-size: 16px` minimum, submit buttons `width: 100%`
  - _Requirements: 14.1, 14.2, 14.3_

- [x] 17. Implement responsive house board page
  - Add responsive CSS to `public/css/styles.css`
  - At `≤768px`: `.top-info-section { flex-direction: column; }`, chatter bubbles single-column at full width, board identity strip `flex-wrap: wrap`
  - At `≤480px`: chatter bubble text minimum font size `0.85rem`
  - _Requirements: 15.1, 15.2, 15.3, 15.4_

- [x] 18. Implement inline style overrides for mobile
  - Add `!important` override rules in `public/css/styles.css` media queries
  - At `≤768px`: explore search bar `min-width: 0 !important; flex: 1 1 100% !important;`, stats row `flex-wrap: wrap !important;`, search inputs with inline `width:200px` overridden to `width: 100% !important;`
  - Use `!important` only when overriding inline styles that cannot be refactored in EJS templates
  - _Requirements: 17.1, 17.2, 17.3, 17.4_

- [x] 19. Ensure minimum touch target sizes across all components
  - Audit all interactive elements in the ≤768px media queries in `public/css/styles.css`
  - Ensure all buttons, links, checkboxes, and radio inputs have minimum 44×44px sizing
  - Add padding or size increases to any elements that fall below the minimum
  - Verify nav links in hamburger overlay have `min-height: 48px`
  - Verify `.tag` elements in card view have `min-height: 32px`
  - _Requirements: 16.1, 16.2, 16.3, 16.4_

- [x] 20. Final checkpoint
  - Ensure all tests pass and all pages render correctly at 320px, 375px, 480px, 600px, 768px, and 1024px. Verify no horizontal overflow on any page. Verify desktop layout is unchanged. Ask the user if questions arise.

## Notes

- No new npm dependencies are required — all changes are CSS media queries and minor EJS template modifications
- Property-based testing does not apply to this feature (CSS/layout changes only)
- The `!important` declarations are used exclusively for overriding inline styles in EJS templates (Requirement 17)
- Existing breakpoints at 900px and 600px for rankings are preserved and extended
- The 700px breakpoint for `.dorm-rankings-grid` is adjusted to 600px for consistency with the breakpoint system
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at logical milestones
