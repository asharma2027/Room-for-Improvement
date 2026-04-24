# Implementation Plan: UX Refinements V2

## Overview

This plan implements 13 UX refinements to the "Room for Improvement" UChicago housing platform. Tasks are ordered so foundational shared utilities and CSS come first, then page-specific template changes, then new routes/pages, and finally cross-cutting navigation updates. Each task builds incrementally on previous work. **Critical constraint: do not break any existing features — only make the specified modifications and leave all other code exactly as is.**

## Tasks

- [x] 1. Update shared rating color functions and add noise color functions
  - [x] 1.1 Update `ratingTextColor` in `views/partials/ratingColors.ejs`
    - Change `ratingTextColor(val)` so values 2 and 4 return dark text (`#1a1a1a`) instead of white, and value 3 returns `#1a1a1a`
    - Values 1 and 5 remain white (`#fff`) — these are the dark backgrounds
    - The updated function: `return (r === 1 || r === 5) ? '#fff' : '#1a1a1a';`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_
  - [x] 1.2 Add `noiseColor` and `noiseTextColor` functions to `views/partials/ratingColors.ejs`
    - Add `noiseColor(val)` with inverted mapping: `{ 1: '#34877A', 2: '#92B89D', 3: '#EFE6D1', 4: '#D69772', 5: '#AE5436' }`
    - Add `noiseTextColor(val)` with same contrast logic: white for 1 and 5, dark (`#1a1a1a`) for 2, 3, 4
    - Keep existing `ratingColor` function completely unchanged
    - _Requirements: 8.1, 8.2, 8.3, 8.6_

- [x] 2. Fix text contrast and noise color in Room Details page
  - [x] 2.1 Update inline `ratingTextColor` in `views/roomDetails.ejs`
    - Replace the inline `ratingTextColor` function (currently returns `#333` only for value 3) with the updated version matching the shared partial: `return (r === 1 || r === 5) ? '#fff' : '#1a1a1a';`
    - Add `font-weight: 700` to all rating label and value text in the `.ratings-table`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_
  - [x] 2.2 Apply inverted noise color scale to the "Outside Noise" row in `views/roomDetails.ejs`
    - Add inline `noiseColor` and `noiseTextColor` functions (same as the shared partial)
    - Change the "Outside Noise" `<tr>` to use `noiseColor(onVal)` and `noiseTextColor(onVal)` instead of `ratingColor`/`ratingTextColor`
    - All other rating rows (Room Size, Natural Light, Temperature Control, House Culture) continue using `ratingColor`/`ratingTextColor`
    - _Requirements: 8.3, 8.6_

- [x] 3. Update CSS for layout adjustments
  - [x] 3.1 Update `.features-grid` in `public/css/styles.css` for 4-column layout
    - Add a media query for viewports ≥ 1024px: `grid-template-columns: repeat(4, 1fr)`
    - Keep the existing `repeat(auto-fit, minmax(280px, 1fr))` as the default/mobile layout
    - _Requirements: 4.3, 4.4_
  - [x] 3.2 Add explore page styles to `public/css/styles.css`
    - Add styles for the combined explore page layout (map section + rankings section divider)
    - _Requirements: 5.1, 5.4_
  - [x] 3.3 Add house board search bar widening styles to `public/css/styles.css`
    - Add a `body.page-houseboard .nav-search-input` rule with `width: 400px` (approximately 50% wider than the default 260px focused width)
    - Ensure the widened bar does not overlap adjacent nav elements
    - _Requirements: 10.1, 10.2, 10.3_

- [ ] 4. Checkpoint — Ensure CSS changes don't break existing layouts
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Update House Page — word cloud text sizes, column width, and noise scale
  - [x] 5.1 Increase word cloud title and description text sizes in `views/housePage.ejs`
    - In the `.word-cloud-row .word-cloud-section h3` CSS rule, change `font-size` from `0.95rem` to `1.15rem`
    - In the `.word-cloud-row .word-cloud-sub` CSS rule, change `font-size` from `0.72rem` to `0.82rem`
    - Leave the non-row (single-column) word cloud sizes unchanged (already 1.15rem and 0.85rem)
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - [x] 5.2 Decrease Temp Control column width in `views/housePage.ejs`
    - Change the `max-width` for rating column headers (`naturalLight`, `roomSize`, `noise`, `culture`, `tempControl`) from `82px` to `76px`
    - Verify the "Temp Control" text fits within the visible table area
    - _Requirements: 3.1, 3.2, 3.3_
  - [x] 5.3 Apply inverted noise color scale in the House Page room table
    - In the room table noise column rendering, replace the standard `ratingColor`/`ratingTextColor` usage with `noiseColor`/`noiseTextColor` (from the included `ratingColors.ejs` partial)
    - Change the noise column header label from "Noise" to "Noise Level"
    - _Requirements: 8.1, 8.4_

- [x] 6. Apply inverted noise color scale on All Rooms page
  - [x] 6.1 Update noise column in `views/rooms.ejs`
    - Replace the inline noise color mapping (`noiseColors` object) with the inverted scale: `{ 1: '#34877A', 2: '#92B89D', 3: '#EFE6D1', 4: '#D69772', 5: '#AE5436' }`
    - Update the inline noise text color logic: white for values 1 and 5, dark (`#1a1a1a`) for values 2, 3, 4
    - Change the noise column header label from "Noise" to "Noise Level"
    - _Requirements: 8.2, 8.5, 8.6_

- [x] 7. Implement sentiment-based word cloud coloring on House Page
  - [x] 7.1 Add sentiment mapping and color functions to `views/housePage.ejs`
    - Add the `cultureSentiment` object mapping culture checklist words to sentiment scores (1–5) as defined in the design document
    - Add the `sentimentColor(score)` function using the rating color scale: `{ 5: '#34877A', 4: '#92B89D', 3: '#EFE6D1', 2: '#D69772', 1: '#AE5436' }`
    - Add `positiveWords` and `negativeWords` arrays for the free-text descriptor heuristic
    - Add `descriptorSentiment(word)` function that returns 4 for positive, 2 for negative, 3 for neutral
    - Default unknown culture words to neutral (#EFE6D1 with dark text)
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_
  - [x] 7.2 Apply sentiment coloring to the Culture Word Cloud rendering
    - Update the wordcloud2.js color callback for the culture cloud to use `sentimentColor(cultureSentiment[word] || 3)`
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

- [x] 8. Rewrite Descriptor Word Cloud with D3-Cloud
  - [x] 8.1 Add D3 and d3-cloud CDN script tags to `views/housePage.ejs`
    - Add `<script src="https://d3js.org/d3.v7.min.js"></script>` and `<script src="https://cdn.jsdelivr.net/npm/d3-cloud@1/build/d3.layout.cloud.min.js"></script>`
    - Place them before the descriptor cloud rendering script
    - _Requirements: 9.1_
  - [x] 8.2 Implement D3-cloud descriptor word cloud rendering in `views/housePage.ejs`
    - Replace the wordcloud2.js rendering for the descriptor cloud with a `renderDescriptorCloud` function using `d3.layout.cloud()`
    - Render words as SVG `<text>` elements with proper bounding-box-aware placement
    - Apply sentiment-based coloring using `descriptorSentiment(word)` and `sentimentColor()`
    - Preserve the existing word tokenization logic (keeping short phrases intact, splitting longer text, filtering stopwords)
    - The Culture Word Cloud must continue using wordcloud2.js — do not change it
    - _Requirements: 9.1, 9.5, 9.6, 11.5_
  - [x] 8.3 Implement hover effects and tooltip for D3-cloud descriptor words
    - On mouseover: scale up the word using SVG transform (e.g., `font-size * 1.4`) with a 200ms transition — no full re-render
    - On mouseover: show tooltip reading "[word in bold]: according to [x] students" where x is the count
    - On mouseout: return word to original size and hide tooltip
    - _Requirements: 9.2, 9.3, 9.4_

- [ ] 9. Checkpoint — Verify all page-specific changes work correctly
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Implement dual filter dropdowns on All Rooms page
  - [x] 10.1 Add House Filter Dropdown HTML to `views/rooms.ejs`
    - Add a new "Filter by Houses" dropdown button next to the existing "Filter by Dorm" button, styled consistently with the `dorm-filter-dropdown-wrapper` pattern
    - The dropdown content should list all houses grouped under bold, unclickable dorm name headers
    - Each house item should have a checkmark indicator (hidden by default, visible when selected)
    - _Requirements: 12.1, 12.2, 12.6_
  - [x] 10.2 Implement House Filter Dropdown JavaScript in `views/rooms.ejs`
    - When no dorm filter is active: show all houses across all dorms, grouped by dorm
    - When dorm filter is active: show only houses within selected dorms
    - Click a house to toggle selection; click again to deselect
    - Filter the room table to show only rooms belonging to selected houses
    - Close dropdown on outside click
    - When dorm filter changes, clear house selections that no longer belong to selected dorms
    - Preserve all existing dorm filter functionality without modification
    - _Requirements: 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 12.9_

- [x] 11. Create combined Explore page and server routes
  - [x] 11.1 Create `views/explore.ejs` template
    - Combine the campus map section from `views/map.ejs` (header, search bar, SVG map, search script) with the dorm rankings card grid from `views/dormRankingsAll.ejs`
    - Include the `ratingColors.ejs` partial for the rankings color functions
    - Use a clear page title "Explore Campus" with descriptive subtitle
    - **Remove** the Quick Access section (the `<h3>` "Quick Access — All Dorms" heading and dorm pill buttons) — do not include it
    - Retain the SVG campus map, map header bar, and house search bar
    - Include all necessary inline scripts for map hover effects, search, and rankings data
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 6.1, 6.2_
  - [x] 11.2 Add `/explore` route and redirects in `server.js`
    - Add a new `GET /explore` route (authenticated) that fetches both map data and rankings data, then renders `explore.ejs`
    - Change the existing `GET /map` route to redirect (302) to `/explore`
    - Change the existing `GET /dorm-rankings` route to redirect (302) to `/explore`
    - The `/explore` route must pass: `user`, `allHousesJson`, `dormScores`, `dormScoresJson`
    - _Requirements: 5.1, 5.5, 5.6, 5.7, 13.5_

- [x] 12. Update navigation bar for page consolidation
  - [x] 12.1 Update `views/partials/nav.ejs`
    - Replace the separate "Campus Map" (`/map`) and "Dorm Rankings" (`/dorm-rankings`) links with a single "Explore Campus" link pointing to `/explore`
    - Set active state when `path === '/explore'`
    - Final nav order for authenticated users: Logo → Search Bar → Explore Campus → All Rooms → Leave Feedback → Logout
    - Do not modify the unauthenticated nav links
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [x] 13. Resize and consolidate landing page feature panels
  - [x] 13.1 Update `views/index.ejs` for authenticated users
    - Replace the separate "Dorm Rankings" and "Campus Map" panels with a single "Explore Campus" panel (icon 🗺️, links to `/explore`)
    - Keep "Search Rooms", "Submit Room Info", and "Leave Feedback" panels unchanged
    - Final panel order: Explore Campus → Search Rooms → Submit Room Info → Leave Feedback (4 panels)
    - Do not modify the unauthenticated feature panels (Real Feedback, Smart Search, Data Driven)
    - _Requirements: 4.1, 4.2, 4.5_

- [x] 14. Add page-specific body class for house board search bar widening
  - [x] 14.1 Add `page-houseboard` body class to `views/houseBoard.ejs`
    - Add `class="page-houseboard"` to the `<body>` tag so the CSS rule from task 3.3 takes effect
    - Verify the search bar retains all existing functionality (debounced search, dropdown, keyboard nav, outside-click-to-close)
    - _Requirements: 10.1, 10.2, 10.3_

- [x] 15. Final checkpoint — Full regression verification
  - Ensure all tests pass, ask the user if questions arise.
  - Verify all existing routes still work: `/`, `/rooms`, `/rooms/:id`, `/rooms/:id/review`, `/dorm/:dorm`, `/house/:dorm/:house`, `/house/:dorm/:house/board`, `/api/houses`, `/api/search`
  - Verify `/map` redirects to `/explore` and `/dorm-rankings` redirects to `/explore`
  - Verify authentication flows are unchanged
  - Verify all existing client-side filtering, sorting, and censorship toggle functionality is preserved
  - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

## Notes

- No property-based tests are included because the design document has no Correctness Properties section — these are UI/template changes
- The project uses Node.js/Express with EJS templates and a single CSS file — all changes are in the view layer and route definitions
- D3-cloud is loaded via CDN to avoid build tooling changes, consistent with how wordcloud2.js is already loaded
- The critical non-regression constraint (R13) is addressed by the final checkpoint and by ensuring each task only modifies the specified elements
- Each task references specific requirements for traceability
