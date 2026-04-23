# Implementation Plan: UX Feedback Improvements

## Overview

This plan implements 13 UX improvements to the "Room for Improvement" UChicago housing platform. Tasks are ordered: foundational CSS/utility changes first, then page-specific modifications, then new routes/pages, then cross-cutting navigation enhancements. All changes are additive or surgically scoped to preserve existing functionality.

## Tasks

- [x] 1. Foundational CSS and utility changes
  - [x] 1.1 Add rating color scale CSS classes and inline helper function
    - Add CSS classes `.rating-bg-1` through `.rating-bg-5` with the Rating_Color_Scale hex values (#AE5436, #D69772, #EFE6D1, #92B89D, #34877A) and appropriate text colors (#fff for 1,2,4,5 and #333 for 3)
    - Define a reusable inline JS helper `ratingColor(val)` and `ratingTextColor(val)` that can be included in EJS templates
    - Add `.ratings-table` CSS styles to `public/css/styles.css` for the new table layout (two-column, left-aligned labels, right-aligned values, row background coloring)
    - _Requirements: 9.1, 9.2, 9.3_

  - [ ]* 1.2 Write property test for rating color scale mapping (Property 1)
    - **Property 1: Rating Color Scale Mapping**
    - Install `fast-check` as a dev dependency and create test file `tests/ratingColor.property.test.js`
    - For any integer rating value in {1, 2, 3, 4, 5}, verify `ratingColor` returns the correct background color and `ratingTextColor` returns the correct text color
    - **Validates: Requirements 6.3, 9.1, 9.2, 9.3**

  - [x] 1.3 Add stats bar visual fix CSS
    - Override `.house-stats-row` background to `#ffffff` (opaque white) in `public/css/styles.css`
    - Remove `margin-bottom: -2rem` from `.house-banner` by adding `margin-bottom: 0` override
    - Retain existing border, border-radius, box-shadow, and padding on `.house-stats-row`
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [x] 1.4 Add profanity toggle label and tooltip CSS
    - Add `.profanity-toggle-group`, `.profanity-label`, `.profanity-info-icon`, and `.profanity-tooltip` styles to `public/css/styles.css`
    - Style the tooltip as a CSS `:hover::after` pseudo-element or positioned child span
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 1.5 Add landing page scroll fix CSS
    - Reduce `.landing-hero` padding from `6rem 2rem` to `3rem 2rem` in `public/css/styles.css`
    - Reduce `.landing-hero h1` font size from `3.5rem` to `2.5rem`
    - Reduce `.landing-hero p` bottom margin for a more compact layout
    - Preserve all existing hero content (title, subtitle, buttons)
    - _Requirements: 12.1, 12.2, 12.3_

  - [x] 1.6 Add dorm filter dropdown CSS
    - Add `.dorm-filter-dropdown-wrapper`, `.dorm-filter-item`, and related styles to `public/css/styles.css`, styled similarly to the existing `.filter-tags-dropdown` on the house page
    - Include checkmark indicator and bold dorm name styling
    - _Requirements: 5.1, 5.2, 5.6_

  - [x] 1.7 Add nav bar search and feedback button CSS
    - Add `.nav-search-wrapper`, `.nav-search-input`, `.nav-search-dropdown`, `.nav-search-result`, and `.nav-feedback-btn` styles to `public/css/styles.css`
    - Style the search dropdown as a positioned absolute panel below the search input
    - Style the feedback button as an outlined/accent-colored button distinct from other nav links
    - _Requirements: 10.1, 13.1_

  - [x] 1.8 Add campus dorm rankings page CSS
    - Add `.dorm-rankings-grid`, `.dorm-rank-card`, `.dorm-score-bar`, and related styles to `public/css/styles.css`
    - Use a card grid layout visually distinct from the existing per-dorm house rankings page
    - _Requirements: 8.3_

- [x] 2. Checkpoint - Ensure CSS changes compile and don't break existing pages
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. House page modifications (housePage.ejs)
  - [x] 3.1 Slow down preview pill animations
    - In `views/housePage.ejs` inline `<script>`, change the `setInterval` duration from ~5000ms to 12000ms for pill text rotation
    - In the inline `<style>`, change `.preview-pill-text.swiping-up` and `.preview-pill-text.visible` transition durations from `0.4s` to `0.8s`
    - Preserve all existing hover, click, and navigation behaviors
    - _Requirements: 1.1, 1.2, 1.3_

  - [x] 3.2 Add profanity toggle label to house page filter row
    - Wrap the existing profanity toggle in a `.profanity-toggle-group` div in `views/housePage.ejs`
    - Add `<span class="profanity-label">Profanity:</span>` and an info icon `<span class="profanity-info-icon">ⓘ</span>` with tooltip text explaining the toggle's purpose
    - Match font family, size, and weight of the existing "Floor:" label
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.3 Add word cloud hover tooltips
    - In `views/housePage.ejs` inline `<script>`, add the `hover` callback to both wordcloud2.js `WordCloud()` calls
    - Create a floating tooltip `<div>` that shows word text and count (e.g., "Friendly — 12 responses") positioned at cursor
    - On hover, increase the hovered word's font size by at least 15% using a CSS overlay or redraw
    - On mouse-out, hide tooltip and restore original font size
    - Ensure tooltips work for both Culture Vibes and House Descriptors word clouds
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [x] 3.4 Apply stats bar visual fix to house page
    - In `views/housePage.ejs`, ensure the `.house-stats-row` uses the opaque white background (via CSS class, no inline override needed if CSS from 1.3 applies)
    - Remove or override the `margin-bottom: -2rem` on the `.house-banner` element (update inline style if present)
    - _Requirements: 4.1, 4.2, 4.3_

  - [x] 3.5 Update word cloud titles and descriptions
    - Change the Culture Vibes word cloud `<h3>` title to "Culture Vibes" and subtitle to "Selected from a fixed checklist by residents — shows the most commonly chosen descriptors."
    - Change the House Descriptors word cloud `<h3>` title to "House Descriptors" and subtitle to "Written freely by residents — shows the most frequently used words and phrases."
    - Use existing `.word-cloud-section h3` and `.word-cloud-sub` class styling
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [x] 3.6 Apply rating color scale to house page room table
    - In `views/housePage.ejs`, apply the `ratingColor()` and `ratingTextColor()` helpers to the Culture, Noise, and any other 1-5 rating columns in the room table
    - Set background-color and text color on rating value elements using inline styles computed from the helper
    - _Requirements: 9.1, 9.2, 9.3_

- [x] 4. All Rooms page modifications (rooms.ejs)
  - [x] 4.1 Add profanity toggle label to All Rooms page
    - Wrap the existing profanity toggle in a `.profanity-toggle-group` div in `views/rooms.ejs`
    - Add the same "Profanity:" label and info icon with tooltip as on the house page
    - _Requirements: 2.4_

  - [x] 4.2 Replace dorm filter select with custom dropdown
    - In `views/rooms.ejs`, replace the `<select id="dorm-filter">` with a custom `.dorm-filter-dropdown-wrapper` component
    - Render each dorm name as a bold, large-font `.dorm-filter-item` inside a positioned dropdown panel
    - Implement click-to-select (filters table + populates house dropdown), click-again-to-deselect, outside-click-to-close, and checkmark indicator for active selection
    - Wire the new dropdown to the existing `onDormChange()` and `applyFilters()` functions
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 4.3 Apply stats bar visual fix to All Rooms page
    - Ensure the `.house-stats-row` on `views/rooms.ejs` uses the opaque white background
    - _Requirements: 4.4_

  - [x] 4.4 Apply rating color scale to All Rooms page table
    - In `views/rooms.ejs`, apply the `ratingColor()` and `ratingTextColor()` helpers to the Culture and Noise rating columns
    - Set background-color and text color on rating value elements
    - _Requirements: 9.1, 9.2, 9.3_

- [x] 5. Room Details page modifications (roomDetails.ejs)
  - [x] 5.1 Replace ratings list with structured ratings table
    - In `views/roomDetails.ejs`, replace the `<ul class="stat-list">` in the "Ratings (1–5)" section with a `<table class="ratings-table">` or CSS grid layout
    - Each row has a left-aligned rating label and a right-aligned value cell showing descriptive label + numeric score in bold (e.g., "Spacious (4/5)")
    - Apply the Rating_Color_Scale as background-color on each row using the `ratingColor()` helper, with text color from `ratingTextColor()`
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [x] 5.2 Apply rating color scale to Room Details page
    - Ensure all 1-5 rating displays on the Room Details page use the Rating_Color_Scale colors
    - This includes the latest submission ratings and any historical data rating displays
    - _Requirements: 9.1, 9.2, 9.3_

- [x] 6. Checkpoint - Verify all page-specific changes render correctly
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. New server routes and pages
  - [x] 7.1 Add search API endpoint to server.js
    - Add `GET /api/search?q=` route to `server.js` behind `ensureAuthenticated`
    - The handler calls `readRooms()`, filters rooms by query string (case-insensitive substring match on house name and room number), and returns JSON array of `{ type, name, dorm, url }` objects
    - Deduplicate house-type results (only one entry per dorm::house pair)
    - Return empty array for empty query or file read errors
    - Limit results to 20 items
    - _Requirements: 10.2, 10.3, 10.4, 10.5_

  - [ ]* 7.2 Write property test for search result relevance (Property 3)
    - **Property 3: Search Result Relevance**
    - Create test file `tests/searchRelevance.property.test.js`
    - For any non-empty query string and any dataset of rooms, verify every result has a name containing the query as a case-insensitive substring, and no duplicate house-type results exist
    - **Validates: Requirements 10.2**

  - [x] 7.3 Add campus dorm rankings route and handler to server.js
    - Add `GET /dorm-rankings` route to `server.js` behind `ensureAuthenticated`
    - The handler calls `readRooms()` and `readRoomEntries()`, computes per-dorm aggregate scores by averaging house-level scores from `computeDormRankings()` across categories (culture, quietness, sunlight, roomSize, tempControl)
    - Pass `dormScores` and `dormScoresJson` to the `dormRankingsAll` template
    - Handle null scores (skip nulls in averaging; if all null, dorm score is null)
    - _Requirements: 8.1, 8.2, 8.5_

  - [ ]* 7.4 Write property test for dorm aggregate score computation (Property 2)
    - **Property 2: Dorm Aggregate Score Computation**
    - Create test file `tests/dormAggregate.property.test.js`
    - For any set of house ranking objects with nullable scores, verify the dorm-level aggregate equals the arithmetic mean of non-null house scores per category, and is null when all house scores are null
    - **Validates: Requirements 8.2**

  - [x] 7.5 Create campus dorm rankings page template
    - Create `views/dormRankingsAll.ejs` with a card grid layout showing all dorms ranked by aggregate scores
    - Each dorm card displays the dorm name, aggregate scores as colored bars or badges using the Rating_Color_Scale, and house count
    - Each card links to the existing per-dorm house rankings page at `/dorm/:dorm`
    - Include a "No data available" message when `dormScores` is empty
    - Display "—" for null category scores
    - Use a visually distinct layout from the existing `dormRankings.ejs` (card grid vs. 5-column scrollable lists)
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 8. Checkpoint - Verify new routes return correct responses
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Navigation bar enhancements (nav.ejs)
  - [x] 9.1 Add search bar to navigation
    - In `views/partials/nav.ejs`, add a search input field (`.nav-search-wrapper`) visible only to authenticated users, positioned between navigation links and the Logout button
    - Add a dropdown container (`.nav-search-dropdown`) that is populated via `fetch('/api/search?q=...')` on the `input` event with 300ms debouncing
    - Display matching results showing house/room name and dorm; clicking a result navigates to the URL
    - Show "No results found" when no matches exist
    - Close dropdown on outside click or Escape key press
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_

  - [x] 9.2 Add "Leave Feedback" button to navigation
    - In `views/partials/nav.ejs`, add a "Leave Feedback" link styled as an outlined/accent button for authenticated users
    - Arrange nav elements in order: Logo, Search Bar, Campus Map, All Rooms, Dorm Rankings, Leave Feedback, Logout
    - On the landing page (`path === '/'`): use `href="#feedback-section"` with smooth scroll
    - On other pages: use `href="/#feedback-section"` to navigate to landing page and scroll to anchor
    - Hide the button for unauthenticated users
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

  - [x] 9.3 Add "Dorm Rankings" link to navigation
    - In `views/partials/nav.ejs`, add a "Dorm Rankings" link pointing to `/dorm-rankings` for authenticated users
    - Position it in the nav order as specified: after "All Rooms" and before "Leave Feedback"
    - _Requirements: 13.2_

- [x] 10. Landing page modifications (index.ejs)
  - [x] 10.1 Add authenticated user panels to landing page
    - In `views/index.ejs`, wrap the `.features-grid` in an EJS conditional on `user`
    - When `user` is truthy, render five panels: "Dorm Rankings" (links to `/dorm-rankings`), "Campus Map" (links to `/map`), "Search Rooms" (links to `/rooms`), "Submit Room Info" (mini form with dorm/house/room selectors using `/api/houses` to populate options client-side), "Leave Feedback" (button scrolling to `#feedback-section`)
    - When `user` is falsy, render the existing three panels unchanged
    - Use the same `.feature-item` card styling as existing panels
    - _Requirements: 7.1, 7.2, 7.3_

  - [x] 10.2 Add feedback section anchor
    - Add `id="feedback-section"` to the feedback form container `<div>` in `views/index.ejs`
    - This enables the nav bar "Leave Feedback" button to scroll to the form
    - _Requirements: 13.3, 13.4_

  - [x] 10.3 Apply landing page scroll fix
    - Update the `.landing-hero` inline styles in `views/index.ejs` to use reduced padding (if inline styles override CSS)
    - Ensure the hero, feature panels, and feedback section are visible with minimal scrolling on a 1080p viewport
    - Preserve all existing hero content
    - _Requirements: 12.1, 12.2, 12.3_

- [x] 11. Final checkpoint - Ensure all tests pass and all features work end-to-end
  - Ensure all tests pass, ask the user if questions arise.
  - Verify all existing routes (`/`, `/map`, `/rooms`, `/rooms/:id`, `/rooms/:id/review`, `/dorm/:dorm`, `/house/:dorm/:house`, `/house/:dorm/:house/board`, `/api/houses`) still return expected responses
  - Verify new routes (`/dorm-rankings`, `/api/search`) work correctly for authenticated users and redirect for unauthenticated users
  - Verify no existing client-side filtering, sorting, or censorship toggle functionality is broken
  - _Requirements: 14.1, 14.2, 14.3, 14.4_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using `fast-check`
- Unit tests validate specific examples and edge cases
- All changes are additive or modify only the specific elements described — no existing features should break
- The project uses Node.js, Express, EJS templates, vanilla CSS, and vanilla JavaScript — no build tools or frontend frameworks
