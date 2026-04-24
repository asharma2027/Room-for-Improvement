# Requirements Document

## Introduction

This feature makes the "Room for Improvement" UChicago housing guide fully functional and visually polished on mobile devices (320px–768px). The site currently has partial responsive support (~40%) with some flexbox/grid usage and three breakpoints, but critical components — navigation, data tables, the SVG campus map, filter UIs, word clouds, and preview pills — break or become unusable on small screens. This specification covers a hamburger menu, responsive tables, scalable map, touch-optimized controls, and consistent spacing across all pages.

## Glossary

- **Navigation_Bar**: The sticky header element (`nav.ejs`) containing the site logo, search input, page links, and authentication actions.
- **Hamburger_Menu**: A collapsible mobile navigation pattern using a toggle button (three horizontal lines icon) that reveals the Navigation_Bar links in a vertical overlay or slide-in panel.
- **Room_Table**: The `<table>` elements on the house page (`housePage.ejs`) and all-rooms page (`rooms.ejs`) displaying room data with sortable columns, tags, and rating values.
- **Card_View**: An alternative mobile layout for Room_Table rows where each row renders as a stacked card with labeled fields instead of a horizontal table row.
- **Campus_Map**: The inline SVG element (`#campus-svg`) on the explore page (`explore.ejs`) showing UChicago dorm buildings as clickable shapes.
- **Filter_Bar**: The `.room-filters` container on the house page and all-rooms page containing floor selects, room-type tag buttons, has-review checkbox, active tag chips, and clear button.
- **Word_Cloud**: The canvas-based word cloud sections on the house page rendered via the wordcloud2 library, displaying culture notes and house descriptors.
- **Preview_Pill**: The absolutely positioned glassmorphism overlay elements on the house page banner showing trivia, quotes, tips, and a back button.
- **Touch_Target**: Any interactive element (button, link, checkbox, radio) that a user taps on a touchscreen device.
- **Breakpoint**: A CSS media query threshold at which the layout adapts. The system uses breakpoints at 480px, 600px, 768px, and 900px.
- **Stats_Row**: The `.house-stats-row` element displaying inline statistics (total rooms, reviews, avg culture, avg noise) below page banners.
- **Rankings_Board**: The 5-column grid (`#rankings-board`) on the dorm rankings page (`dormRankings.ejs`) showing sorted house rankings per category.
- **Dorm_Rankings_Grid**: The card grid (`.dorm-rankings-grid`) on the explore page showing dorm comparison cards with score bars.
- **SD_Strip**: The semantic differential radio strip (`.sd-strip`) on the room review form (`roomReview.ejs`) with 5 radio options and labels.
- **Viewport**: The visible area of the web page on the user's device screen.

## Requirements

### Requirement 1: Mobile Navigation with Hamburger Menu

**User Story:** As a mobile user, I want a hamburger menu that collapses the navigation links, so that the Navigation_Bar fits on small screens without wrapping or overflowing.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE Navigation_Bar SHALL hide the inline link list and display a Hamburger_Menu toggle button.
2. WHEN the user taps the Hamburger_Menu toggle button, THE Navigation_Bar SHALL display all navigation links in a vertical overlay panel.
3. WHEN the user taps the Hamburger_Menu toggle button while the overlay is open, THE Navigation_Bar SHALL close the overlay panel.
4. WHEN the overlay panel is open, THE Navigation_Bar SHALL display the search input at full width within the overlay.
5. THE Hamburger_Menu toggle button SHALL have a minimum Touch_Target size of 44×44 CSS pixels.
6. WHEN the user taps a navigation link inside the overlay, THE Navigation_Bar SHALL close the overlay and navigate to the selected page.
7. WHEN the user taps outside the overlay panel, THE Navigation_Bar SHALL close the overlay.

### Requirement 2: Responsive Data Tables with Card View

**User Story:** As a mobile user, I want room data displayed as stacked cards on small screens, so that I can read room information without horizontal scrolling.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE Room_Table SHALL render each table row as a Card_View with vertically stacked labeled fields.
2. THE Card_View SHALL display the room name, dorm, house, floor, room type, tags, culture rating, and noise rating as labeled key-value pairs.
3. WHEN the user taps a Card_View element, THE system SHALL navigate to the corresponding room detail page.
4. WHILE the Viewport width is greater than 768px, THE Room_Table SHALL display in the standard horizontal table layout.
5. THE Card_View SHALL preserve all sorting and filtering functionality available in the table layout.

### Requirement 3: Scalable Campus Map

**User Story:** As a mobile user, I want the campus map to scale and remain interactive on small screens, so that I can tap dorm buildings to explore them.

#### Acceptance Criteria

1. THE Campus_Map SVG SHALL scale proportionally to fill the available container width on all Viewport sizes.
2. WHEN the Viewport width is 600px or less, THE Campus_Map SHALL increase the tap target area of each dorm building group to a minimum of 44×44 CSS pixels.
3. WHEN the Viewport width is 600px or less, THE Campus_Map SHALL increase dorm label font sizes by a factor of at least 1.3 to maintain readability.
4. WHEN a user taps a dorm building on a touch device, THE Campus_Map SHALL navigate to the corresponding dorm page.
5. WHEN the Viewport width is 480px or less, THE Campus_Map legend SHALL reposition below the map instead of overlaying the bottom-left corner.

### Requirement 4: Touch-Optimized Filter Controls

**User Story:** As a mobile user, I want filter controls that are easy to tap and use on a touchscreen, so that I can filter rooms without accidentally tapping the wrong control.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE Filter_Bar SHALL stack its controls vertically instead of in a single horizontal row.
2. THE Filter_Bar room-type tag buttons SHALL have a minimum Touch_Target size of 44px height on screens 768px or narrower.
3. WHEN the Viewport width is 768px or less, THE Filter_Bar dropdown panels (dorm filter, house filter, tag filter) SHALL expand to full container width.
4. THE Filter_Bar select elements SHALL have a minimum height of 44px and a minimum font size of 16px on screens 768px or narrower to prevent iOS zoom on focus.
5. WHEN the Viewport width is 768px or less, THE Filter_Bar clear button SHALL appear as a full-width button at the bottom of the filter stack.

### Requirement 5: Responsive Word Clouds

**User Story:** As a mobile user, I want word clouds to be readable on small screens, so that I can understand house culture and descriptor data.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE Word_Cloud two-column layout (`.word-cloud-row`) SHALL stack into a single column.
2. WHEN the Viewport width is 768px or less, THE Word_Cloud canvas height SHALL reduce to 180px to fit the mobile layout.
3. IF the Word_Cloud canvas fails to render on a mobile device, THEN THE system SHALL display the CSS fallback word cloud (`.word-cloud-fallback`) with readable font sizes.
4. THE Word_Cloud fallback words SHALL have a minimum font size of 14px on screens 480px or narrower.

### Requirement 6: Responsive Preview Pills on House Banner

**User Story:** As a mobile user, I want the house page banner content to be accessible without overlapping elements, so that I can read and tap preview pills.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE Preview_Pill elements SHALL reposition from absolute corner placement to a stacked layout below the banner content.
2. THE Preview_Pill elements SHALL have a minimum Touch_Target height of 44px on screens 768px or narrower.
3. WHEN the Viewport width is 480px or less, THE house banner SHALL reduce its vertical padding to 1.5rem and the house name font size to 1.75rem.
4. WHEN the Viewport width is 768px or less, THE house board button SHALL display at full width below the house name.

### Requirement 7: Consistent Mobile Spacing and Typography

**User Story:** As a mobile user, I want consistent and compact spacing on small screens, so that content is readable without excessive scrolling.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE main content area SHALL use horizontal padding of 1rem instead of the desktop value of 2rem.
2. WHEN the Viewport width is 768px or less, THE h1 elements SHALL use a font size of 1.75rem instead of the desktop value of 2.5rem.
3. WHEN the Viewport width is 768px or less, THE `.stat-card` and `.feature-item` elements SHALL use padding of 1.25rem instead of the desktop value of 2rem.
4. WHEN the Viewport width is 480px or less, THE body font size SHALL remain at 1rem to maintain readability.
5. THE footer SHALL use reduced padding of 1rem on screens 768px or narrower.

### Requirement 8: Responsive Stats Row

**User Story:** As a mobile user, I want the stats row below page banners to be readable without horizontal scrolling, so that I can see room counts and ratings.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE Stats_Row SHALL wrap its stat items into multiple rows instead of a single non-wrapping horizontal line.
2. WHEN the Viewport width is 768px or less, THE Stats_Row inline search form SHALL display on its own row at full width below the stat items.
3. WHEN the Viewport width is 480px or less, THE Stats_Row stat labels SHALL use a font size of 0.65rem and stat values SHALL use a font size of 1rem.

### Requirement 9: Responsive Rankings Board

**User Story:** As a mobile user, I want the dorm rankings columns to be viewable on small screens, so that I can compare house rankings.

#### Acceptance Criteria

1. WHEN the Viewport width is 900px or less, THE Rankings_Board SHALL display in a 2-column grid layout.
2. WHEN the Viewport width is 600px or less, THE Rankings_Board SHALL display in a single-column layout.
3. WHEN the Viewport width is 768px or less, THE Rankings_Board emblem strip SHALL allow horizontal scrolling instead of wrapping to multiple rows.
4. WHEN the Viewport width is 768px or less, THE Rankings_Board scrollable list height SHALL reduce to 320px.

### Requirement 10: Responsive Explore Page

**User Story:** As a mobile user, I want the explore page search bar and rankings grid to work on small screens, so that I can search for houses and compare dorms.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE explore page search bar SHALL display at full width below the description text instead of inline beside the description.
2. WHEN the Viewport width is 768px or less, THE explore page search bar SHALL remove the fixed `min-width:320px` and `flex:0 0 360px` inline styles.
3. WHEN the Viewport width is 600px or less, THE Dorm_Rankings_Grid SHALL display in a single-column layout.
4. THE explore page map header bar SHALL wrap its text content on screens 480px or narrower without clipping.

### Requirement 11: Responsive Room Review Form

**User Story:** As a mobile user, I want the room review form to be easy to fill out on a touchscreen, so that I can submit reviews without difficulty.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE SD_Strip radio options SHALL display with increased spacing (minimum 44px between tap targets).
2. WHEN the Viewport width is 480px or less, THE SD_Strip sub-labels SHALL be hidden to reduce visual clutter.
3. WHEN the Viewport width is 768px or less, THE room review form grid (academic year and custom name fields) SHALL stack into a single column.
4. WHEN the Viewport width is 768px or less, THE culture descriptor chips SHALL use a minimum height of 44px per chip.
5. WHEN the Viewport width is 768px or less, THE v2 tag grid SHALL display in a single column layout.

### Requirement 12: Responsive Room Detail Page

**User Story:** As a mobile user, I want the room detail page to display properly on small screens, so that I can view room ratings and history.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE room detail header (room name and submit review button) SHALL stack vertically instead of side-by-side.
2. WHEN the Viewport width is 768px or less, THE ratings table SHALL use full container width with compact padding (0.5rem).
3. WHEN the Viewport width is 480px or less, THE custom room name (`.custom-room-name`) SHALL use a font size of 2rem instead of 3.2rem.

### Requirement 13: Responsive Landing Page

**User Story:** As a mobile user, I want the landing page hero and feature cards to display properly on my phone, so that I can navigate the site.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE landing hero section SHALL use padding of 2rem 1rem and the hero heading SHALL use a font size of 1.75rem.
2. WHEN the Viewport width is 480px or less, THE landing buttons SHALL stack vertically with full-width buttons.
3. WHEN the Viewport width is 768px or less, THE features grid SHALL display in a single-column layout.
4. WHEN the Viewport width is 768px or less, THE submit room info panel cascading selects SHALL use full width within the feature card.

### Requirement 14: Responsive Authentication Pages

**User Story:** As a mobile user, I want the login and register forms to be usable on small screens, so that I can authenticate without layout issues.

#### Acceptance Criteria

1. WHEN the Viewport width is 480px or less, THE login and register form containers SHALL use horizontal margin of 1rem instead of auto-centering with a fixed max-width.
2. THE login and register form input fields SHALL have a minimum font size of 16px to prevent iOS auto-zoom on focus.
3. THE login and register form submit buttons SHALL span full container width on all Viewport sizes.

### Requirement 15: Responsive House Board Page

**User Story:** As a mobile user, I want the house board page to display trivia, tips, and quotes properly on small screens, so that I can read community content.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE top info section (`.top-info-section`) SHALL stack the trivia and tips columns vertically.
2. WHEN the Viewport width is 768px or less, THE chatter bubbles SHALL display in a single-column layout at full container width.
3. WHEN the Viewport width is 768px or less, THE board identity strip SHALL wrap the back button below the house name if space is insufficient.
4. THE chatter bubble text SHALL use a minimum font size of 0.85rem on screens 480px or narrower.

### Requirement 16: Minimum Touch Target Sizes

**User Story:** As a mobile user, I want all interactive elements to be large enough to tap accurately, so that I do not accidentally tap the wrong control.

#### Acceptance Criteria

1. THE system SHALL ensure all Touch_Target elements (buttons, links, checkboxes, radio inputs) have a minimum size of 44×44 CSS pixels on screens 768px or narrower.
2. THE Navigation_Bar links inside the Hamburger_Menu overlay SHALL have a minimum height of 48px with vertical padding.
3. THE tag elements (`.tag`) in Room_Table Card_View SHALL have a minimum height of 32px.
4. IF a Touch_Target element is smaller than 44×44 CSS pixels on a screen 768px or narrower, THEN THE system SHALL increase its padding or size to meet the minimum.

### Requirement 17: Inline Style Overrides for Mobile

**User Story:** As a developer, I want inline styles with fixed widths to be overridden on mobile, so that elements do not overflow the Viewport.

#### Acceptance Criteria

1. WHEN the Viewport width is 768px or less, THE system SHALL override the explore page search bar inline `min-width:320px` and `flex:0 0 360px` to `min-width:0` and `flex:1 1 100%`.
2. WHEN the Viewport width is 768px or less, THE system SHALL override the Stats_Row inline `flex-wrap:nowrap` to `flex-wrap:wrap`.
3. WHEN the Viewport width is 768px or less, THE system SHALL override any inline `width:200px` on search inputs to `width:100%`.
4. THE system SHALL use CSS `!important` declarations in media queries only when overriding inline styles that cannot be refactored in EJS templates.
