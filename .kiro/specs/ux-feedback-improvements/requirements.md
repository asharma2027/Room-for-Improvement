# Requirements Document

## Introduction

This document specifies UX improvements to the "Room for Improvement" website — a UChicago dorm/housing information platform built with Node.js, Express, and EJS. The changes address 13 user-reported feedback items spanning animation tuning, labeling clarity, visual fixes, new pages, navigation enhancements, and layout refinements. All modifications must preserve existing functionality.

## Glossary

- **Preview_Pill**: A glassmorphic overlay element on the house page banner that displays rotating text snippets (trivia, quotes, tips) with swipe animations.
- **House_Page**: The page rendered at `/house/:dorm/:house` showing house details, stats, word clouds, filters, and a room table.
- **All_Rooms_Page**: The page rendered at `/rooms` listing all campus rooms with filter controls and a sortable table.
- **Room_Details_Page**: The page rendered at `/rooms/:id` displaying a single room's latest and historical submission data.
- **Landing_Page**: The home page rendered at `/` with a hero banner, feature panels, and a feedback form.
- **Nav_Bar**: The sticky top navigation bar rendered from `views/partials/nav.ejs`, present on all pages.
- **Stats_Bar**: The `house-stats-row` element on the House_Page displaying aggregate statistics (total rooms, reviews, culture, noise) directly below the house banner.
- **Word_Cloud**: A visual display of terms rendered via wordcloud2.js on the House_Page, showing either culture vibes (from checklist selections) or house descriptors (from free-text input).
- **Profanity_Toggle**: A toggle switch in the House_Page and All_Rooms_Page filter row that controls visibility of profane content in room names and notes.
- **Filter_Tags_Dropdown**: A dropdown UI component on the House_Page filter bar that lets users select room attribute tags to filter the room table.
- **Dorm_Rankings_Page**: An existing page at `/dorm/:dorm` showing per-dorm house rankings across five categories.
- **Campus_Dorm_Rankings_Page**: A new page comparing all dorms against each other at a glance, distinct from the per-dorm house rankings.
- **Rating_Color_Scale**: A five-level hex color mapping: #34877A (Excellent/5) → #92B89D (Good/4) → #EFE6D1 (Neutral/3) → #D69772 (Poor/2) → #AE5436 (Bad/1).
- **Dorm_Filter_Dropdown**: A new dropdown on the All_Rooms_Page that lists dorms as bold category headers, allowing users to filter rooms by dorm selection.
- **Ratings_Table**: The section on the Room_Details_Page displaying scalar ratings (Room Size, Natural Light, Outside Noise, Temperature Control, House Culture) for a room submission.

## Requirements

### Requirement 1: Slower Preview Pill Animations

**User Story:** As a user browsing a house page, I want the preview pill text to transition slower and less frequently, so that I can read the content comfortably before it changes.

#### Acceptance Criteria

1. WHEN the House_Page loads, THE Preview_Pill SHALL rotate its text content at an interval of no less than 12 seconds between transitions (increased from the current 5 seconds).
2. WHEN a Preview_Pill text transition occurs, THE Preview_Pill SHALL animate the swipe-up and slide-in phases over a duration of no less than 800 milliseconds each (increased from the current 400 milliseconds).
3. THE Preview_Pill SHALL preserve all existing hover, click, and navigation behaviors without modification.

### Requirement 2: Profanity Toggle Label

**User Story:** As a user viewing the house page filter row, I want a clear text label next to the profanity toggle, so that I understand what the 18+ toggle controls without guessing.

#### Acceptance Criteria

1. THE House_Page filter row SHALL display a text label reading "Profanity:" immediately to the left of the Profanity_Toggle, using the same font family, size, and weight as the "Floor:" label in the filter bar.
2. THE House_Page filter row SHALL display an info icon (ⓘ or equivalent SVG) adjacent to the "Profanity:" label.
3. WHEN a user hovers over or clicks the info icon, THE House_Page SHALL display a tooltip or popover explaining: "Toggles visibility of profane language in custom room names and notes. Some submissions contain adult language — this filter hides that content by default."
4. THE All_Rooms_Page profanity toggle area SHALL also display the same "Profanity:" label and info icon with the same tooltip behavior.

### Requirement 3: Word Cloud Hover Tooltips

**User Story:** As a user viewing word clouds on the house page, I want to see how many users selected each word when I hover over it, so that I understand the popularity behind each term.

#### Acceptance Criteria

1. WHEN a user hovers over a word in a Word_Cloud on the House_Page, THE Word_Cloud SHALL display a tooltip panel showing the word text and the number of users who submitted that word (e.g., "Friendly — 12 responses").
2. WHEN a user hovers over a word in a Word_Cloud, THE Word_Cloud SHALL increase the font size of that word by a visually noticeable amount (at least 15% larger) for the duration of the hover.
3. WHEN the user moves the cursor away from the word, THE Word_Cloud SHALL return the word to its original font size and hide the tooltip.
4. THE Word_Cloud hover behavior SHALL function for both the Culture Vibes word cloud and the House Descriptors word cloud.

### Requirement 4: Stats Bar Visual Fix

**User Story:** As a user viewing the house page, I want the stats bar to appear visually distinct from the banner image behind it, so that the interface looks clean and uncluttered.

#### Acceptance Criteria

1. THE Stats_Bar on the House_Page SHALL have an opaque white background (`#ffffff`) instead of the current semi-transparent `rgba(255,255,255,0.85)`.
2. THE House_Page SHALL set the house banner's `margin-bottom` to `0` (removing the current `-2rem` negative margin) so that the Stats_Bar does not visually overlap with the banner image.
3. THE Stats_Bar SHALL retain its existing border, border-radius, box-shadow, and padding values.
4. THE Stats_Bar on the All_Rooms_Page SHALL also use an opaque white background for visual consistency.

### Requirement 5: Dorm Filter Dropdown on All Rooms Page

**User Story:** As a user on the All Rooms page, I want a clickable dropdown that lists dorms as bold category headers, so that I can quickly filter rooms by dorm without confusion.

#### Acceptance Criteria

1. THE All_Rooms_Page SHALL replace the existing `<select>` element for "Filter by Dorm" with a Dorm_Filter_Dropdown component styled similarly to the Filter_Tags_Dropdown on the House_Page.
2. THE Dorm_Filter_Dropdown SHALL list each dorm name (e.g., "Max Palevsky", "Burton-Judson") as a bold, large-font category item.
3. WHEN a user clicks a dorm name in the Dorm_Filter_Dropdown, THE All_Rooms_Page SHALL filter the room table to show only rooms belonging to that dorm and populate the house filter dropdown with houses from the selected dorm.
4. WHEN a user clicks the currently selected dorm name again, THE All_Rooms_Page SHALL deselect the dorm filter and show all rooms.
5. THE Dorm_Filter_Dropdown SHALL close when the user clicks outside of it.
6. THE Dorm_Filter_Dropdown SHALL display a visual checkmark or highlight next to the currently selected dorm.

### Requirement 6: Room Details Ratings Table

**User Story:** As a user viewing room details, I want the ratings displayed in a clean, aligned table format, so that I can quickly scan and compare rating values.

#### Acceptance Criteria

1. THE Room_Details_Page SHALL display ratings (Room Size, Natural Light, Outside Noise, Temperature Control, House Culture) in a two-column table layout with the rating label left-aligned and the rating value right-aligned.
2. THE Ratings_Table SHALL display each rating value with its descriptive label (e.g., "Spacious") and numeric score (e.g., "4/5") in bold, right-aligned in the value column.
3. WHERE the Rating_Color_Scale is applicable, THE Ratings_Table SHALL color-code each rating value row using the corresponding hex color from the scale: #34877A for 5, #92B89D for 4, #EFE6D1 for 3, #D69772 for 2, #AE5436 for 1.
4. THE Ratings_Table SHALL replace the current `<ul class="stat-list">` markup with a structured `<table>` or CSS grid layout that enforces column alignment.

### Requirement 7: Landing Page Panels When Signed In

**User Story:** As a signed-in user on the landing page, I want quick-access panels for key site features, so that I can navigate to important pages and actions without extra clicks.

#### Acceptance Criteria

1. WHILE a user is authenticated, THE Landing_Page SHALL display the following panels in place of the current three feature panels:
   - A "Dorm Rankings" panel linking to the Campus_Dorm_Rankings_Page.
   - A "Campus Map" panel linking to `/map`.
   - A "Search Rooms" panel linking to `/rooms`.
   - A "Submit Room Info" panel containing a button or form that allows the user to quickly select a dorm, house, and room number, then navigate to the corresponding room review page.
   - A "Leave Feedback" panel containing a button that scrolls to or opens the feedback form.
2. WHILE a user is not authenticated, THE Landing_Page SHALL continue to display the existing three feature panels (Real Feedback, Smart Search, Data Driven) without modification.
3. THE authenticated Landing_Page panels SHALL use the same `feature-item` card styling as the existing panels.

### Requirement 8: Campus Dorm Rankings Page

**User Story:** As a user, I want a dorm rankings page that compares all dorms at a glance, so that I can evaluate which dorm is best overall before drilling into house-level rankings.

#### Acceptance Criteria

1. THE system SHALL provide a new route at `/dorm-rankings` that renders the Campus_Dorm_Rankings_Page.
2. THE Campus_Dorm_Rankings_Page SHALL display all dorms (Burton-Judson, I-House, Max Palevsky, Renee_Granville-Grossman, Snell_Hitchcock, Woodlawn) ranked by aggregate scores across categories (culture, quietness, sunlight, room size, temperature control).
3. THE Campus_Dorm_Rankings_Page SHALL use a visually distinct layout from the existing Dorm_Rankings_Page (e.g., horizontal bar chart, card grid, or comparison table) so that users do not confuse the two pages.
4. WHEN a user clicks on a dorm in the Campus_Dorm_Rankings_Page, THE system SHALL navigate to that dorm's existing house rankings page at `/dorm/:dorm`.
5. THE Campus_Dorm_Rankings_Page SHALL be accessible only to authenticated users.

### Requirement 9: Rating Color Scale

**User Story:** As a user viewing ratings, I want color-coded rating values, so that I can quickly assess quality at a glance.

#### Acceptance Criteria

1. THE system SHALL apply the Rating_Color_Scale to all numeric 1–5 rating displays where categorization is applicable: Room_Details_Page ratings, House_Page room table rating columns, and All_Rooms_Page rating columns.
2. THE Rating_Color_Scale SHALL map values as follows: 5 → #34877A (Excellent), 4 → #92B89D (Good), 3 → #EFE6D1 (Neutral, with dark text for contrast), 2 → #D69772 (Poor), 1 → #AE5436 (Bad).
3. THE color SHALL be applied as a background color or prominent visual indicator on the rating value element, with text color adjusted for readability (dark text on light backgrounds, light text on dark backgrounds).

### Requirement 10: Nav Bar Search

**User Story:** As a user, I want a search bar in the navigation bar, so that I can quickly find a specific house or room from any page.

#### Acceptance Criteria

1. THE Nav_Bar SHALL include a search input field visible to authenticated users, positioned between the navigation links and the Logout button.
2. WHEN a user types in the Nav_Bar search field, THE Nav_Bar SHALL display a dropdown of matching results showing house names and room numbers that match the query.
3. WHEN a user selects a house result from the dropdown, THE system SHALL redirect to the corresponding house page at `/house/:dorm/:house`.
4. WHEN a user selects a room result from the dropdown, THE system SHALL redirect to the corresponding room details page at `/rooms/:id`.
5. WHEN no results match the query, THE Nav_Bar search dropdown SHALL display a "No results found" message.
6. THE Nav_Bar search dropdown SHALL close when the user clicks outside of it or presses Escape.

### Requirement 11: Word Cloud Descriptions

**User Story:** As a user viewing word clouds on the house page, I want clear titles that explain the difference between culture vibes and house descriptors, so that I understand what each cloud represents.

#### Acceptance Criteria

1. THE House_Page Culture Vibes Word_Cloud section SHALL display a title of "Culture Vibes" with a subtitle explaining: "Selected from a fixed checklist by residents — shows the most commonly chosen descriptors."
2. THE House_Page House Descriptors Word_Cloud section SHALL display a title of "House Descriptors" with a subtitle explaining: "Written freely by residents — shows the most frequently used words and phrases."
3. THE Word_Cloud section titles SHALL use the existing `h3` styling from the `.word-cloud-section` class.
4. THE Word_Cloud subtitles SHALL use the existing `.word-cloud-sub` class styling.

### Requirement 12: Landing Page Scroll Fix

**User Story:** As a user visiting the landing page, I want all key content (hero, panels, feedback section) to fit on screen with minimal scrolling, so that I can see everything important at a glance.

#### Acceptance Criteria

1. THE Landing_Page hero section SHALL reduce its vertical padding so that the hero, feature panels, and feedback section are all visible with minimal scrolling on a standard 1080p viewport.
2. THE Landing_Page hero section SHALL reduce the `h1` font size and the paragraph bottom margin to create a more compact layout.
3. THE Landing_Page SHALL preserve all existing hero content (title, subtitle, buttons) without removing any elements.

### Requirement 13: Nav Bar Feedback Button

**User Story:** As a user, I want a "Leave Feedback" button in the navigation bar, so that I can quickly access the feedback form from any page.

#### Acceptance Criteria

1. WHILE a user is authenticated, THE Nav_Bar SHALL display a "Leave Feedback" button styled distinctly from other nav links (e.g., outlined or accent-colored button).
2. THE Nav_Bar SHALL arrange its elements in the following order for authenticated users: Logo ("Room for Improvement"), Search Bar, Campus Map, All Rooms, Dorm Rankings, Leave Feedback, Logout.
3. WHEN a user clicks the "Leave Feedback" button from the Landing_Page, THE system SHALL scroll to the feedback form section on the same page.
4. WHEN a user clicks the "Leave Feedback" button from any other page, THE system SHALL navigate to the Landing_Page and scroll to the feedback form section.
5. WHILE a user is not authenticated, THE Nav_Bar SHALL not display the "Leave Feedback" button.

### Requirement 14: Non-Regression Constraint

**User Story:** As a developer, I want all existing features to remain functional after these changes, so that no current user workflows are broken.

#### Acceptance Criteria

1. THE system SHALL preserve all existing routes (`/`, `/map`, `/rooms`, `/rooms/:id`, `/rooms/:id/review`, `/dorm/:dorm`, `/house/:dorm/:house`, `/house/:dorm/:house/board`, `/api/houses`) without modification to their core behavior.
2. THE system SHALL preserve all existing authentication flows (registration, email verification, login, logout) without modification.
3. THE system SHALL preserve all existing data reading and writing operations (rooms CSV, room entries JSON, users JSON, feedback JSON) without modification.
4. THE system SHALL preserve all existing client-side filtering, sorting, and censorship toggle functionality on the House_Page and All_Rooms_Page.
