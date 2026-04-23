# Requirements Document

## Introduction

This document specifies a second round of UX refinements to the "Room for Improvement" UChicago housing platform. The changes span text contrast improvements, layout adjustments, page consolidation, word cloud rendering upgrades, noise color scale inversion, sentiment-based word cloud coloring, and enhanced filtering on the All Rooms page. All modifications must preserve existing functionality — only the specified elements are changed.

## Glossary

- **Room_Details_Page**: The page rendered at `/rooms/:id` displaying a single room's latest and historical submission data.
- **House_Page**: The page rendered at `/house/:dorm/:house` showing house details, stats, word clouds, filters, and a room table.
- **All_Rooms_Page**: The page rendered at `/rooms` listing all campus rooms with filter controls and a sortable table.
- **Landing_Page**: The home page rendered at `/` with a hero banner, feature panels, and a feedback form.
- **Campus_Map_Page**: The page rendered at `/map` displaying an interactive SVG campus map with dorm buildings.
- **Dorm_Rankings_Page**: The page rendered at `/dorm-rankings` showing campus-wide dorm rankings with aggregate scores.
- **House_Board_Page**: The page rendered at `/house/:dorm/:house/board` showing trivia, tips, and quotes for a house.
- **Nav_Bar**: The sticky top navigation bar rendered from `views/partials/nav.ejs`, present on all pages.
- **Latest_Submission_Card**: The `#latest-submission-card` element on the Room_Details_Page displaying the most recent room submission's ratings, tags, and notes.
- **Ratings_Table**: The `<table class="ratings-table">` inside the Latest_Submission_Card displaying color-coded scalar ratings (Room Size, Natural Light, Outside Noise, Temperature Control, House Culture).
- **Rating_Color_Scale**: A five-level hex color mapping: #34877A (Excellent/5) → #92B89D (Good/4) → #EFE6D1 (Neutral/3) → #D69772 (Poor/2) → #AE5436 (Bad/1).
- **Noise_Color_Scale**: An inverted five-level color mapping for noise where 1 (quietest) maps to #34877A (green) and 5 (loudest) maps to #AE5436 (red), since higher noise is worse.
- **Word_Cloud**: A visual display of terms rendered on the House_Page, showing either culture vibes (from checklist selections) or house descriptors (from free-text input).
- **Culture_Word_Cloud**: The word cloud displaying culture vibes selected from a fixed checklist, rendered in `#culture-wordcloud`.
- **Descriptor_Word_Cloud**: The word cloud displaying house descriptors from free-text input, rendered in `#descriptor-wordcloud`.
- **D3_Cloud**: The `d3-cloud` library (d3.layout.cloud) used for word cloud layout computation, providing proper bounding-box-aware word placement and hover interactivity.
- **Filter_Tags_Dropdown**: The existing dropdown UI component on the House_Page filter bar that lets users select room attribute tags to filter the room table.
- **Dorm_Filter_Dropdown**: The existing custom dropdown on the All_Rooms_Page that lists dorms for filtering.
- **House_Filter_Dropdown**: A new dropdown on the All_Rooms_Page that lists houses grouped by dorm for filtering.
- **Feature_Panel**: A clickable card element (`a.feature-item`) on the Landing_Page providing quick access to site features.
- **Combined_Explore_Page**: A consolidated page merging the Campus_Map_Page and Dorm_Rankings_Page into a single unified view, accessible at `/explore`.
- **Quick_Access_Section**: The `<h3>` heading and dorm pill buttons section below the SVG map on the Campus_Map_Page.
- **Sentiment_Color_Scale**: A color gradient applied to word cloud words based on sentiment analysis, using the same green-to-red scale as the table rating columns (positive sentiment → green, negative sentiment → red, neutral → beige).

## Requirements

### Requirement 1: Improve Text Contrast in Latest Submission Ratings

**User Story:** As a user viewing room details, I want the rating text in the latest submission card to be clearly readable against the background colors, so that I can easily scan rating values without straining.

#### Acceptance Criteria

1. THE Ratings_Table on the Room_Details_Page SHALL display rating text with sufficient contrast against the Rating_Color_Scale background colors, ensuring a minimum WCAG AA contrast ratio of 4.5:1 for normal text.
2. WHEN a rating value of 5 is displayed (background #34877A), THE Ratings_Table SHALL use white (#ffffff) bold text for both the label and value cells.
3. WHEN a rating value of 4 is displayed (background #92B89D), THE Ratings_Table SHALL use dark text (#1a1a1a or darker) for both the label and value cells to ensure readability against the lighter green background.
4. WHEN a rating value of 3 is displayed (background #EFE6D1), THE Ratings_Table SHALL use dark text (#333333) for both the label and value cells.
5. WHEN a rating value of 2 is displayed (background #D69772), THE Ratings_Table SHALL use dark text (#1a1a1a or darker) for both the label and value cells to ensure readability against the tan/orange background.
6. WHEN a rating value of 1 is displayed (background #AE5436), THE Ratings_Table SHALL use white (#ffffff) bold text for both the label and value cells.
7. THE Ratings_Table SHALL apply `font-weight: 700` (bold) to all rating label and value text to further improve readability.

### Requirement 2: Increase Word Cloud Title and Description Text Size

**User Story:** As a user viewing word clouds on the house page, I want the word cloud titles and descriptions to be larger and more prominent, so that I can quickly understand what each cloud represents.

#### Acceptance Criteria

1. THE House_Page word cloud section `h3` titles ("Culture Vibes" and "House Descriptors") SHALL be displayed at a font size of at least 1.15rem (increased from the current 0.95rem in the two-column layout).
2. THE House_Page word cloud section `.word-cloud-sub` descriptions SHALL be displayed at a font size of at least 0.82rem (increased from the current 0.72rem in the two-column layout).
3. THE word cloud description text size SHALL remain visually smaller than the word cloud title text size.
4. THE word cloud titles and descriptions outside the two-column layout SHALL retain their existing sizes (1.15rem for titles, 0.85rem for descriptions).

### Requirement 3: Decrease Temp Control Column Width

**User Story:** As a user viewing the room table on the house page, I want the column widths to be properly sized so that the "Temp Control" label fits fully within the table bounds without being clipped.

#### Acceptance Criteria

1. THE House_Page room table column with `data-sort-key="tempControl"` SHALL have a reduced width that allows the "Temp Control" text to display fully within the visible table area.
2. THE House_Page room table rating columns (naturalLight, roomSize, noise, culture, tempControl) SHALL each have a maximum width of no more than 76px (reduced from the current 82px maximum).
3. THE column width reduction SHALL not cause rating value badges to overflow or clip.

### Requirement 4: Resize and Consolidate Landing Page Feature Panels

**User Story:** As a signed-in user on the landing page, I want the feature panels to fit in a single row without feeling cramped, and I want the Dorm Rankings and Campus Map panels combined into one since they are being consolidated into a single page.

#### Acceptance Criteria

1. WHILE a user is authenticated, THE Landing_Page SHALL display four Feature_Panels in a single row: "Explore Campus" (linking to the Combined_Explore_Page), "Search Rooms" (linking to `/rooms`), "Submit Room Info" (containing the dorm/house/room selector form), and "Leave Feedback" (scrolling to the feedback section).
2. THE "Explore Campus" Feature_Panel SHALL replace the separate "Dorm Rankings" and "Campus Map" panels, combining their functionality into a single panel with an appropriate icon and description.
3. THE Landing_Page `.features-grid` SHALL use a grid layout that fits all four panels in one row on viewports 1024px and wider, without any panel feeling visually compressed.
4. THE Feature_Panels SHALL maintain the existing `feature-item` card styling, hover effects, and glassmorphism appearance.
5. WHILE a user is not authenticated, THE Landing_Page SHALL continue to display the existing three feature panels (Real Feedback, Smart Search, Data Driven) without modification.

### Requirement 5: Consolidate Dorm Rankings and Campus Map Pages

**User Story:** As a user, I want the dorm rankings and campus map on a single page, so that I can explore dorms visually on the map and compare rankings without navigating between two separate pages.

#### Acceptance Criteria

1. THE system SHALL provide a new route at `/explore` that renders the Combined_Explore_Page, combining the campus map and dorm rankings into a single view.
2. THE Combined_Explore_Page SHALL display the interactive SVG campus map at the top of the page, preserving all existing click-to-navigate, hover effects, and search functionality from the current Campus_Map_Page.
3. THE Combined_Explore_Page SHALL display the dorm rankings card grid below the campus map, preserving all existing dorm score bars, card click-through to `/dorm/:dorm`, and Rating_Color_Scale coloring from the current Dorm_Rankings_Page.
4. THE Combined_Explore_Page SHALL use a clear, descriptive page title (e.g., "Explore Campus") that communicates both map and rankings functionality.
5. THE Combined_Explore_Page SHALL be accessible only to authenticated users.
6. THE existing `/map` route SHALL redirect to `/explore` so that existing links and bookmarks continue to work.
7. THE existing `/dorm-rankings` route SHALL redirect to `/explore` so that existing links and bookmarks continue to work.

### Requirement 6: Remove Quick Access Section from Map

**User Story:** As a user viewing the combined explore page, I want a clean layout without redundant navigation elements, so that the page is not cluttered with unnecessary buttons.

#### Acceptance Criteria

1. THE Combined_Explore_Page SHALL NOT display the Quick_Access_Section (the `<h3>` heading "Quick Access — All Dorms" and the dorm pill buttons below the SVG map) that currently exists on the Campus_Map_Page.
2. THE Combined_Explore_Page SHALL retain the SVG campus map, the map header bar, and the house search bar from the current Campus_Map_Page.

### Requirement 7: Update Navigation Bar for Page Consolidation

**User Story:** As a user, I want the navigation bar to reflect the consolidated dorm rankings and campus map page, so that I can find the combined page easily.

#### Acceptance Criteria

1. WHILE a user is authenticated, THE Nav_Bar SHALL display a single "Explore Campus" link pointing to `/explore`, replacing the separate "Campus Map" and "Dorm Rankings" links.
2. THE Nav_Bar SHALL arrange its elements in the following order for authenticated users: Logo ("Room for Improvement"), Search Bar, Explore Campus, All Rooms, Leave Feedback, Logout.
3. THE "Explore Campus" Nav_Bar link SHALL display an active state when the current path is `/explore`.
4. WHILE a user is not authenticated, THE Nav_Bar SHALL not display the "Explore Campus" link.

### Requirement 8: Invert Noise Color Scale

**User Story:** As a user viewing noise ratings, I want a noise value of 5 (loudest) to appear red and a noise value of 1 (quietest) to appear green, so that the color intuitively communicates that higher noise is worse.

#### Acceptance Criteria

1. THE House_Page room table noise column SHALL apply the Noise_Color_Scale: 1 → #34877A (green/quiet), 2 → #92B89D (light green), 3 → #EFE6D1 (neutral), 4 → #D69772 (orange/loud), 5 → #AE5436 (red/loudest).
2. THE All_Rooms_Page room table noise column SHALL apply the same Noise_Color_Scale as the House_Page.
3. THE Room_Details_Page "Outside Noise" rating row in the Ratings_Table SHALL apply the Noise_Color_Scale instead of the standard Rating_Color_Scale.
4. THE House_Page room table noise column header label SHALL read "Noise Level" instead of "Noise".
5. THE All_Rooms_Page room table noise column header label SHALL read "Noise Level" instead of "Noise".
6. THE text color on noise rating badges SHALL maintain readability: white text on values 1 and 5 (dark backgrounds), dark text on values 2, 3, and 4 (lighter backgrounds).

### Requirement 9: Rewrite Descriptor Word Cloud with D3-Cloud

**User Story:** As a user viewing the house descriptors word cloud, I want words to enlarge smoothly within the cloud itself when I hover over them, and I want the tooltip to clearly state how many students mentioned each word.

#### Acceptance Criteria

1. THE Descriptor_Word_Cloud on the House_Page SHALL be rendered using the D3_Cloud library (d3.layout.cloud) instead of wordcloud2.js, providing SVG-based word placement.
2. WHEN a user hovers over a word in the Descriptor_Word_Cloud, THE word SHALL visually enlarge within the word cloud in real time using an SVG transform, without requiring a full re-render of the cloud.
3. WHEN a user hovers over a word in the Descriptor_Word_Cloud, THE system SHALL display a tooltip reading "[word in bold]: according to [x] students" where x is the number of responses for that word.
4. WHEN the user moves the cursor away from a word, THE word SHALL return to its original size and the tooltip SHALL hide.
5. THE Descriptor_Word_Cloud SHALL preserve the existing word tokenization logic (keeping short phrases intact, splitting longer text into individual words, filtering stopwords).
6. THE Culture_Word_Cloud SHALL continue to use the existing wordcloud2.js rendering without modification.

### Requirement 10: Widen House Board Search Bar

**User Story:** As a user on the house board page, I want the search bar to be wider so that I can type longer search queries comfortably.

#### Acceptance Criteria

1. THE Nav_Bar search input on the House_Board_Page SHALL have its left edge extended approximately 50% of its current width further to the left, while maintaining approximately the same right edge position.
2. THE widened search bar SHALL not overlap with or obscure adjacent Nav_Bar elements (logo, navigation links).
3. THE search bar SHALL retain all existing functionality (debounced search, dropdown results, keyboard navigation, outside-click-to-close).

### Requirement 11: Sentiment-Based Word Cloud Coloring

**User Story:** As a user viewing the culture word cloud, I want words colored by sentiment (positive words in green, negative words in red, neutral in beige), so that I can quickly gauge the overall vibe of a house.

#### Acceptance Criteria

1. THE Culture_Word_Cloud on the House_Page SHALL color each word based on sentiment analysis, using the same green-to-red color gradient as the table rating columns (Rating_Color_Scale).
2. THE sentiment analysis SHALL classify words into positive (green tones: #34877A, #92B89D), neutral (beige: #EFE6D1), and negative (red/orange tones: #D69772, #AE5436) categories.
3. THE sentiment classification SHALL use a predefined mapping of common culture descriptor words to sentiment scores, since the culture vibes come from a fixed checklist of known terms.
4. WHEN a culture descriptor word is not found in the predefined sentiment mapping, THE Culture_Word_Cloud SHALL default to a neutral color (#EFE6D1 with dark text).
5. THE Descriptor_Word_Cloud (free-text) SHALL also apply sentiment-based coloring using the same color scale, with a basic sentiment heuristic for free-text words.

### Requirement 12: Dual Filter Dropdowns on All Rooms Page

**User Story:** As a user on the All Rooms page, I want separate dropdown menus for filtering by dorm and by house, with the house dropdown showing houses grouped by dorm, so that I can quickly narrow down rooms.

#### Acceptance Criteria

1. THE All_Rooms_Page SHALL display two filter dropdown buttons: "Filter by Dorm" and "Filter by Houses", styled consistently with the existing Dorm_Filter_Dropdown.
2. WHEN a user clicks "Filter by Houses" without first selecting a dorm, THE House_Filter_Dropdown SHALL display all houses across all dorms, with dorm names as bold, unclickable category headers and individual houses listed underneath each dorm header.
3. WHEN a user clicks "Filter by Dorm" first and selects one or more dorms, THEN clicks "Filter by Houses", THE House_Filter_Dropdown SHALL display only houses within the selected dorms, with dorm names as bold category headers.
4. WHEN a user selects a house from the House_Filter_Dropdown, THE All_Rooms_Page SHALL filter the room table to show only rooms belonging to that house.
5. WHEN a user clicks a currently selected house again, THE All_Rooms_Page SHALL deselect that house filter.
6. THE House_Filter_Dropdown SHALL display a visual checkmark next to currently selected houses.
7. THE House_Filter_Dropdown SHALL close when the user clicks outside of it.
8. THE existing Dorm_Filter_Dropdown functionality (select dorm, deselect, checkmark, outside-click-to-close) SHALL be preserved without modification.
9. WHEN a dorm filter is changed after houses have been selected, THE system SHALL clear any house selections that no longer belong to the selected dorms.

### Requirement 13: Non-Regression Constraint

**User Story:** As a developer, I want all existing features to remain functional after these changes, so that no current user workflows are broken.

#### Acceptance Criteria

1. THE system SHALL preserve all existing routes (`/`, `/rooms`, `/rooms/:id`, `/rooms/:id/review`, `/dorm/:dorm`, `/house/:dorm/:house`, `/house/:dorm/:house/board`, `/api/houses`, `/api/search`) without modification to their core behavior.
2. THE system SHALL preserve all existing authentication flows (registration, email verification, login, logout) without modification.
3. THE system SHALL preserve all existing data reading and writing operations (rooms CSV, room entries JSON, users JSON, feedback JSON) without modification.
4. THE system SHALL preserve all existing client-side filtering, sorting, and censorship toggle functionality on the House_Page and All_Rooms_Page.
5. THE system SHALL ensure that `/map` and `/dorm-rankings` routes redirect to `/explore` so that existing bookmarks and links continue to function.
