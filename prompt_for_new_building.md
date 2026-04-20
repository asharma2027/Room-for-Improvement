Extract both **colored** and **uncolored/grey** room info from floorplan screenshots for a specific building into two CSVs.

**Input:** `data/floorplans/<BuildingName>/processed/` 
(Format: `[Index]_[Initials]_[HouseName]_[FloorNumber]_pdf_house_0.png`)

**Outputs:** 
1. `data/floorplans/<BuildingName>/colored_rooms.csv` 
(Columns: `Room Number,Floor,Building Name,House Name,Room Type,Original Image`)
2. `data/floorplans/<BuildingName>/uncolored_rooms.csv`
(Columns: `Full Text,Floor,Building Name,House Name,Original Image`)

**General Rules for Both:**
1. Floor is the integer (e.g., `3`, not `pdf`). House Name excludes floor number.
2. **Only extract rooms *inside* the bright colored boundary polygon.**
3. Do not merge separate distinct rooms due to OCR grouping errors.

**Colored Rooms (`colored_rooms.csv`) Rules:**
1. Room Number is alphanumeric only (e.g. "848"). Exclude types like "Single" from this column.
2. Room Type must match text exactly. No hallucinated types (e.g., "Apartment").
3. **Adjacent Blank Squares:** If a labeled colored room has an attached unlabeled colored square (e.g., a bathroom), treat it as part of the labeled room. Do not create a hallucinated room entry.

**Uncolored / Grey Rooms (`uncolored_rooms.csv`) Rules:**
1. Record the *complete* text block grouping exactly as shown (e.g., "RA 847", "Bathroom All Gender").
2. Include all grey-colored rooms/areas as long as they fall *within* the colored polygon bounds.

**Workflow:**
Visually inspect each image -> compile a local dictionary -> write a Python script to generate both CSVs -> report ambiguous cases.
