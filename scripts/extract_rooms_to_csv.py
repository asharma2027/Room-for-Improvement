import pytesseract
from PIL import Image
import os
import glob
import csv
import re

# Configuration
INPUT_DIR = os.path.join('data', 'processed_floorplans')
OUTPUT_CSV = os.path.join('data', 'rooms_extracted.csv')

# Regular expressions for room parsing
# Matches "SINGLE 820A", "Double 304", "Bathroom 201", "RA Apartment 101"
# Also handles cases with weak OCR spacing like "SINGLE820A"
# Matches "SINGLE 820A", "Double 304", "Bathroom 201", "RA Apartment 101"
# Robust to OCR errors like "Singte", "Doubte", "Bathream"
# S[il1]ng -> Single
# D[ou0]b -> Double
# Tr[il1]p -> Triple
# Su[il1]t -> Suite
# B[a@]th -> Bathroom/Bath
# Kit -> Kitchen
# Off -> Office
ROOM_WITH_PREFIX_REGEX = re.compile(r'(S[il1]ng[l1t]e|D[ou0]ub[l1t]e|Tr[il1]p[l1t]e|Su[il1]te|B[a@]th[rn]?[o0]{0,2}m?|RA\s*A[pP]t|RA\s*Apartment|K[il1]tchen|Lounge|Off[il1]ce)[\s\.:-]*([0-9]+[A-Z]*)', re.IGNORECASE)

# Matches just a room number: "820A", "304"
ROOM_NUMBER_ONLY_REGEX = re.compile(r'\b([0-9]{3,4}[A-Z]?)\b')

def normalize_room_type(text):
    text = text.lower()
    if 'sin' in text: return 'Single'
    if 'dou' in text: return 'Double'
    if 'tri' in text: return 'Triple'
    if 'sui' in text: return 'Suite'
    if 'bat' in text: return 'Bathroom'
    if 'kit' in text: return 'Kitchen'
    if 'off' in text: return 'Office'
    if 'ra' in text: return 'RA Apartment'
    return text.title()

def parse_filename_metadata(filename):
    """
    Extracts Building, House, and Floor from filename.
    Format example: 001_BJ_Salisbury_3_pdf_...
    """
    parts = filename.split('_')
    
    # Default values
    building = "Unknown"
    house = "Unknown"
    floor = "Unknown"

    if len(parts) >= 3:
        # Heuristic: 
        # parts[1] is usually Building (BJ)
        if parts[1] == "BJ":
            building = "Burton-Judson"
        else:
            building = parts[1]
        
        # Look for the floor number (usually a single digit) starting from index 2
        floor_index = -1
        for i in range(2, len(parts)):
            # Check if part is a digit (e.g., "3", "4")
            # Sometimes floor might be "3rd" or similar, but here it seems to be just digit
            if parts[i].isdigit():
                floor_index = i
                break
        
        if floor_index != -1:
            floor = parts[floor_index]
            # House is everything between index 1 and floor_index
            house_parts = parts[2:floor_index]
            house = " ".join(house_parts) # e.g. "Linn Mathews"
        else:
            # Fallback if no digit found: use the part after building as house
            if len(parts) > 2:
                house = parts[2]
    
    return building, house, floor

def extract_text_from_image(image_path):
    try:
        img = Image.open(image_path)
        # psm 6: Assume a single uniform block of text. 
        # psm 11: Sparse text. Find as much text as possible in no particular order.
        # Let's try 11 for scattered room labels.
        text = pytesseract.image_to_string(img, config='--psm 11')
        return text
    except Exception as e:
        print(f"Error OCRing {image_path}: {e}")
        return ""

def parse_rooms_from_text(text):
    found_rooms = []
    
    # Split text into lines to process line-by-line or regionally if possible
    # But since image_to_string flattens it, regex on the whole block is easier/safer
    
    # 1. Find explicit room types (High confidence)
    # 1. Find explicit room types (High confidence)
    for match in ROOM_WITH_PREFIX_REGEX.finditer(text):
        raw_type = match.group(1)
        room_type = normalize_room_type(raw_type)
        room_number = match.group(2)        # e.g. 820A
        full_name = f"{room_type} {room_number}"
        found_rooms.append(full_name)

    # 2. Find numbers that weren't caught by the above (Backfill)
    # This is trickier because we don't want to double count or catch "2021" from date
    for match in ROOM_NUMBER_ONLY_REGEX.finditer(text):
        number = match.group(1)
        
        # Filter out common false positives (like years usually present in headers)
        if number.startswith("202"): # 2021, 2025 etc
            continue

        # Check if this number is already part of a found room
        already_found = False
        for room in found_rooms:
            if number in room:
                already_found = True
                break
        
        if not already_found:
             # If it's just a number, we treat it as a room. 
             # We might default to "Room [Number]" or just "[Number]"
             found_rooms.append(number)

    return list(set(found_rooms)) # Dedup

def main():
    print(f"Starting extraction from {INPUT_DIR}...")
    
    # Prepare CSV
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        fieldnames = ['Room Name', 'Floor', 'Building Name', 'House Name', 'Original Image']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Get images
        types = ('*.jpg', '*.png', '*.jpeg')
        files_grabbed = []
        for files in types:
            files_grabbed.extend(glob.glob(os.path.join(INPUT_DIR, files)))

        path_count = 0
        room_count = 0

        for filepath in files_grabbed:
            filename = os.path.basename(filepath)
            
            # 1. Metadata from filename
            building, house, floor = parse_filename_metadata(filename)
            
            # 2. OCR Text
            text = extract_text_from_image(filepath)
            
            # 3. Parse Rooms
            rooms = parse_rooms_from_text(text)
            
            if not rooms:
                print(f"Warning: No rooms found in {filename}")
                # Optional: Write a row with empty room name to track processing?
                # writer.writerow({
                #    'Room Name': 'NO_TEXT_FOUND',
                #    'Floor': floor,
                #    'Building Name': building,
                #    'House Name': house,
                #    'Original Image': filename
                # })
            
            for room in rooms:
                writer.writerow({
                    'Room Name': room,
                    'Floor': floor,
                    'Building Name': building,
                    'House Name': house,
                    'Original Image': filename
                })
                room_count += 1
            
            path_count += 1
            if path_count % 5 == 0:
                print(f"Processed {path_count} images...")

    print(f"Done! Processed {path_count} images. Found {room_count} potential rooms.")
    print(f"Saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
