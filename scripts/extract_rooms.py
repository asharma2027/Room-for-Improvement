import cv2
import pytesseract
import numpy as np
import os
import glob
import csv
import re

# Configuration
INPUT_DIR = os.path.join('data', 'processed_floorplans')
COLORED_CSV = os.path.join('data', 'colored_rooms.csv')
UNCOLORED_CSV = os.path.join('data', 'uncolored_rooms.csv')

# Regex for room numbers "820A", "304", etc.
ROOM_NUMBER_REGEX = re.compile(r'\b([0-9]{3,4}[A-Z]?)\b')
ROOM_KEYWORD_REGEX = re.compile(r'(Bath|RA\b|Lounge|Kitchen|Office|Ath|athr|athrop)', re.IGNORECASE)

def parse_filename_metadata(filename):
    """Extracts Building, House, and Floor from filename."""
    parts = filename.split('_')
    building = "Unknown"
    house = "Unknown"
    floor = "Unknown"

    if len(parts) >= 3:
        if parts[1] == "BJ": building = "Burton-Judson"
        else: building = parts[1]
        
        floor_index = -1
        for i in range(2, len(parts)):
            if parts[i].isdigit():
                floor_index = i
                break
                
        if floor_index != -1:
            floor = parts[floor_index]
            house_parts = parts[2:floor_index]
            house = " ".join(house_parts)
        else:
            if len(parts) > 2: house = parts[2]
            
    return building, house, floor

def get_color_class(h, s, v):
    """Map HSV median to a room type from the Legend."""
    if s < 30:
        return "Grey", "Unavailable"
    if (h > 150 or h < 15):
        return "Pink", "Single"
    if 35 <= h <= 85:
        return "Green", "Double"
    if 15 <= h < 35:
        return "Orange", "Triple"
    if 85 < h <= 150:
        return "Blue", "Apartment"
        
    return "Unknown", "Unknown"

def process():
    print(f"Starting execution. Scanning {INPUT_DIR}...")
    files = glob.glob(os.path.join(INPUT_DIR, '*.png'))
    if not files:
        print("No processed files found.")
        return

    colored_rooms = []
    uncolored_rooms = []

    for filepath in files:
        filename = os.path.basename(filepath)
        building, house, floor = parse_filename_metadata(filename)
        
        # Load images
        img = cv2.imread(filepath)
        if img is None: continue

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        binary = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        binary_for_color = binary.copy()
        
        # Morphological closing to repair text sliced by black lines
        kernel = np.ones((2,2), np.uint8)
        binary_clean = cv2.morphologyEx(binary, cv2.MORPH_CLOSE, kernel)
        
        hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

        # OCR
        d = pytesseract.image_to_data(binary_clean, config='--psm 11', output_type=pytesseract.Output.DICT)
        
        words = []
        for i in range(len(d['level'])):
            text = d['text'][i].strip()
            if not text: continue
            words.append({
                'text': text,
                'x': d['left'][i], 'y': d['top'][i],
                'w': d['width'][i], 'h': d['height'][i],
                'cx': d['left'][i] + d['width'][i]//2,
                'cy': d['top'][i] + d['height'][i]//2,
            })

        # Spatial grouping
        MAX_DX = 120
        MAX_DY = 50
        groups = []

        for w in words:
            added = False
            for g in groups:
                for wg in g['words']:
                    dx = abs(w['cx'] - wg['cx'])
                    dy = abs(w['cy'] - wg['cy'])
                    if dx < MAX_DX and dy < MAX_DY:
                        g['words'].append(w)
                        g['x_min'] = min(g['x_min'], w['x'])
                        g['y_min'] = min(g['y_min'], w['y'])
                        g['x_max'] = max(g['x_max'], w['x']+w['w'])
                        g['y_max'] = max(g['y_max'], w['y']+w['h'])
                        added = True
                        break
                if added: break
            if not added:
                groups.append({
                    'words': [w],
                    'x_min': w['x'], 'y_min': w['y'],
                    'x_max': w['x']+w['w'], 'y_max': w['y']+w['h']
                })
                
        # Analyze blocks
        for g in groups:
            sorted_words = sorted(g['words'], key=lambda w: (w['y']//10, w['x']))
            full_text = " ".join([w['text'] for w in sorted_words]).strip()
            
            # Filter noise (years)
            if full_text.startswith("202"): continue
            
            # Find Room Number or specific keyword
            room_matches = ROOM_NUMBER_REGEX.findall(full_text)
            has_keyword = bool(ROOM_KEYWORD_REGEX.search(full_text))

            # Check Color
            x1, y1 = g['x_min'], g['y_min']
            x2, y2 = g['x_max'], g['y_max']
            
            patch_binary = binary_for_color[y1:y2, x1:x2]
            patch_hsv = hsv[y1:y2, x1:x2]
            mask = (patch_binary == 255)
            
            if not np.any(mask):
                continue
                
            bg_hsv = patch_hsv[mask]
            med_h, med_s, med_v = np.median(bg_hsv, axis=0)
            
            color_name, room_type = get_color_class(med_h, med_s, med_v)
            
            if color_name == "Grey" or color_name == "Unknown":
                # Uncolored: We need full words + room number OR a recognized keyword
                if room_matches or has_keyword:
                    uncolored_rooms.append({
                        'Full Text': full_text,
                        'Floor': floor,
                        'Building Name': building,
                        'House Name': house,
                        'Original Image': filename
                    })
            else:
                # Colored: We ONLY want room numbers and derived room_type
                if room_matches:
                    for r_num in room_matches:
                        colored_rooms.append({
                        'Room Number': r_num,
                        'Floor': floor,
                        'Building Name': building,
                        'House Name': house,
                        'Room Type': room_type,
                        'Original Image': filename
                    })

    # Saving Colored CSV
    with open(COLORED_CSV, 'w', newline='') as f:
        fields = ['Room Number', 'Floor', 'Building Name', 'House Name', 'Room Type', 'Original Image']
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in colored_rooms: writer.writerow(r)
        
    print(f"Saved {len(colored_rooms)} colored rooms to {COLORED_CSV}")

    # Saving Uncolored CSV
    with open(UNCOLORED_CSV, 'w', newline='') as f:
        fields = ['Full Text', 'Floor', 'Building Name', 'House Name', 'Original Image']
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in uncolored_rooms: writer.writerow(r)
        
    print(f"Saved {len(uncolored_rooms)} uncolored rooms to {UNCOLORED_CSV}")

if __name__ == "__main__":
    process()
