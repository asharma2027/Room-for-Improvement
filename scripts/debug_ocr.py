import cv2
import pytesseract
import numpy as np
import os
import re

img_path = 'data/processed_floorplans/001_BJ_Salisbury_3_pdf_house_0.png'
img = cv2.imread(img_path)

ROOM_NUMBER_REGEX = re.compile(r'\b([0-9]{3,4}[A-Z]?)\b')
ROOM_KEYWORD_REGEX = re.compile(r'(Bath|RA\b|Lounge|Kitchen|Office|Ath)', re.IGNORECASE)

gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
binary = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
binary_for_color = binary.copy()

# Remove thin black lines (close the white background over black lines)
kernel = np.ones((2,2), np.uint8)
binary_clean = cv2.morphologyEx(binary, cv2.MORPH_CLOSE, kernel)

hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

def get_color_class(h, s, v):
    if s < 30: return "Grey", "Unavailable"
    if (h > 150 or h < 15): return "Pink", "Single"
    if 35 <= h <= 85: return "Green", "Double"
    if 15 <= h < 35: return "Orange", "Triple"
    if 85 < h <= 150: return "Blue", "Apartment"
    return "Unknown", "Unknown"

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

# Spatial grouping (MAX_DX=100, MAX_DY=40 helps keep nearby items together)
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

print("Groups found:")
for g in groups:
    sorted_words = sorted(g['words'], key=lambda w: (w['y']//10, w['x']))
    full_text = " ".join([w['text'] for w in sorted_words])
    
    # Check if keeping
    has_num = bool(ROOM_NUMBER_REGEX.findall(full_text))
    has_key = bool(ROOM_KEYWORD_REGEX.search(full_text))
    
    x1, y1, x2, y2 = g['x_min'], g['y_min'], g['x_max'], g['y_max']
    patch = binary_for_color[y1:y2, x1:x2]
    patch_hsv = hsv[y1:y2, x1:x2]
    mask = (patch == 255)
    
    if np.any(mask):
        bg_hsv = patch_hsv[mask]
        med_h, med_s, med_v = np.median(bg_hsv, axis=0)
        cname, rtype = get_color_class(med_h, med_s, med_v)
        
        if cname == "Grey" or cname == "Unknown":
            if has_num or has_key:
                print(f"[UNCOLORED] '{full_text}'")
        else:
            if has_num:
                print(f"[COLORED] '{full_text}' ({rtype})")
