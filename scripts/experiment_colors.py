import cv2
import pytesseract
import numpy as np
import os
import glob

INPUT_DIR = os.path.join('data', 'processed_floorplans')

def process():
    files = glob.glob(os.path.join(INPUT_DIR, '*.png'))
    if not files:
        print("No processed files found.")
        return

    # Let's just process the first 2 files for calibration
    for filepath in files[:2]:
        print(f"\n--- Processing {os.path.basename(filepath)} ---")
        img = cv2.imread(filepath)
        if img is None: continue

        # 1. Binarize for OCR
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        binary = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)

        # 2. Convert original to HSV for sampling
        hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

        # 3. OCR Data
        d = pytesseract.image_to_data(binary, config='--psm 11', output_type=pytesseract.Output.DICT)
        
        n_boxes = len(d['level'])
        for i in range(n_boxes):
            text = d['text'][i].strip()
            if not text: continue
            
            x, y, w, h = d['left'][i], d['top'][i], d['width'][i], d['height'][i]
            
            # 4. Sample background color in the bounding box
            # Get the binary patch. Text is usually black (0), Background is white (255)
            # Actually, because of adaptive threshold, background might have noise.
            # We want to sample pixels where binary == 255.
            patch_binary = binary[y:y+h, x:x+w]
            patch_hsv = hsv[y:y+h, x:x+w]
            
            mask = (patch_binary == 255)
            # If mask is empty (all text), fallback to whole patch
            if not np.any(mask):
                continue
                
            bg_pixels_hsv = patch_hsv[mask]
            
            # Calculate median H, S, V
            median_h = np.median(bg_pixels_hsv[:, 0])
            median_s = np.median(bg_pixels_hsv[:, 1])
            median_v = np.median(bg_pixels_hsv[:, 2])
            
            print(f"'{text}': HSV=({int(median_h)}, {int(median_s)}, {int(median_v)})")

if __name__ == "__main__":
    process()
