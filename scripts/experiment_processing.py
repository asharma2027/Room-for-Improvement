import cv2
import pytesseract
import numpy as np
import os

INPUT_FILE = "data/floorplans/011_BJ_Linn_Mathews_4_pdf_May_10__2021_by_A_Prior_Coll.jpg"
OUTPUT_DIR = "data/experiment"

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def ocr(image, name):
    print(f"\n--- OCR for {name} ---")
    text = pytesseract.image_to_string(image, config='--psm 6') # Assume block of text
    print(text[:500]) # First 500 chars

    text_sparse = pytesseract.image_to_string(image, config='--psm 11') # Sparse
    print(f"\n[PSM 11]:\n{text_sparse[:500]}")

def process():
    ensure_dir(OUTPUT_DIR)
    img = cv2.imread(INPUT_FILE)
    if img is None:
        print("Image not found")
        return

    # 1. Extract House (assume largest contour logic from before)
    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
    mask = cv2.inRange(hsv, np.array([0, 30, 0]), np.array([180, 255, 255]))
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        print("No house found")
        return
    cnt = max(contours, key=cv2.contourArea)
    x, y, w, h = cv2.boundingRect(cnt)
    crop = img[y:y+h, x:x+w]

    # Variant 1: Original Crop
    cv2.imwrite(f"{OUTPUT_DIR}/v1_orig.png", crop)
    ocr(crop, "Original Crop")

    # Variant 2: Gray + 2x
    gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
    gray_2x = cv2.resize(gray, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)
    cv2.imwrite(f"{OUTPUT_DIR}/v2_gray_2x.png", gray_2x)
    ocr(gray_2x, "Gray + 2x")

    # Variant 3: Gray + 2x + Otsu (Current approach)
    # Adding unsharp mask first
    blurred = cv2.GaussianBlur(gray_2x, (5, 5), 1.0)
    sharpened = cv2.addWeighted(gray_2x, 2.5, blurred, -1.5, 0)
    _, otsu = cv2.threshold(sharpened, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    cv2.imwrite(f"{OUTPUT_DIR}/v3_otsu.png", otsu)
    ocr(otsu, "Gray + 2x + Sharpen + Otsu")

    # Variant 4: Gray + 2x + Adaptive Threshold
    adaptive = cv2.adaptiveThreshold(gray_2x, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
    cv2.imwrite(f"{OUTPUT_DIR}/v4_adaptive.png", adaptive)
    ocr(adaptive, "Gray + 2x + Adaptive")

    # Variant 5: Gray + 3x + Sharpen (No Threshold) - Let Tesseract handle binarization
    gray_3x = cv2.resize(gray, None, fx=3.0, fy=3.0, interpolation=cv2.INTER_CUBIC)
    blurred_3x = cv2.GaussianBlur(gray_3x, (0, 0), 3)
    sharpened_3x = cv2.addWeighted(gray_3x, 1.5, blurred_3x, -0.5, 0)
    cv2.imwrite(f"{OUTPUT_DIR}/v5_gray_3x_sharp.png", sharpened_3x)
    ocr(sharpened_3x, "Gray + 3x + Sharpen (No Threshold)")

if __name__ == "__main__":
    process()
