import cv2
import numpy as np
import os
import glob

# Configuration
INPUT_DIR = os.path.join('data', 'floorplans')
OUTPUT_DIR = os.path.join('data', 'processed_floorplans')
LOWER_SATURATION_THRESHOLD = 30  # Filter out grayscale
MIN_CONTOUR_AREA = 5000  # Ignore small noise

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def unsharp_mask(image, kernel_size=(5, 5), sigma=1.0, amount=1.5, threshold=0):
    """Return a sharpened version of the image, using an unsharp mask."""
    blurred = cv2.GaussianBlur(image, kernel_size, sigma)
    sharpened = float(amount + 1) * image - float(amount) * blurred
    sharpened = np.maximum(sharpened, 0)
    sharpened = np.minimum(sharpened, 255)
    return sharpened.astype(np.uint8)

def process_floorplan(filepath):
    filename = os.path.basename(filepath)
    print(f"Processing: {filename}")
    
    # Load image
    img = cv2.imread(filepath)
    if img is None:
        print(f"Error: Could not load {filepath}")
        return

    # Convert to HSV to detect colored regions
    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
    
    # Create valid mask: Saturation > threshold (identifies colored parts)
    # Floor plan lines are usually black/gray (low saturation)
    lower_bound = np.array([0, LOWER_SATURATION_THRESHOLD, 0])
    upper_bound = np.array([180, 255, 255])
    mask = cv2.inRange(hsv, lower_bound, upper_bound)

    # Clean up mask with closing
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5,5))
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel)

    # Find contours
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    count = 0
    for i, cnt in enumerate(contours):
        area = cv2.contourArea(cnt)
        if area < MIN_CONTOUR_AREA:
            continue

        # Get bounding box
        x, y, w, h = cv2.boundingRect(cnt)
        
        # Add a small padding
        padding = 10
        x = max(0, x - padding)
        y = max(0, y - padding)
        w = min(img.shape[1] - x, w + 2 * padding)
        h = min(img.shape[0] - y, h + 2 * padding)

        # Crop
        crop = img[y:y+h, x:x+w]

        # --- Enhancement Pipeline ---
        
        # 1. Upscale (2x) for better text resolution
        crop_large = cv2.resize(crop, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)

        # 2. Convert to Grayscale
        gray = cv2.cvtColor(crop_large, cv2.COLOR_BGR2GRAY)

        # 3. Thresholding (Adaptive)
        # Adaptive thresholding works better for varying lighting/contrast
        # and helps isolate text without being too harsh
        binary = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)

        # Optional: Denoise
        # binary = cv2.fastNlMeansDenoising(binary, None, 10, 7, 21)

        # Save output
        name, ext = os.path.splitext(filename)
        output_filename = f"{name}_house_{count}.png"
        output_path = os.path.join(OUTPUT_DIR, output_filename)
        cv2.imwrite(output_path, binary)
        
        count += 1
        print(f"  Saved crop: {output_filename}")

    if count == 0:
        print("  No colored regions found.")

def main():
    ensure_dir(OUTPUT_DIR)
    # Process all images in INPUT_DIR
    types = ('*.jpg', '*.png', '*.jpeg')
    files_grabbed = []
    for files in types:
        files_grabbed.extend(glob.glob(os.path.join(INPUT_DIR, files)))

    if not files_grabbed:
        print(f"No images found in {INPUT_DIR}")
        return

    for filepath in files_grabbed:
        process_floorplan(filepath)

if __name__ == "__main__":
    main()
