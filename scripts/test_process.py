import cv2
import numpy as np

img = cv2.imread('data/new_link_preview.png')
hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
mask = cv2.inRange(hsv, np.array([0, 30, 0]), np.array([180, 255, 255]))

kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5,5))
mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel)

contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

valid_cnts = [cnt for cnt in contours if cv2.contourArea(cnt) >= 5000]
print(f"Found {len(valid_cnts)} valid contours (area >= 5000)")

if valid_cnts:
    all_x = []
    all_y = []
    
    for i, cnt in enumerate(valid_cnts):
        x, y, w, h = cv2.boundingRect(cnt)
        print(f"  Contour {i}: x={x}, y={y}, w={w}, h={h}, area={cv2.contourArea(cnt)}")
        all_x.extend([x, x+w])
        all_y.extend([y, y+h])
        
    minX, maxX = min(all_x), max(all_x)
    minY, maxY = min(all_y), max(all_y)
    
    print(f"Global Bounding Box of all valid contours: x={minX}, y={minY}, w={maxX - minX}, h={maxY - minY}")
else:
    print("No valid contours found.")
