import pytesseract
from PIL import Image
import os

# Target image
IMAGE_PATH = 'data/processed_floorplans/011_BJ_Linn_Mathews_4_pdf_May_10__2021_by_A_Prior_Coll_house_0.png'

def main():
    if not os.path.exists(IMAGE_PATH):
        print(f"File not found: {IMAGE_PATH}")
        return

    print(f"--- Processing {IMAGE_PATH} ---")
    img = Image.open(IMAGE_PATH)
    
    # Try different PSM modes
    for psm in [3, 6, 11]:
        print(f"\n--- PSM {psm} ---")
        try:
            text = pytesseract.image_to_string(img, config=f'--psm {psm}')
            print(text)
        except Exception as e:
            print(e)

if __name__ == "__main__":
    main()
