import sys
from PIL import Image
import math

def test_image(img_path):
    img = Image.open(img_path).convert('RGB')
    width, height = img.size
    pixels = img.load()

    min_x = width
    max_x = 0
    min_y = height
    max_y = 0
    found = False

    margin_x = math.floor(width * 0.05)
    margin_y = math.floor(height * 0.05)
    edge_threshold_x = margin_x + 15
    edge_threshold_y = margin_y + 15

    for y in range(margin_y, height - margin_y, 4):
        for x in range(margin_x, width - margin_x, 4):
            r, g, b = pixels[x, y]
            max_ch = max(r, g, b)
            min_ch = min(r, g, b)

            if max_ch - min_ch > 40:
                is_inner_marker = False
                if r > g + 40 and r > b + 40 and g < 150:
                    is_inner_marker = True
                if g > r + 40 and g > b + 40:
                    is_inner_marker = True
                
                if not is_inner_marker:
                    white_bg_count = 0
                    map_bg_count = 0
                    check_radius = 8
                    
                    for ny in range(max(0, y - check_radius), min(height - 1, y + check_radius) + 1, 2):
                        for nx in range(max(0, x - check_radius), min(width - 1, x + check_radius) + 1, 2):
                            nr, ng, nb = pixels[nx, ny]
                            n_max = max(nr, ng, nb)
                            n_min = min(nr, ng, nb)
                            n_chroma = n_max - n_min
                            
                            if n_chroma < 40 or (nr > 220 and ng > 220 and nb > 220):
                                if nr > 245 and ng > 245 and nb > 245:
                                    white_bg_count += 1
                                else:
                                    map_bg_count += 1
                                    
                    is_text_label = (white_bg_count > 5 and map_bg_count < white_bg_count / 2)
                    
                    if not is_text_label:
                        if x < min_x: min_x = x
                        if x > max_x: max_x = x
                        if y < min_y: min_y = y
                        if y > max_y: max_y = y
                        found = True

    print(f"Image: {img_path}")
    print(f"Size: {width}x{height}")
    print(f"Margins: X={margin_x}, Y={margin_y}")
    print(f"Thresholds: X={edge_threshold_x}, Y={edge_threshold_y} | Max allowed X={width - edge_threshold_x}, Max allowed Y={height - edge_threshold_y}")
    print(f"Found: {found}")
    
    if found:
        print(f"Bounds: minX={min_x}, maxX={max_x}, minY={min_y}, maxY={max_y}")
        cut_off = False
        if min_x <= edge_threshold_x or max_x >= width - edge_threshold_x or min_y <= edge_threshold_y or max_y >= height - edge_threshold_y:
            cut_off = True
        print(f"cutOff triggered: {cut_off}")
    print("---")

test_image('/Users/arjun/Downloads/Room for Improvement/data/floorplans/010_BJ_Linn_Mathews_3_pdf.png')
test_image('/Users/arjun/Downloads/Room for Improvement/data/floorplans/011_BJ_Linn_Mathews_4_pdf.png')
test_image('/Users/arjun/Downloads/Room for Improvement/data/floorplans/018_BJ_Coulter_3_pdf.png')
