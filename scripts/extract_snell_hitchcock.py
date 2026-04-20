import csv
import os

images_data = [
    {
        "filename": "001_Snell_Floor_2_pdf_house_0.png",
        "singles": ["217", "226", "222", "225", "223", "224"],
        "doubles": ["220"],
        "triples": [],
        "apartments": [],
        "ra_rooms": [],
        "uncolored": ["Bathroom 218 Men", "RH Apartment 211"]
    },
    {
        "filename": "002_Hitchcock_Floor_3_pdf_house_0.png",
        "singles": ["314", "315", "313", "312", "311", "310", "344", "345", "346", "343", "347"],
        "doubles": ["321", "322", "323", "324", "325", "326", "341", "342"],
        "triples": [],
        "apartments": [],
        "ra_rooms": [],
        "uncolored": ["Bathroom 327", "Bathroom All Gender 328", "Bathroom 348 All Gender", "RA 340"]
    },
    {
        "filename": "003_Hitchcock_Floor_2_pdf_house_0.png",
        "singles": ["124", "125", "123", "122", "522", "523", "524", "525", "523A"],
        "doubles": ["121", "127", "222", "221", "223", "224", "322", "321", "323", "324", "423", "421", "424", "526"],
        "triples": [],
        "apartments": [],
        "ra_rooms": [],
        "uncolored": ["Women Bathroom 128", "Bathroom 225", "Bathroom 325", "Bathroom 425", "Women Bathroom 527"]
    },
    {
        "filename": "004_Hitchcock_Floor_1_pdf_house_0.png",
        "singles": ["114", "115", "113", "111"],
        "doubles": ["116", "112", "412"],
        "triples": [],
        "apartments": [],
        "ra_rooms": [],
        "uncolored": ["Bathroom All Gender 117", "RD Apartment 311", "RH Apartment 512", "Hitchcock Lounge 516"]
    },
    {
        "filename": "005_Hitchcock_Floor_4_pdf_house_0.png",
        "singles": ["144", "145", "146", "143", "141", "542", "543", "547", "545", "546"],
        "doubles": ["147", "241", "242", "341", "342", "441", "442", "541"],
        "triples": [],
        "apartments": [],
        "ra_rooms": [],
        "uncolored": ["RA 142", "RA 544", "Bathroom All Gender 148", "Bathroom All Gender 548"]
    },
    {
        "filename": "006_Snell_Floor_1_pdf_house_0.png",
        "singles": ["115", "114", "116", "113", "117", "112", "119", "120", "121", "126", "122", "125", "123", "124"],
        "doubles": [],
        "triples": [],
        "apartments": [],
        "ra_rooms": [],
        "uncolored": ["Bathroom 118 All Gender", "Lounge 111"]
    },
    {
        "filename": "007_Snell_Floor_4_pdf_house_0.png",
        "singles": ["415", "414", "416", "413", "417", "412", "411", "410", "420", "421", "426", "422", "425", "423", "424"],
        "doubles": [],
        "triples": [],
        "apartments": [],
        "ra_rooms": [],
        "uncolored": ["Bathroom 418 All Gender", "RA 419"]
    },
    {
        "filename": "008_Snell_Floor_3_pdf_house_0.png",
        "singles": ["315", "314", "316", "313", "317", "312", "311", "319", "310", "320", "321", "326", "322", "325", "323", "324"],
        "doubles": [],
        "triples": [],
        "apartments": [],
        "ra_rooms": [],
        "uncolored": ["Bathroom 318 Women"]
    }
]

import os
import csv

def parse_filename(filename):
    # e.g., 001_Snell_Floor_2_pdf_house_0.png
    parts = filename.split('_')
    building = "Snell_Hitchcock"
    
    # Extract 'Snell' or 'Hitchcock'
    house = parts[1]
    
    # Extract floor (which is after 'Floor')
    if 'Floor' in parts:
        floor_index = parts.index('Floor') + 1
        floor = parts[floor_index]
    else:
        floor = "Unknown"
            
    return building, house, floor

def generate_csv():
    colored_rows = []
    uncolored_rows = []

    for img in images_data:
        bld, house, flr = parse_filename(img['filename'])
        
        for rm in img.get('singles', []):
            colored_rows.append([rm, flr, bld, house, "Single", img['filename']])
        for rm in img.get('doubles', []):
            colored_rows.append([rm, flr, bld, house, "Double", img['filename']])
        for rm in img.get('triples', []):
            colored_rows.append([rm, flr, bld, house, "Triple", img['filename']])
        for rm in img.get('apartments', []):
            colored_rows.append([rm, flr, bld, house, "Apartment", img['filename']])
        for rm in img.get('ra_rooms', []):
            colored_rows.append([rm, flr, bld, house, "RA", img['filename']])
            
        for txt in img.get('uncolored', []):
            uncolored_rows.append([txt, flr, bld, house, img['filename']])

    os.makedirs('data/floorplans/Snell_Hitchcock', exist_ok=True)
    c_csv = 'data/floorplans/Snell_Hitchcock/colored_rooms.csv'
    with open(c_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Room Number", "Floor", "Building Name", "House Name", "Room Type", "Original Image"])
        writer.writerows(colored_rows)
    print(f"Wrote {len(colored_rows)} rows to {c_csv}")

    u_csv = 'data/floorplans/Snell_Hitchcock/uncolored_rooms.csv'
    with open(u_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Full Text", "Floor", "Building Name", "House Name", "Original Image"])
        writer.writerows(uncolored_rows)
    print(f"Wrote {len(uncolored_rows)} rows to {u_csv}")

if __name__ == "__main__":
    generate_csv()
