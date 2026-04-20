import csv
import os

rooms_data = [
    {
        'Image': '001_Max_P_Graham_Floor_3_pdf_house_0.png',
        'Floor': 3,
        'House Name': 'Graham',
        'Rooms': [
            'RA C311B',
            'Trash Room C300D'
        ]
    },
    {
        'Image': '002_Max_P_Alper_Floor_3_pdf_house_0.png',
        'Floor': 3,
        'House Name': 'Alper',
        'Rooms': [
            'RH E316',
            'RA E309B',
            'RA E322B'
        ]
    },
    {
        'Image': '003_Max_P_Alper_Floor_4_pdf_house_0.png',
        'Floor': 4,
        'House Name': 'Alper',
        'Rooms': [
            'RA E412B'
        ]
    },
    {
        'Image': '004_Max_P_Graham_Floor_4_pdf_house_0.png',
        'Floor': 4,
        'House Name': 'Graham',
        'Rooms': [
            'RA C411B',
            'RH C403',
            'Trash Room C400D'
        ]
    },
    {
        'Image': '005_Max_P_Woodward_Floor_4_pdf_house_0.png',
        'Floor': 4,
        'House Name': 'Woodward',
        'Rooms': [
            'Trash Room C400G',
            'RA C428A'
        ]
    },
    {
        'Image': '006_Max_P_Woodward_Floor_3_pdf_house_0.png',
        'Floor': 3,
        'House Name': 'Woodward',
        'Rooms': [
            'RH C321',
            'Trash Room C300G'
        ]
    },
    {
        'Image': '007_Max_P_Flint_Floor_1_pdf_house_0.png',
        'Floor': 1,
        'House Name': 'Flint',
        'Rooms': [
            'RA C111B'
        ]
    },
    {
        'Image': '008_Max_P_Flint_Floor_2_pdf_house_0.png',
        'Floor': 2,
        'House Name': 'Flint',
        'Rooms': [
            'RA C211B'
        ]
    },
    {
        'Image': '009_Max_P_Rickert_Floor_3_pdf_house_0.png',
        'Floor': 3,
        'House Name': 'Rickert',
        'Rooms': [
            'Lounge W312',
            'Kitchen W312A',
            'RH W316',
            'Study W307',
            'RA W305B'
        ]
    },
    {
        'Image': '010_Max_P_Rickert_Floor_4_pdf_house_0.png',
        'Floor': 4,
        'House Name': 'Rickert',
        'Rooms': [
            'Study W400B',
            'RA W414B'
        ]
    },
    {
        'Image': '011_Max_P_Wallace_Floor_1_pdf_house_0.png',
        'Floor': 1,
        'House Name': 'Wallace',
        'Rooms': [
            'Lounge W112',
            'Kitchen W112A',
            'RA W114B',
            'Trash W100I'
        ]
    },
    {
        'Image': '012_Max_P_Wallace_Floor_2_pdf_house_0.png',
        'Floor': 2,
        'House Name': 'Wallace',
        'Rooms': [
            'Study W207',
            'RH W216',
            'RA W202B'
        ]
    },
    {
        'Image': '013_Max_P_Woodward_Floor_2_pdf_house_0.png',
        'Floor': 2,
        'House Name': 'Woodward',
        'Rooms': [
            
        ]
    },
    {
        'Image': '014_Max_P_Woodward_Floor_1_pdf_house_0.png',
        'Floor': 1,
        'House Name': 'Woodward',
        'Rooms': [
            'RA C128A'
        ]
    },
    {
        'Image': '015_Max_P_Hoover_Floor_3_pdf_house_0.png',
        'Floor': 3,
        'House Name': 'Hoover',
        'Rooms': [
            'RA E322B',
            'Lounge E325',
            'Kitchen E325A'
        ]
    },
    {
        'Image': '016_Max_P_May_Floor_1_pdf_house_0.png',
        'Floor': 1,
        'House Name': 'May',
        'Rooms': [
            'Commons E102',
            'Commons E104',
            'Kitchen E104A',
            'Computer Lab E106',
            'RA E109B',
            'AD E116'
        ]
    },
    {
        'Image': '017_Max_P_Hoover_Floor_1_pdf_house_0.png',
        'Floor': 1,
        'House Name': 'Hoover',
        'Rooms': [
            'RA Room E127A',
            'Lounge E125'
        ]
    },
    {
        'Image': '018_Max_P_Hoover_Floor_2_pdf_house_0.png',
        'Floor': 2,
        'House Name': 'Hoover',
        'Rooms': [
            'RH E231'
        ]
    },
    {
        'Image': '019_Max_P_May_Floor_2_pdf_house_0.png',
        'Floor': 2,
        'House Name': 'May',
        'Rooms': [
            'Commons E202',
            'Kitchen E202A',
            'RA E210B',
            'RH E216'
        ]
    },
    {
        'Image': '020_Max_P_Hoover_Floor_4_pdf_house_0.png',
        'Floor': 4,
        'House Name': 'Hoover',
        'Rooms': [
            'RM E429'
        ]
    }
]

def generate_csv():
    output_path = "data/floorplans/Max Palevsky/uncolored_rooms.csv"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Full Text', 'Floor', 'Building Name', 'House Name', 'Original Image'])
        
        for image_data in rooms_data:
            floor = image_data['Floor']
            house = image_data['House Name']
            image_name = image_data['Image']
            
            for room_text in image_data['Rooms']:
                writer.writerow([
                    room_text,
                    floor,
                    "Max Palevsky",
                    house,
                    image_name
                ])
                
    print(f"Successfully wrote {output_path}")

if __name__ == "__main__":
    generate_csv()
