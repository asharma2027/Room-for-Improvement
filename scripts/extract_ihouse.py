import csv
import os

images_data = [
    {
        "filename": "001_I_House_Breckinridge_8_pdf_house_0.png",
        "singles": ["835", "836", "837", "838", "839", "840", "841", "842", "843", "844", "845", "846", "847", "848", "849", "850", "851", "853", "854", "855", "858", "860", "862", "864", "866", "868", "870", "872", "874", "876"],
        "doubles": [], "triples": [], "apartments": [],
        "uncolored": ["Lounge 867", "Women Bathroom"]
    },
    {
        "filename": "002_I_House_Breckinridge_9_pdf_house_0.png",
        "singles": ["915", "935", "936", "937", "938", "939", "940", "941", "942", "943", "944", "945", "946", "947", "949", "950", "951", "952", "953", "954", "955", "956"],
        "doubles": ["917", "918"], "triples": [], "apartments": [],
        "uncolored": ["RA 948", "Bathroom", "Bathroom"]
    },
    {
        "filename": "003_I_House_Booth_3_pdf_house_0.png",
        "singles": ["334", "335", "336", "337", "338", "339", "340", "341", "342", "343", "344", "345", "346", "347", "348", "349", "350", "351", "353", "355", "356", "357", "358", "362", "364", "365", "366", "367", "368", "369", "370", "371", "372", "373", "374", "375", "376", "377", "392", "394", "395", "396", "397"],
        "doubles": [], "triples": [], "apartments": [],
        "uncolored": ["RA 360", "Bathroom Men", "Bathroom All Gender", "Stairs", "RH 382"]
    },
    {
        "filename": "004_I_House_Breckinridge_7_pdf_house_0.png",
        "singles": ["736", "738", "740", "742", "744", "746", "748", "750", "739", "741", "743", "745", "747", "749", "751", "753", "755", "756", "757", "758", "762", "764", "765", "766", "767", "768", "769", "770", "771", "772", "774", "776", "777", "778"],
        "doubles": ["735", "775"], "triples": [], "apartments": [],
        "uncolored": ["Bathroom Men", "RA 760"]
    },
    {
        "filename": "005_I_House_Breckinridge_11_pdf_house_0.png",
        "singles": ["1101", "1102", "1103"],
        "doubles": [], "triples": [], "apartments": [],
        "uncolored": ["Bathroom"]
    },
    {
        "filename": "006_I_House_Thompson_4_pdf_house_0.png",
        "singles": ["404", "406", "407", "408", "409", "410", "411", "412", "414", "415", "418", "419", "420", "421", "422", "423", "424", "425", "426", "427", "428", "429", "430", "431", "432", "433"],
        "doubles": ["401", "402", "403", "416"], "triples": [], "apartments": [],
        "uncolored": ["RA 417", "Bathroom All Gender"]
    },
    {
        "filename": "007_I_House_Booth_2_pdf_house_0.png",
        "singles": ["234", "236", "238", "240", "242", "244", "246", "248", "250", "235", "237", "239", "241", "243", "245", "247", "249", "251", "256", "257", "258", "260", "262", "264", "265", "266", "267", "268", "269", "270", "272", "274", "276", "280", "282", "284", "286", "288", "290"],
        "doubles": ["277"], "triples": ["275"], "apartments": [],
        "uncolored": ["Bathroom Women", "RA 278", "Trash Room", "Bathroom", "Lounge"]
    },
    {
        "filename": "008_I_House_Thompson_5_pdf_house_0.png",
        "singles": ["504", "506", "507", "509", "511", "515", "517", "519", "521", "523", "525", "526", "527", "528", "529", "530", "531", "532", "533"],
        "doubles": ["503"], "triples": [], "apartments": [],
        "uncolored": ["RH 516", "Bathroom Men", "Lounge 501"]
    },
    {
        "filename": "009_I_House_Thompson_3_pdf_house_0.png",
        "singles": ["304", "306", "307", "308", "309", "310", "311", "312", "314", "315", "317", "318", "319", "320", "334"],
        "doubles": ["301", "303", "316"], "triples": [], "apartments": [],
        "uncolored": ["Bathroom Women", "Lounge 398"]
    },
    {
        "filename": "010_I_House_Thompson_2_pdf_house_0.png",
        "singles": ["204", "206", "207", "208", "209", "210", "211", "212", "214", "215", "218", "219", "220"],
        "doubles": ["203", "216"], "triples": [], "apartments": ["299"],
        "uncolored": ["Bathroom All Gender", "RA 217"]
    },
    {
        "filename": "011_I_House_Phoenix_4_pdf_house_0.png",
        "singles": ["435", "437", "439", "441", "443", "445", "447", "449", "451", "453", "455", "436", "438", "440", "442", "444", "446", "448", "450", "456", "457", "458", "460", "462", "464", "465", "466", "467", "468", "469", "470", "471", "472", "473", "474", "475", "476", "477"],
        "doubles": [], "triples": [], "apartments": [],
        "uncolored": ["Bathroom Men", "RH 482"]
    },
    {
        "filename": "012_I_House_Shorey_7_pdf_house_0.png",
        "singles": ["704", "706", "707", "708", "709", "710", "711", "712", "714", "715", "716", "718", "719", "720", "721", "722", "723", "724", "725", "726", "727", "728", "729", "730", "731", "732", "733"],
        "doubles": ["701", "702", "703"], "triples": [], "apartments": [],
        "uncolored": ["Bathroom All Gender", "RA 717"]
    },
    {
        "filename": "013_I_House_Shorey_6_pdf_house_0.png",
        "singles": ["604", "606", "607", "609", "611", "615", "617", "619", "621", "623", "625", "626", "627", "628", "629", "630", "631", "632", "633"],
        "doubles": ["603"], "triples": [], "apartments": [],
        "uncolored": ["RH 616", "Bathroom Women", "Lounge 601"]
    },
    {
        "filename": "014_I_House_Phoenix_5_pdf_house_0.png",
        "singles": ["539", "541", "543", "545", "547", "549", "551", "553", "555", "540", "542", "544", "546", "548", "550", "556", "557", "558", "562", "564", "565", "566", "567", "568", "569", "570", "571", "572", "574", "576"],
        "doubles": ["535", "536", "575"], "triples": [], "apartments": [],
        "uncolored": ["Bathroom Women", "RA 560", "Lounge 577"]
    },
    {
        "filename": "015_I_House_Phoenix_6_pdf_house_0.png",
        "singles": ["639", "641", "643", "645", "647", "649", "651", "653", "655", "640", "642", "644", "646", "648", "650", "656", "657", "658", "662", "664", "666", "668", "670", "671", "672", "674", "676", "677", "678"],
        "doubles": ["635", "636", "675"], "triples": [], "apartments": [],
        "uncolored": ["Bathroom All Gender", "RA 660", "Lounge 669"]
    },
    {
        "filename": "016_I_House_Breckinridge_12_pdf_house_0.png",
        "singles": ["1201", "1202", "1203"],
        "doubles": [], "triples": [], "apartments": [],
        "uncolored": ["Bathroom"]
    }
]

def parse_filename(filename):
    # E.g. "001_I_House_Breckinridge_8_pdf_house_0.png"
    # Wait: building = "I-House". house = "Breckinridge". floor = "8"
    parts = filename.split('_')
    building = "I-House"
    house = "Unknown"
    floor = "Unknown"
    
    # Let's find index containing "pdf"
    for i, p in enumerate(parts):
        if 'pdf' in p:
            floor = parts[i-1]
            house_parts = parts[3:i-1]
            house = " ".join(house_parts)
            break
            
    return building, house, floor

colored_rows = []
uncolored_rows = []

for img in images_data:
    bld, house, flr = parse_filename(img['filename'])
    
    # Colored
    for rm in img['singles']:
        colored_rows.append([rm, flr, bld, house, "Single", img['filename']])
    for rm in img['doubles']:
        colored_rows.append([rm, flr, bld, house, "Double", img['filename']])
    for rm in img['triples']:
        colored_rows.append([rm, flr, bld, house, "Triple", img['filename']])
    for rm in img['apartments']:
        colored_rows.append([rm, flr, bld, house, "Apartment", img['filename']])
        
    # Uncolored
    for txt in img['uncolored']:
        uncolored_rows.append([txt, flr, bld, house, img['filename']])

# Write Colored CSV
os.makedirs('data/floorplans/I-House', exist_ok=True)
c_csv = 'data/floorplans/I-House/colored_rooms.csv'
with open(c_csv, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Room Number", "Floor", "Building Name", "House Name", "Room Type", "Original Image"])
    writer.writerows(colored_rows)
print(f"Wrote {len(colored_rows)} rows to {c_csv}")

u_csv = 'data/floorplans/I-House/uncolored_rooms.csv'
with open(u_csv, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Full Text", "Floor", "Building Name", "House Name", "Original Image"])
    writer.writerows(uncolored_rows)
print(f"Wrote {len(uncolored_rows)} rows to {u_csv}")
