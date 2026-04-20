import csv
import os

images_data = [
    {
        "filename": "001_GGRC_Halperin_4_pdf_house_0.png",
        "singles": ["W417", "W419", "W423", "W426", "W428", "W432", "W409", "W401", "W408", "W404"],
        "doubles": ["W421", "W407", "W405", "W403", "W410", "W406", "W402"],
        "triples": [],
        "apartments": ["W431"],
        "ra_rooms": ["W425"], # Room Type: RA
        "uncolored": ["Trash Room W416", "Bathroom W422 All Gender", "Bathroom W424", "Single W430"]
    },
    {
        "filename": "002_GGRC_Crown_8_pdf_house_0.png",
        "singles": ["C803", "C805", "C816", "C818", "C823"],
        "doubles": ["C801", "C815", "C814", "C821", "C822"],
        "triples": [], "apartments": ["C819", "C820"], "ra_rooms": [],
        "uncolored": ["Bathroom Men", "Trash Room C817"]
    },
    {
        "filename": "003_GGRC_Crown_9_pdf_house_0.png",
        "singles": ["C903", "C914"],
        "doubles": ["C901", "C913", "C912", "C919", "C921", "C923", "C925", "C926"],
        "triples": [], "apartments": ["C924"], "ra_rooms": [],
        "uncolored": ["Bathroom All Gender", "Bathroom", "RA C916"]
    },
    {
        "filename": "004_GGRC_Crown_5_pdf_house_0.png",
        "singles": ["C501", "C503", "C505", "C514", "C527"],
        "doubles": ["C515", "C512", "C523", "C525", "C522"],
        "triples": [], "apartments": [], "ra_rooms": [],
        "uncolored": ["Bathroom C502 All Gender", "Trash Room C517", "Computer lab C519", "Kitchen C518", "Lounge C521", "RH C520"]
    },
    {
        "filename": "005_GGRC_Crown_6_pdf_house_0.png",
        "singles": ["C603", "C614", "C616", "C617", "C623"],
        "doubles": ["C601", "C613", "C612", "C619", "C621", "C622"],
        "triples": [], "apartments": [], "ra_rooms": [],
        "uncolored": ["Bathroom C602 All Gender", "RH C610"]
    },
    {
        "filename": "006_GGRC_Cathey_5_pdf_house_0.png",
        "singles": ["C530", "C531", "C533", "C535", "E540", "E536", "E541", "E539"],
        "doubles": ["C532", "C534", "C529", "C537", "E538", "E534", "E537", "E535", "E533", "E531"],
        "triples": [], "apartments": [], "ra_rooms": [],
        "uncolored": ["Trash room E532", "Bathroom E526 All Gender", "RA E529"]
    },
    {
        "filename": "007_GGRC_Cathey_3_pdf_house_0.png",
        "singles": ["E331", "E339", "E341", "E343", "E355", "E353"],
        "doubles": ["E330", "E337", "E351", "E349", "E347", "E345"],
        "triples": [], "apartments": ["E352"], "ra_rooms": [],
        "uncolored": ["RH E332", "Trash Room E348", "Bathroom Men"]
    },
    {
        "filename": "008_GGRC_Cathey_4_pdf_house_0.png",
        "singles": ["E429", "E431", "E433", "E439", "E441", "E454", "E450", "E455", "E453"],
        "doubles": ["E437", "E452", "E448", "E451", "E449", "E447", "E445", "E430"],
        "triples": [], "apartments": ["E438"], "ra_rooms": [],
        "uncolored": ["Bathroom E442 Women", "RA E443"]
    },
    {
        "filename": "009_GGRC_Cathey_2_pdf_house_0.png",
        "singles": ["E225", "E227", "E233", "E235", "E242", "E243", "E241"],
        "doubles": ["E228", "E231", "E238", "E239"],
        "triples": [], "apartments": [], "ra_rooms": [],
        "uncolored": ["RH 230", "Bathroom E234 Women", "RD E237"]
    },
    {
        "filename": "010_GGRC_Cathey_1_pdf_house_0.png",
        "singles": ["E133", "E135"],
        "doubles": ["E131"],
        "triples": [], "apartments": ["E132"], "ra_rooms": [],
        "uncolored": ["Study E146", "Lounge E144", "Study E140", "Bathroom E136 All Gender", "RD E137"]
    },
    {
        "filename": "011_GGRC_Wendt_7_pdf_house_0.png",
        "singles": ["E710", "E714", "E722", "E707", "E709", "E713", "E721", "E723"],
        "doubles": ["E712", "E716", "E718", "E720", "E724", "E726", "E705", "E711", "E719"],
        "triples": [], "apartments": ["E701"], "ra_rooms": [],
        "uncolored": ["Trash Room E706", "Bathroom E703 Men", "RA E705"]
    },
    {
        "filename": "012_GGRC_Kenwood_5_pdf_house_0.png",
        "singles": ["W541", "W552", "W554", "W543", "W545", "W547", "W551", "W553", "W557"],
        "doubles": ["W537", "W539", "W536", "W538", "W548", "W550", "W560", "W549", "W555", "W559"],
        "triples": [], "apartments": [], "ra_rooms": [],
        "uncolored": ["Bathroom W556", "Bathroom W558 Men"]
    },
    {
        "filename": "013_GGRC_Wendt_5_pdf_house_0.png",
        "singles": ["E511", "E513", "E517", "E519", "E525", "E527"],
        "doubles": ["E516", "E509", "E515", "E523"],
        "triples": [], "apartments": ["E510"], "ra_rooms": [],
        "uncolored": ["Computer Lab E503B", "Kitchen E503", "Lounge E505", "Trash Room E504", "Bathroom E507 All Gender", "RH E520"]
    },
    {
        "filename": "014_GGRC_Kenwood_4_pdf_house_0.png",
        "singles": ["W446", "W448", "W450", "W441", "W443", "W445", "W449", "W451"],
        "doubles": ["W437", "W436", "W438", "W442", "W444", "W454", "W447"],
        "triples": [], "apartments": ["W453"], "ra_rooms": [],
        "uncolored": ["RA W439", "Trash room W440", "Bathroom W452 Women"]
    },
    {
        "filename": "015_GGRC_Wendt_6_pdf_house_0.png",
        "singles": ["E605", "E611", "E613", "E617", "E623", "E625", "E610"],
        "doubles": ["E603", "E616", "E626", "E609", "E615", "E621"],
        "triples": [], "apartments": ["E612"], "ra_rooms": [],
        "uncolored": ["Trash Room E604", "Bathroom E607 Women", "RH E620"]
    },
    {
        "filename": "016_GGRC_Wendt_8_pdf_house_0.png",
        "singles": ["E814", "E822", "E811", "E813", "E817", "E825", "E827"],
        "doubles": ["E812", "E816", "E818", "E820", "E824", "E826", "E809", "E815", "E823"],
        "triples": [], "apartments": ["E801"], "ra_rooms": [],
        "uncolored": ["Trash Room E806", "Bathroom", "Bathroom All Gender", "RA E819"]
    },
    {
        "filename": "017_GGRC_DelGiorno_5_pdf_house_0.png",
        "singles": ["W506", "W502", "W515", "W523", "W525", "W524", "W526", "W528", "W530", "W532"],
        "doubles": ["W505", "W503", "W501", "W504", "W517", "W521"],
        "triples": [], "apartments": [], "ra_rooms": [],
        "uncolored": ["Lounge W509", "Computer Lab W511", "Kitchen W507", "Trash Room W516", "Bathroom W520", "Bathroom W522 All Gender", "RH W531"]
    },
    {
        "filename": "018_GGRC_Delgiorno_8_pdf_house_0.png",
        "singles": ["W811", "W815", "W817", "W821", "W814", "W816", "W818", "W820", "W822"],
        "doubles": ["W809", "W813", "W819", "W825", "W827", "W826", "W828"],
        "triples": [], "apartments": ["W801"], "ra_rooms": [],
        "uncolored": ["Trash Room W808", "Bathroom Men", "RA W823"]
    },
    {
        "filename": "019_GGRC_DelGiorno_6_pdf_house_0.png",
        "singles": ["W603", "W605", "W601", "W607", "W613", "W617", "W619", "W614", "W616", "W618", "W620"],
        "doubles": ["W611", "W615", "W625", "W627", "W624", "W626"],
        "triples": [], "apartments": [], "ra_rooms": [],
        "uncolored": ["Trash Room W606", "Bathroom W612 Women", "RH W623"]
    },
    {
        "filename": "020_GGRC_Crown_7_pdf_house_0.png",
        "singles": ["C703", "C705", "C719", "C721", "C723", "C727", "C731", "C714"],
        "doubles": ["C701", "C715", "C729", "C712", "C728"],
        "triples": [], "apartments": ["C726"], "ra_rooms": [],
        "uncolored": ["Bathroom C702 Women", "Trash Room C717", "RA C716", "Bathroom C725"]
    }
]

import os
import csv

def parse_filename(filename):
    parts = filename.split('_')
    building = "Renee_Granville-Grossman"
    house = "Unknown"
    floor = "Unknown"
    
    for i, p in enumerate(parts):
        if 'pdf' in p:
            floor = parts[i-1]
            house_parts = parts[2:i-1]
            house = " ".join(house_parts)
            break
            
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

    os.makedirs('data/floorplans/Renee_Granville-Grossman', exist_ok=True)
    c_csv = 'data/floorplans/Renee_Granville-Grossman/colored_rooms.csv'
    with open(c_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Room Number", "Floor", "Building Name", "House Name", "Room Type", "Original Image"])
        writer.writerows(colored_rows)
    print(f"Wrote {len(colored_rows)} rows to {c_csv}")

    u_csv = 'data/floorplans/Renee_Granville-Grossman/uncolored_rooms.csv'
    with open(u_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Full Text", "Floor", "Building Name", "House Name", "Original Image"])
        writer.writerows(uncolored_rows)
    print(f"Wrote {len(uncolored_rows)} rows to {u_csv}")

if __name__ == "__main__":
    generate_csv()

if __name__ == "__main__":
    generate_csv()
