import csv
import os

images_data = [
    # Eka
    {
        "filename": "001_Eka_16_pdf.png",
        "singles": ["1618", "1620", "1622", "1624", "1612", "1608", "1604", "1630", "1634", "1636", "1638", "1640", "1623", "1621", "1619", "1617", "1615"],
        "doubles": ["1616", "1614", "1610", "1606", "1602", "1628", "1632"],
        "triples": [],
        "apartments": ["1611", "1629"],
        "ra_rooms": [],
        "uncolored": ["Bath 1609", "Bath 1607 All Gender", "RA 1613", "Bath 1601 Men", "House Commons 1626", "Elevator"]
    },
    {
        "filename": "002_Eka_15_pdf.png",
        "singles": ["1518", "1520", "1522", "1524", "1512", "1508", "1504", "1530", "1534", "1536", "1538", "1540", "1523", "1521", "1519", "1517", "1515", "1513"],
        "doubles": ["1516", "1514", "1510", "1506", "1502", "1528", "1532"],
        "triples": [],
        "apartments": ["1529"],
        "ra_rooms": [],
        "uncolored": ["Bath 1509", "Bath 1507 Women", "RH Apartment 1511", "Bath 1501 All Gender", "House Commons 1526", "Elev", "Elev"]
    },
    {
        "filename": "003_Eka_14_pdf.png",
        "singles": ["1418", "1420", "1422", "1424", "1412", "1408", "1404", "1430", "1434", "1436", "1438", "1440", "1423", "1421", "1419", "1417", "1415"],
        "doubles": ["1416", "1414", "1410", "1406", "1402", "1428", "1432"],
        "triples": [],
        "apartments": ["1411", "1429"],
        "ra_rooms": [],
        "uncolored": ["Bath 1409", "Bath 1407 Women", "RA 1413", "Bath 1405", "Bath 1401 Men", "House Commons 1426", "Elev", "Elev"]
    },
    # Markovitz
    {
        "filename": "004_Markovitz_13_pdf.png",
        "singles": ["1318", "1320", "1322", "1324", "1312", "1308", "1304", "1330", "1334", "1336", "1338", "1340", "1323", "1321", "1319", "1317", "1315"],
        "doubles": ["1316", "1314", "1310", "1306", "1302", "1328", "1332"],
        "triples": [],
        "apartments": ["1311", "1329"],
        "ra_rooms": [],
        "uncolored": ["Bath 1309", "Bath 1307 Men", "RA 1313", "Bath 1301 All Gender", "House Commons 1126", "Elev", "Elev"]
    },
    {
        "filename": "005_Liew_8_pdf.png",
        "singles": ["818", "820", "822", "824", "812", "808", "804", "830", "834", "836", "838", "840", "823", "821", "819", "817", "815"],
        "doubles": ["816", "814", "810", "806", "802", "828", "832"],
        "triples": [],
        "apartments": ["811", "829"],
        "ra_rooms": [],
        "uncolored": ["Bath 809", "Bath 807 Women", "RA 813", "Bath 805 All Gender", "Bath 801 Men", "House Commons 526", "Elev", "Elev"]
    },
    {
        "filename": "006_Markovitz_11_pdf.png",
        "singles": ["1118", "1120", "1122", "1124", "1112", "1108", "1104", "1130", "1134", "1136", "1138", "1140", "1123", "1121", "1119", "1117", "1115"],
        "doubles": ["1116", "1114", "1110", "1106", "1102", "1128", "1132"],
        "triples": [],
        "apartments": ["1111", "1129"],
        "ra_rooms": [],
        "uncolored": ["Bath 1109", "Bath 1107 Women", "RA 1113", "Bath 1105 All Gender", "Bath 1101 Men", "House Commons 1126", "Elev", "Elev"]
    },
    # Liew
    {
        "filename": "007_Liew_10_pdf.png",
        "singles": ["1018", "1020", "1022", "1024", "1012", "1008", "1004", "1030", "1034", "1036", "1038", "1040", "1023", "1021", "1019", "1017", "1015"],
        "doubles": ["1016", "1014", "1010", "1006", "1002", "1028", "1032"],
        "triples": [],
        "apartments": ["1011", "1029"],
        "ra_rooms": [],
        "uncolored": ["Bath 1009", "Bath 1007 Women", "RA 1013", "Bath 1001 All Gender", "House Commons 1026", "Elev", "Elev"]
    },
    {
        "filename": "008_Markovitz_12_pdf.png",
        "singles": ["1218", "1220", "1222", "1224", "1212", "1208", "1204", "1230", "1234", "1236", "1238", "1240", "1223", "1221", "1219", "1217", "1215"],
        "doubles": ["1216", "1214", "1210", "1206", "1202", "1228", "1232"],
        "triples": [],
        "apartments": ["1211", "1229"],
        "ra_rooms": [],
        "uncolored": ["Bathroom 1207 Women", "RH Apartment 1211", "Bathroom 1201 Women", "House Commons 1126", "Elevator"]
    },
    {
        "filename": "009_Liew_9_pdf.png",
        "singles": ["918", "920", "922", "924", "912", "908", "904", "930", "934", "936", "938", "940", "923", "921", "919", "917", "915", "913"],
        "doubles": ["916", "914", "910", "906", "902", "928", "932"],
        "triples": [],
        "apartments": ["929"],
        "ra_rooms": [],
        "uncolored": ["Bath 909", "Bath 907 Men", "Resident Head 911", "Bath 901 Women", "House Commons 826", "Elev", "Elev"]
    },
    # Baker
    {
        "filename": "010_Baker_6_pdf.png",
        "singles": ["640", "638", "636", "634", "637", "635", "633", "631", "629", "627", "628", "624", "620", "604", "614", "612", "610", "608"],
        "doubles": ["632", "630", "626", "622", "618", "602", "606"],
        "triples": [],
        "apartments": ["605"],
        "ra_rooms": [],
        "uncolored": ["Bath 623", "Bath 621 Women", "Resident Head 625", "Bath 615 Men", "Elev", "Elev", "House Commons 516"]
    },
    # Chenn
    {
        "filename": "011_Chenn_6_pdf.png",
        "singles": ["618", "620", "622", "624", "612", "608", "604", "630", "634", "636", "638", "640", "623", "621", "619", "617", "615", "613"],
        "doubles": ["616", "614", "610", "606", "602", "628", "632"],
        "triples": [],
        "apartments": ["629"],
        "ra_rooms": [],
        "uncolored": ["Bath 609", "Bath 607 Women", "Resident Head 611", "Bath 601 Men", "House Commons 526", "Elev", "Elev"]
    },
    {
        "filename": "012_Baker_7_pdf.png",
        "singles": ["740", "738", "736", "734", "735", "733", "731", "729", "727", "728", "724", "720", "704", "714", "712", "710", "708"],
        "doubles": ["732", "730", "726", "722", "718", "702", "706"],
        "triples": [],
        "apartments": ["725", "705"],
        "ra_rooms": [],
        "uncolored": ["RA 737", "Bath 723", "Bath 721 Men", "Bath 715 All Gender", "Elev", "Elev", "House Commons 516"]
    },
    # Yovovich
    {
        "filename": "013_Yovovich_7_pdf.png",
        "singles": ["720", "718", "716", "710", "709", "707", "705", "703", "717", "719", "721", "723", "727", "735", "733", "731"],
        "doubles": ["722", "714", "712", "708", "725", "729", "737"],
        "triples": [],
        "apartments": ["724", "738"],
        "ra_rooms": [],
        "uncolored": ["Bath 726", "Bath 728 Women", "Bath 734 Men", "Bath All 713 Gender", "RA 715", "Bath 704 Men", "Elev", "House Commons 501"]
    },
    {
        "filename": "014_Chenn_7_pdf.png",
        "singles": ["718", "720", "722", "724", "712", "708", "704", "730", "734", "736", "738", "740", "723", "721", "719", "717", "715"],
        "doubles": ["716", "714", "710", "706", "702", "728", "732", "713"],
        "triples": [],
        "apartments": ["711", "729"],
        "ra_rooms": [],
        "uncolored": ["Bath 709", "Bath 707 All Gender", "Bath 701 Women", "House Commons 526", "Elev", "Elev"]
    },
    # Fama
    {
        "filename": "015_Fama_7_pdf.png",
        "singles": ["703", "705", "707", "709", "711", "708", "712", "716", "720", "722", "735", "733", "731", "729", "727", "725", "738"],
        "doubles": ["706", "710", "714", "718", "724", "732", "728", "726"],
        "triples": [],
        "apartments": ["713", "734"],
        "ra_rooms": [],
        "uncolored": ["Bath 719 Women", "Bath All 721 Gender", "Bath 723", "Bath 730 Women"]
    },
    {
        "filename": "016_Yovovich_6_pdf.png",
        "singles": ["620", "618", "616", "615", "617", "619", "621", "623", "627", "635", "633", "631", "610", "609", "607", "605", "603"],
        "doubles": ["622", "625", "629", "614", "612", "608"],
        "triples": [],
        "apartments": ["638"],
        "ra_rooms": [],
        "uncolored": ["Resident Head", "Bath 626", "Bath 628", "Bath 634 Men", "Bath All 613 Gender", "Bath 604 Women", "Elev", "House Commons 501"]
    },
    {
        "filename": "017_Fama_6_pdf.png",
        "singles": ["603", "605", "607", "609", "611", "608", "612", "616", "620", "622", "624", "635", "633", "631", "629", "627", "625", "638"],
        "doubles": ["606", "610", "614", "618", "632", "628", "626"],
        "triples": [],
        "apartments": ["634"],
        "ra_rooms": [],
        "uncolored": ["Resident Head 613", "Bath 619 Men", "Bath All 621 Gender", "Bath 623", "Bath 630 Women"]
    },
    {
        "filename": "018_Baker_5_pdf.png",
        "singles": ["540", "538", "536", "534", "535", "533", "531", "529", "527", "528", "524", "520", "504", "514", "512", "510", "508"],
        "doubles": ["532", "530", "526", "522", "518", "502", "506"],
        "triples": [],
        "apartments": ["525", "505"],
        "ra_rooms": [],
        "uncolored": ["RA 537", "Bath 523", "Bath 521 Men", "Bath 515 Women", "House Commons 516", "Elev", "Elev"]
    },
    {
        "filename": "019_Chenn_5_pdf.png",
        "singles": ["518", "520", "522", "524", "512", "508", "504", "530", "534", "536", "538", "540", "523", "521", "519", "517", "515"],
        "doubles": ["516", "514", "510", "506", "502", "528", "532"],
        "triples": [],
        "apartments": ["511", "529"],
        "ra_rooms": [],
        "uncolored": ["Bath 507 Men", "Bath 505 All Gender", "RA 513", "Bath 501 Women", "House Commons 526", "Elev", "Elev"]
    },
    {
        "filename": "020_Fama_5_pdf.png",
        "singles": ["503", "505", "507", "509", "511", "508", "512", "516", "520", "522", "535", "533", "531", "529", "527", "525", "538"],
        "doubles": ["506", "510", "514", "518", "524", "532", "528", "526"],
        "triples": [],
        "apartments": ["513", "534"],
        "ra_rooms": [],
        "uncolored": ["Bath 519 Women", "Bath All 521 Gender", "Bath 523", "Bath 530 Men"]
    },
    {
        "filename": "021_Yovovich_5_pdf.png",
        "singles": ["520", "518", "516", "535", "533", "531", "517", "519", "521", "523", "527", "510", "509", "507", "505", "503"],
        "doubles": ["522", "537", "525", "529", "514", "512", "508"],
        "triples": [],
        "apartments": ["524", "538"],
        "ra_rooms": [],
        "uncolored": ["Bath 526", "Bath 528 Women", "Bathroom 534 Men", "Bath All 513 Gender", "RA 515", "Bath 504 Men", "Elev", "House Commons 501"]
    },
    # 018_Baker_5_pdf.png
    # 019_Chenn_5_pdf.png
    # 020_Fama_5_pdf.png
    # 021_Yovovich_5_pdf.png
    # Casner
    {
        "filename": "022_Casner_2_pdf.webp",
        "singles": ["240", "238", "236", "234", "235", "233", "231", "229", "227", "228", "220", "214", "212", "210", "208", "204"],
        "doubles": ["232", "230", "226", "222", "218", "202", "206"],
        "triples": [],
        "apartments": ["225", "205"],
        "ra_rooms": [],
        "uncolored": ["RA 237", "Bath 223", "Bath 219 All Gender", "Bath 215 Men", "House Commons 216", "Elev", "Elev"]
    },
    {
        "filename": "023_Casner_3_pdf.png",
        "singles": ["340", "338", "336", "334", "328", "324", "320", "304", "314", "312", "310", "308"],
        "doubles": ["332", "330", "326", "322", "318", "302", "306"],
        "triples": [],
        "apartments": ["305"],
        "ra_rooms": [],
        "uncolored": ["Resident Head 325", "Bath 323", "Bath 321 Men", "Bath 315 Men", "Elev", "Elev"]
    },
    {
        "filename": "024_Casner_4_pdf.png",
        "singles": ["440", "438", "436", "434", "435", "433", "431", "429", "427", "428", "424", "420", "404", "414", "412", "410", "408"],
        "doubles": ["432", "430", "426", "422", "418", "402", "406"],
        "triples": [],
        "apartments": ["425", "405"],
        "ra_rooms": [],
        "uncolored": ["RA 437", "Bath 423", "Bath 421 All Gender", "Bath 415 Women", "Elev", "Elev"]
    },
    # Gallo
    {
        "filename": "025_Gallo_2_pdf.webp",
        "singles": ["203", "205", "207", "209", "208", "212", "216", "220", "222", "235", "233", "231", "229", "227", "225", "238"],
        "doubles": ["206", "210", "214", "218", "232", "228", "226"],
        "triples": [],
        "apartments": ["211", "213", "234"],
        "ra_rooms": [],
        "uncolored": ["House Commons 201", "Bath 219 Men", "All Bath Gender 221", "RA 224", "Bath 230 Women", "Bath 223"]
    },
    {
        "filename": "026_Gallo_3_pdf.png",
        "singles": ["303", "305", "307", "309", "311", "308", "312", "316", "320", "322", "324", "335", "333", "331", "329", "327", "325", "338"],
        "doubles": ["306", "310", "314", "318", "332", "328", "326"],
        "triples": [],
        "apartments": ["334"],
        "ra_rooms": [],
        "uncolored": ["Resident Head 313", "Bath 319 Women", "All Bath Gender 321", "Bath 330 Men", "Elevator"]
    },
    {
        "filename": "027_Gallo_4_pdf.png",
        "singles": ["403", "405", "407", "409", "411", "408", "412", "416", "420", "422", "435", "433", "431", "429", "427", "425", "438"],
        "doubles": ["406", "410", "414", "418", "432", "428", "426"],
        "triples": [],
        "apartments": ["413", "434"],
        "ra_rooms": [],
        "uncolored": ["Elev", "Bath 419 Men", "Bath All 421 Gender", "RA 424", "Bath 423", "Bath 430 Women"]
    },
    # 026_Gallo_3_pdf.png
    # 027_Gallo_4_pdf.png
    # Han
    {
        "filename": "028_Han_2_pdf.webp",
        "singles": ["218", "220", "222", "224", "212", "208", "204", "230", "234", "236", "238", "240", "225", "223", "221", "219", "217", "215"],
        "doubles": ["216", "214", "210", "206", "202", "228", "232"],
        "triples": [],
        "apartments": ["211", "229"],
        "ra_rooms": [],
        "uncolored": ["House Commons 226", "Bath 209", "RA 213", "Bath 207 Men", "Bath 205 All Gender", "Bath 201 Women", "Elev", "Elev"]
    },
    {
        "filename": "029_Han_3_pdf.png",
        "singles": ["318", "320", "322", "324", "312", "308", "304", "330", "334", "336", "338", "340", "323", "321", "319", "317", "315", "313"],
        "doubles": ["316", "314", "310", "306", "302", "328", "332"],
        "triples": [],
        "apartments": ["329"],
        "ra_rooms": [],
        "uncolored": ["Resident Head 311", "Bath 309", "Bath 307 Men", "Bath 301 Women", "Elev", "Elev"]
    },
    {
        "filename": "030_Han_4_pdf.png",
        "singles": ["418", "420", "422", "424", "412", "408", "404", "430", "434", "436", "438", "440", "423", "421", "419", "417", "415"],
        "doubles": ["416", "414", "410", "406", "402", "428", "432"],
        "triples": [],
        "apartments": ["411", "429"],
        "ra_rooms": [],
        "uncolored": ["House Commons 426", "RA 413", "Bath 409", "Bathroom 407 All Gender", "Bath 401 Men", "Elev", "Elev"]
    },
    # Rustandy
    {
        "filename": "031_Rustandy_2_pdf.webp",
        "singles": ["220", "218", "216", "210", "235", "233", "231", "217", "219", "221", "223", "227", "211", "209", "207", "205", "203"],
        "doubles": ["222", "214", "212", "208", "237", "225", "229"],
        "triples": [],
        "apartments": ["224", "226"],
        "ra_rooms": [],
        "uncolored": ["Bath 226 All Gender", "Bath 228 Men", "Bath 234", "Bath All 213 Gender", "RA 215", "House Commons 201", "Bath 206 Shower", "Elevator"]
    },
    {
        "filename": "032_Rustandy_3_pdf.png",
        "singles": ["320", "318", "316", "310", "311", "309", "307", "305", "303", "335", "333", "331", "315", "317", "319", "321", "323", "327"],
        "doubles": ["322", "314", "312", "308", "337", "325", "329"],
        "triples": [],
        "apartments": ["338"],
        "ra_rooms": [],
        "uncolored": ["Resident Head 324", "Bath 326 All Gender", "Bath 328 Women", "Bath 334", "Bath All 313 Gender", "Bath 304 Men", "Elevator"]
    },
    {
        "filename": "033_Rustandy_4_pdf.png",
        "singles": ["420", "418", "416", "410", "411", "409", "407", "405", "403", "435", "433", "431", "417", "419", "421", "423", "427"],
        "doubles": ["422", "414", "412", "408", "437", "425", "429"],
        "triples": [],
        "apartments": ["424", "438"],
        "ra_rooms": [],
        "uncolored": ["Bath 426 All Gender", "Bath 428 Men", "Bath 434", "Bath All 413 Gender", "RA 415", "Bath 404 Women", "Elev"]
    }
]

def parse_filename(filename):
    parts = filename.split('_')
    building = "Woodlawn"
    house = "Unknown"
    floor = "Unknown"
    
    for i, p in enumerate(parts):
        if 'pdf' in p:
            floor = parts[i-1]
            house_parts = parts[1:i-1]
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

    os.makedirs('data/floorplans/Woodlawn', exist_ok=True)
    c_csv = 'data/floorplans/Woodlawn/colored_rooms.csv'
    with open(c_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Room Number", "Floor", "Building Name", "House Name", "Room Type", "Original Image"])
        writer.writerows(colored_rows)
    print(f"Wrote {len(colored_rows)} rows to {c_csv}")

    u_csv = 'data/floorplans/Woodlawn/uncolored_rooms.csv'
    with open(u_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Full Text", "Floor", "Building Name", "House Name", "Original Image"])
        writer.writerows(uncolored_rows)
    print(f"Wrote {len(uncolored_rows)} rows to {u_csv}")

if __name__ == "__main__":
    generate_csv()
