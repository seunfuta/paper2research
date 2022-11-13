import sqlite3
import pandas as pd
import sys
import numpy as np
import argparse
from os import listdir
from os.path import isfile, join
import math

class args:
    i = "/Users/seunfuta/Downloads/NIST/IMG/eraser-W7x32.db" #"/Volumes/Samsung_T5/M57/pat-2009-12-03c.db" #Wireshark-W7x64.db"
    c = "/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db"
    o = "/Volumes/Samsung_T5/M57/OLUSCAN/"

#if __name__ == '__main__':
#parser = argparse.ArgumentParser(description='Olu method')
#parser.add_argument('-c', action="store", default="/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db", help='catalog path')
#parser.add_argument('-i', action="store", default="/Users/seunfuta/Downloads/NIST/IMG/Wireshark-W7x64.db", help="image path folder")
#parser.add_argument('-o', action="store", default="/Users/seunfuta/Downloads/NIST/OLUSCAN/NEWER", help='output csv')
#args = parser.parse_args()

#onlyfiles = [f for f in listdir(args.i) if isfile(join(args.i, f))]
#for file in onlyfiles:
#    print("IMAGE "+str(onlyfiles.index(file)) +" out of "+str(len(onlyfiles)))
#    main(join(args.i+file))
#main(join(args.i))
#def main(imagefilepath):
CATALOG_DB_PATH = args.c
catalog_conn = sqlite3.connect(CATALOG_DB_PATH)
catalog_df = pd.DataFrame(columns=['obj_id', 'inode', 'filename','file_offset', 'len','md5','sha1', 'partition', 'filesize','app','app_id'])
catalog_df = pd.read_sql_query("SELECT block_hashes.obj_id, block_hashes.inode, block_hashes.filename, block_hashes.file_offset, \
                block_hashes.len, block_hashes.md5, block_hashes.sha1, files.partition,files.filesize , files.app, files.app_id\
                FROM files \
                INNER JOIN block_hashes ON files.obj_id = block_hashes.obj_id \
                and files.inode = block_hashes.inode and files.filename=block_hashes.filename;", catalog_conn)
print("original length ",len(catalog_df))
catalog_df = catalog_df[catalog_df.md5 != 'bf619eac0cdf3f68d496ea9344137e8b']
catalog_df = catalog_df[catalog_df.md5 != 'de03fe65a6765caa8c91343acc62cffc']
catalog_df = catalog_df[catalog_df.md5 != '85eba416ce0ee0951d1d93e73b191b75']
catalog_df = catalog_df[catalog_df.md5 != '1b5c2cbf1e37f6b0d33751269ae707af']
catalog_conn.close()
print("catalog app length, ", len(catalog_df))

#image_df = pd.read_csv('/Users/seunfuta/Downloads/NIST/IMG/AdvancedKeylogger-WinXP.db',encoding='latin-1')
print(args.i)#magefilepath)
IMAGE_DB_PATH = args.i#imagefilepath
image_conn = sqlite3.connect(IMAGE_DB_PATH)
image_df = pd.DataFrame(columns=['obj_id', 'inode', 'filename','file_offset', 'len','md5','sha1', 'partition', 'filesize'])
image_df = pd.read_sql_query("SELECT block_hashes.obj_id, files.inode, files.filename, block_hashes.file_offset, \
                block_hashes.len, block_hashes.md5, block_hashes.sha1, files.partition,files.filesize \
                FROM files \
                INNER JOIN block_hashes ON files.obj_id = block_hashes.obj_id;", image_conn)
print("original image length ",len(image_df))
#"/Volumes/Samsung_T5/M57/pat-2009-12-03.csv", index_col=False)
image_df = image_df[image_df.md5 != 'bf619eac0cdf3f68d496ea9344137e8b']
image_df = image_df[image_df.md5 != 'de03fe65a6765caa8c91343acc62cffc']
image_df = image_df[image_df.md5 != '85eba416ce0ee0951d1d93e73b191b75']
image_df = image_df[image_df.md5 != '1b5c2cbf1e37f6b0d33751269ae707af']
print("current image length ",len(image_df))

app_list = list(catalog_df.app.unique()) #['Wireshark-W7x64'] #
print(app_list)
result_df = pd.DataFrame()
#for app in app_list:#['TrueCrypt63-WinXP']:#TrueCrypt63-WinXP']:#sdelete-W7x64']:#app_list:
for app in app_list:
    if app == 'Wireshark-W7x64':
        ##START SHIFT TAB
        result_df.loc[app_list.index(app),'appname'] = app
        validated_app_matched = int(0)
        app_Prob = float(0)
        app_df = catalog_df[catalog_df.app == app]
        result_df.loc[app_list.index(app),'appsize'] = int(len(app_df))
        app_unique_md5s= app_df.md5.unique()

        matched_image_df = image_df[image_df.md5.isin(app_unique_md5s)]

        result_df.loc[app_list.index(app),'image_matches'] = int(len(matched_image_df))
        app_files = app_df.filename.unique()
        app_pairs_set = {} 
        matched_image_df.loc[:,'image_offset'] = matched_image_df.index
        appfilenames= app_df.filename.unique()

        app_df_new = app_df[app_df.groupby('obj_id')['obj_id'].transform('size') > 1]

        app_files_new = app_df_new.filename.unique()
        app_prob_numerator = float(0)
        app_prob_denominator = float(0) #len(app_files_new)
        for file in app_files_new:
            file_df = app_df[app_df.filename == file][["file_offset","md5"]].reset_index(drop=True)
            img_appfile_df =matched_image_df[matched_image_df.md5.isin(file_df.md5.unique())]
            if len(img_appfile_df) <2:
                continue
            
            file_pairs = map(lambda x, y: x + y, file_df.md5[:-1], file_df.md5[1:])
            set_file_pairs = set(file_pairs)
            img_appfile_pairs = map(lambda a, b: a + b, img_appfile_df.md5[:-1], img_appfile_df.md5[1:])
            next_match = list(map(lambda x: 1 if x in set_file_pairs else 0, img_appfile_pairs))
            next_match.extend([1]) if next_match[len(next_match)-1] == 1 else next_match.extend([0])
            s_var = 1
            q_var = 2
            simple_match_count = next_match.count(1)
            adjusted_match_count =simple_match_count 
            num_of_runs = 1
            file_sector_count = len(file_df)
            app_prob_denominator += file_sector_count
            prob = round((1-((1/(simple_match_count+s_var))**q_var))**math.log10(file_sector_count), 4)
            app_prob_numerator += (prob * float(file_sector_count))
            print(len(file_df), len(img_appfile_df),len(file_df.md5.unique()), len(img_appfile_df.md5.unique()),len(next_match), prob,file)
        if app_prob_denominator !=0:
            app_prob = round((app_prob_numerator / app_prob_denominator), 8)  
        else:
            app_prob = 0
        print(app_prob)
        result_df.loc[app_list.index(app),'prob'] = app_prob
        #### END SHIFT TAB
    else:
        continue
print(result_df)