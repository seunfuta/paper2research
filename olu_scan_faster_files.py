import sqlite3
import pandas as pd
import sys
import numpy as np
import argparse
from os import listdir
from os.path import isfile, join

def main(imagefilepath):
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
    #############
    print(imagefilepath)
    IMAGE_DB_PATH = imagefilepath
    image_conn = sqlite3.connect(IMAGE_DB_PATH)
    image_df = pd.DataFrame(columns=['obj_id', 'inode', 'filename','file_offset', 'len','md5','sha1', 'partition', 'filesize'])
    image_df = pd.read_sql_query("SELECT block_hashes.obj_id, files.inode, files.filename, block_hashes.file_offset, \
                    block_hashes.len, block_hashes.md5, block_hashes.sha1, files.partition,files.filesize \
                    FROM files \
                    INNER JOIN block_hashes ON files.obj_id = block_hashes.obj_id;", image_conn)
    print("original image length ",len(image_df))
    image_df = image_df[image_df.md5 != 'bf619eac0cdf3f68d496ea9344137e8b']
    image_df = image_df[image_df.md5 != 'de03fe65a6765caa8c91343acc62cffc']
    image_df = image_df[image_df.md5 != '85eba416ce0ee0951d1d93e73b191b75']
    image_df = image_df[image_df.md5 != '1b5c2cbf1e37f6b0d33751269ae707af']
    print("current image length ",len(image_df))
    ##############

    app_list = catalog_df.app.unique()
    result_df = pd.DataFrame()
    for app in app_list:
        #if app == 'OfficePro2003-W7x32':
        app_df = catalog_df[catalog_df.app == app]
        app_unique_md5s= app_df.md5.unique()
        matched_image_df = image_df[image_df.md5.isin(app_unique_md5s)]
        #print(app," matched number of sectors in image ",len(matched_image_df))
        #print(matched_image_df)
        #lets create app sec pairs
        app_files = app_df.filename.unique()
        #print(app_files)
        app_pairs_set = {} #dict #set() 
        for file in app_files:
            file_hashpair_set = set()
            files_df = app_df[app_df.filename == file]
            #print(f'file {file} is of size {len(files_df)}')
            file_hashes = files_df.md5
            if len(file_hashes)< 2:
                #print(file_hashes.iloc[0])
                file_hashpair_set.add(file_hashes.iloc[0])
            else:
                for i in range(0, len(file_hashes)-1):
                    #print(file_hashes.iloc[i])
                    #print(file_hashes.iloc[int(i+1)])
                    hash_pair = file_hashes.iloc[i]+file_hashes.iloc[i+1]
                #print(i, hash_pair)
                    file_hashpair_set.add(hash_pair)
            app_pairs_set[file] = file_hashpair_set 
        #print(f"set size is {len(app_pairs_set)}")
        lst2 = list(matched_image_df.md5)
        lst2_pairs = list(map(lambda a, b: a + b, lst2[:-1], lst2[1:]))
        Prob_Total = 0
        for file in app_files:
            #x = 0 #setting a default value
            forward_list = list(map(lambda x: 1 if x in app_pairs_set[file] else 0, lst2_pairs))
            x= forward_list.count(1)
            t= len(forward_list)+0.0000000001
            s = 1
            q = 2
            Prob_file = (1 - ((1/(x + s))**q))**(np.log(t))
            Prob_Total+= Prob_file
        Prob_App = Prob_Total/len(app_files)    


        #forward_series = pd.Series(forward_list)
        if Prob_App == np.inf: Prob_App =float(0)
        print(app, " matched ", len(matched_image_df), " set ", len(app_pairs_set), " Prob ",Prob_App)
        result_df.loc[app,'matched'] = len(matched_image_df)
        result_df.loc[app,'prob'] = "{:.4f}".format(Prob_App)
    print(result_df)
    ###############
    result_df.to_csv(args.o+imagefilepath.split("/")[-1].split(".")[0]+".csv")
    ################
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Olu method')
    parser.add_argument('-c', action="store", default="/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db", help='catalog path')
    parser.add_argument('-i', action="store", default="/Users/seunfuta/Downloads/NIST/IMG/", help="image path folder")
    parser.add_argument('-o', action="store", default="/Users/seunfuta/Downloads/NIST/OLUSCAN/", help='output csv')
    args = parser.parse_args()
    onlyfiles = [f for f in listdir(args.i) if isfile(join(args.i, f))]
    for file in onlyfiles:
        print("IMAGE "+str(onlyfiles.index(file)) +" out of "+str(len(onlyfiles)))
        main(join(args.i+file))