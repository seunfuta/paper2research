import sqlite3
import pandas as pd
import sys
import numpy as np
import argparse
from os import listdir
from os.path import isfile, join
'''
class args:
    i = "/Users/seunfuta/Downloads/NIST/IMG/sdelete-W7x64.db" #Wireshark-W7x64.db"
    c = "/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db"
    o = "/Users/seunfuta/Downloads/NIST/OLUSCAN/NEWER"
'''
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Olu method')
    parser.add_argument('-c', action="store", default="/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db", help='catalog path')
    parser.add_argument('-i', action="store", default="/Users/seunfuta/Downloads/NIST/IMG/Wireshark-W7x64.db", help="image path folder")
    parser.add_argument('-o', action="store", default="/Users/seunfuta/Downloads/NIST/OLUSCAN/NEWER", help='output csv')
    args = parser.parse_args()
    
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
    #############
    print(args.i)#magefilepath)
    IMAGE_DB_PATH = args.i#imagefilepath
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
    #from collections import OrderedDict
    app_list = list(catalog_df.app.unique()) #['Wireshark-W7x64'] #
    print(app_list)
    result_df = pd.DataFrame()
    for app in app_list:#['TrueCrypt63-WinXP']:#TrueCrypt63-WinXP']:#sdelete-W7x64']:#app_list:
        #if app == 'OfficePro2003-W7x32':
        result_df.loc[app_list.index(app),'appname'] = app
        validated_app_matched = int(0)
        app_Prob = float(0)
        app_df = catalog_df[catalog_df.app == app]
        result_df.loc[app_list.index(app),'appsize'] = int(len(app_df))
        app_unique_md5s= app_df.md5.unique()
        matched_image_df = image_df[image_df.md5.isin(app_unique_md5s)]
        result_df.loc[app_list.index(app),'image_matches'] = int(len(matched_image_df))
        #print(app," matched number of sectors in image ",len(matched_image_df))
        #print(matched_image_df)
        #lets create app sec pairs
        app_files = app_df.filename.unique()
        #print(app_files)
        app_pairs_set = {} #dict #set() 
        #lst2 = list(matched_image_df.md5)
        #lst2_pairs = list(map(lambda a, b: a + b, lst2[:-1], lst2[1:]))
        #Prob_Total = float(0)
        file1 = app_files[2]
        print(file1)
        ################XXXXXXX##############
        matched_image_df.loc[:,'image_offset'] = matched_image_df.index
        ###notthing
        #matched_image_df_dict = matched_image_df.to_dict('records')
        #series_filename = pd.Series()
        #series_file_off = pd.Series()
        appfilenames= app_df.filename.unique()
        for filename in appfilenames:
            print(filename)
            series_file_off = pd.Series(index=[0,1,2,3,4],dtype = 'object')
            appfile_df = app_df[app_df.filename == filename]
            matched_image_appfile_df = matched_image_df[matched_image_df.filename == filename]
            #print(len(matched_image_appfile_df)," sectors", filename)
            matched_image_appfile_dict = matched_image_appfile_df.to_dict('records')
            counter = 0
            for row in matched_image_appfile_dict:
                #print(row)
                cluster_off = row['image_offset'] % 8
                
                catapphash_off = np.array(appfile_df.index[appfile_df.md5 == row['md5']])
                catapphash_off = catapphash_off % 8
                #print("catapphash_off ",catapphash_off)

                catapphash_filename = np.array(appfile_df.filename[appfile_df.md5 == row['md5']])
                #print("catapphash_filename ",catapphash_filename)
                catapphash_file_off = np.array(appfile_df.file_offset[appfile_df.md5 == row['md5']])/512
                #print("catapphash_file_off ", catapphash_file_off)
                #print(cluster_off, row['md5'],cluster_off in catapphash_off)
                #if cluster_off in catapphash_off:
                #print("image", row['image_offset'], row['md5'], "cluster off", cluster_off, catapphash_filename, catapphash_file_off )
                #series_filename[len(series_filename)] = catapphash_filename
                series_file_off[counter]= catapphash_file_off
                counter +=1
            #for index, value in series_file_off.iteritems():
                #if type(value)!= float and len(value) > 1: print(value)
            #print("series_file_off ",series_file_off)
            #lst2_pairs_f = list(map(lambda a, b: print(type(a),a,type(b),b),series_file_off[:-1],series_file_off[1:]))
            series_file_off = series_file_off.dropna()
            print("size of series ", len(series_file_off))
            if len(series_file_off) > 1:
                if filename == "Program Files/Wireshark/libglib-2.0-0.dll":
                    print(series_file_off)
                    for each in range(len(series_file_off)-1):
                        if series_file_off[each].shape[0]!=1 or series_file_off[each+1].shape[0]!=1:
                            print(series_file_off[each].shape, series_file_off[each+1].shape)

                lst2_pairs_f = list(map(lambda a, b: 1 if (b-a).any()==1 else 0,series_file_off[:-1],series_file_off[1:]))
                lst2_pairs_b = list(map(lambda a, b: 1 if (a-b).any()==1 else 0, series_file_off[1:],series_file_off[:-1]))
                if lst2_pairs_f[-1] == 1: lst2_pairs_f.extend([1]) 
                else: lst2_pairs_f.extend([0])
                if lst2_pairs_b[0] == 1: lst2_pairs_b.insert (0, 1) 
                else: lst2_pairs_b.insert (0, 0)  
                #print(lst2_pairs_f)
                #print(lst2_pairs_b)
                lst2_pairs = (pd.Series(lst2_pairs_f) | pd.Series(lst2_pairs_b))
            else: 
                lst2_pairs = (pd.Series([1]))
            #print(lst2_pairs)
            validated_app_matched += lst2_pairs.sum()
            file_Prob =float(lst2_pairs.sum()/float(len(appfile_df)))
            file_app_fraction = float(len(appfile_df))/float(len(app_df))
            #print("file Prob ", file_Prob, "app fraction", file_app_fraction)
            app_Prob += (file_Prob * file_app_fraction)
        result_df.loc[app_list.index(app),'validmatches'] = int(validated_app_matched)
        print("APP Prob ", app_Prob)
        result_df.loc[app_list.index(app),'ProbApp'] = round(app_Prob, 6)
    print(result_df)
    image_app = args.i.split("/")[-1][:-3]
    print(image_app)
    output_path = args.o+"/"+image_app+".csv"
    print(output_path)
    result_df['appsize'] = result_df['appsize'].astype('int64')
    result_df['image_matches'] = result_df['image_matches'].astype('int64')
    result_df['validmatches'] = result_df['validmatches'].astype('int64')
    result_df['ProbApp'] = result_df['ProbApp'].astype('float64')
    result_df['ProbApp'] = result_df['ProbApp'].round(decimals=6)
    result_df.to_csv(output_path, index=False)