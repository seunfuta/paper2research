import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_curve, auc

#table = pd.DataFrame({'id':[1,2,3,4,5,6,7,8,9,10],'class':[0,0,1,1,1,0,1,0,1,0],'p1':[0.35,0.05,0.70,0.45,0.40,0.30,0.80,0.15,0.65,0.60],'p2':[0.8,0.40,0.10,0.25,0.05,0.15,0.60,0.20,0.45,0.30]},columns=['id','class','p1','p2'])
#table 
from functools import partial
from itertools import repeat
from multiprocessing import Pool, freeze_support

def func(a, b):
    return a + b

def main2():
    a_args = [1,2,3]
    second_arg = 1
    with Pool() as pool:
        L = pool.starmap(func, [(1, 1), (2, 1), (3, 1)])
        M = pool.starmap(func, zip(a_args, repeat(second_arg)))
        N = pool.map(partial(func, b=second_arg), a_args)
        assert L == M == N

def main():
    pool_size = 3
    a_args = [1,2,3]
    second_arg = 1
    pool = Pool(processes=pool_size)
    #pool_outputs = pool.map(scan_list_v_world,list_of_file_dfs)
    pool_outputs = pool.starmap(func, zip(a_args, repeat(second_arg)))
    pool.close()
    pool.join()
    print(pool_outputs)
if __name__=="__main__":
    #freeze_support()
    main()