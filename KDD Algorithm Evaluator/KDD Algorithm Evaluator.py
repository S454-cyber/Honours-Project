#Source Used: https://www.kaggle.com/code/eneskosar19/intrusion-detection-system-nsl-kdd#6.3-EVALUATION

#IMPORTING LIBRARIES
#Importing the numpy library (adding support for large, multi-dimensional arrarys and matricies).
#Importing Pandas library (data manipulation and analysis).
#Importing Matplotlib library (Creating various forms of data visullisations).
#Importing Seaborn library (Creating high-level data visualisation interfaces).
#Importing Warnings library.
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings

warnings.filterwarnings ('ignore')
#%matplotlib warnings: A magical function that is only valid in Jupyter notebooks. Commented out as it is not valid in python.
pd.set_option ('display.float_format', lambda x: '%.3f' % x)
plt.rcParams ["figure.figsize"] = (10,6)

#READING DATASET
#Reading the CSV file named "KDDTrain+.txt" stored locally in the same location as this python file using pandas.
#Variable name df_0 has been given.
df_0 = pd.read_csv ("KDDTrain+.txt") 
#Variable df_0 is using the .copy() method to creat copies of the "KDDTrain+.txt" file.
#New variable name of df has been given.
df = df_0.copy()
#Displaying a section of the organised CSV file as a table to the screen. 
#Displays 5 rows by default as no number of rows to display has been specified.
df.head()

