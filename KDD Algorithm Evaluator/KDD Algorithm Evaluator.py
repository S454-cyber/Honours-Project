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
readTrainFile = pd.read_csv ("KDDTrain+.txt") 
#Variable df_0 is using the .copy() method to create copies of the "KDDTrain+.txt" file.
#New variable name of df has been given.
organisedFile = readTrainFile.copy()
#ADJUSTING COLUMNS
#Giving names to each column of the KDD datset to make it easier to identify value category.
columns = (['duration'
            ,'protocolType'
            ,'service'
            ,'flag'
            ,'sourceByte'
            ,'destinationByte'
            ,'land'
            ,'wrongFragemnt'
            ,'urgent'
            ,'hot'
            ,'numberFailedLogins'
            ,'loggedIn'
            ,'numberCompromised'
            ,'rootShell'
            ,'suAttempted'
            ,'numRoot'
            ,'numberFileCreations'
            ,'numberShells'
            ,'numberAccessFiles'
            ,'numberOutboundCommands'
            ,'isHostLogin'
            ,'isGuestLogin'
            ,'count'
            ,'srvCount'
            ,'serrorRate'
            ,'srvSerrorRate'
            ,'rerrorRate'
            ,'srvRerrorRate'
            ,'sameSrvRate'
            ,'diffSrvRate'
            ,'srvDiffHostRate'
            ,'destinationHostCount'
            ,'destinationHostSrvCount'
            ,'destinationHostSameSrvCount'
            ,'destinationHostDiffSrvCount'
            ,'destinationHostSameSourcePortRate'
            ,'destinationHostSrvDifferentHostRate'
            ,'destinationHostSerrorRate'
            ,'destinationHostSrvSerrorRate'
            ,'destinationHostRerrorRate'
            ,'destinationHostSrvRerrorRate'
            ,'attack'
            ,'level'])
#Assigning the labels of each column to the ones defined above to the KDD dataset.
organisedFile.columns = columns
#Displaying a section of the organised CSV file as a table to the screen. 
#Displays 5 rows by default as no number of rows to display has been specified.
organisedFile.head()
#INSIGHTS
#Displaying information about the KDD data frame to the screen.
organisedFile.info()
#Displaying descriptions of the transposed (T) KDD data fram to the screen.
organisedFile.describe().T

#DATA CLEANING
#NULL VALUES
#DUPLCIATES
#OUTLIERS
#ATTACK OR NON ATTACK CLASSIFICATION

