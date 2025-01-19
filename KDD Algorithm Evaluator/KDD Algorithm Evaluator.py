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
organisedFile.head(10)
#INSIGHTS
#Displaying information about the KDD data frame to the screen using the pandas library.
organisedFile.info()
#Displaying descriptions of the transposed (T) KDD data frame to the screen using the pandas library.
organisedFile.describe().T

#DATA CLEANING
#NULL VALUES
#Fidning the total sum of data points where the data value is null/empty.
organisedFile.isnull().sum()
#Creating a helper function which will allow for deeper analysis of the datapoints.
def uniqueValues(organisedFile, columns):
    #Displays unique values and their counts for specific columns within the data frame to the screen.
    for columnName in columns:
        #Displaying the column name the current data is related to to the screen.
        print(f"column: {columnName}\n{'-'*30}")
        #Sorting unique values by their columns name.
        uniqueValues = organisedFile[columnName].unique()
        #Sorting the count of a specific value by its column name.
        valueCounts = organisedFile[columnName].value_counts()
        #Displaying all the unique values of a specific column to the screen.
        print(f"Unique Values ({len(uniqueValues)}): {uniqueValues}\n")
        #Displaying the total count of the unique values to a specific column to the screen.
        print(f"Value Counts:\n{valueCounts}\n{'='*40}\n")

#Displaying the unique features of the data types as well as including the object of the column to the screen.
catFeatures = organisedFile.select_dtypes(include='object').columns
#Unique values to have the attributes of organisedFile and catFeatures.
uniqueValues(organisedFile, catFeatures)
#DUPLCIATES
#Calculating the total sum of duplicated entries.
organisedFile.duplicated().sum()
#OUTLIERS
#Obtaining the current shape of the array.
organisedFile.shape
#Specifyign the size of the figure that is to be displayed to the screen. This will display a figure size of 2000x4000 pixels.
plt.figure(figsize=(20,40))
#The data will be displayed as a box plot graph with a layout of 800x500 pixels and a figure size of 2000x4000 pixels.
organisedFile.plot(kind='box', subplots=True, layout=(8,5), figsize=(20,40))
#Displaying the plotted graphs to the screen.
plt.show()
#ATTACK OR NON ATTACK CLASSIFICATION
attackClassifier = []
for i in organisedFile.attack:
    if i == 'normal':
        attackClassifier.append("Normal")
    else:
        attackClassifier.append("Attack")
organisedFile['Attack'] = attackClassifier

organisedFile['Attack'].unique()