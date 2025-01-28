#Source Used to Build Foundation of Code: https://www.kaggle.com/code/eneskosar19/intrusion-detection-system-nsl-kdd#6.3-EVALUATION

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
#Specifyign the size of the figure that is to be displayed to the screen. This will display a figure size of 20x40 inches (Width x Height).
plt.figure(figsize=(20,40))
#The data will be displayed as a box plot graph with a layout of 800x500 pixels and a figure size of 20x40 inches (Width x Height).
organisedFile.plot(kind='box', subplots=True, layout=(8,5), figsize=(20,40))
#Displaying the plotted graphs to the screen.
plt.show()
#ATTACK OR NON ATTACK CLASSIFICATION
#Creating a list with the name attackClassifier.
attackClassifier = []
#A for loop that analyses event within the dataset.
for i in organisedFile.attack:
    #If the event is considered normal, it will append the keyword 'Normal' to the list.
    #Else, if the event is considered an attack, it will append the keyword 'Attack' to the list.
    if i == 'normal':
        attackClassifier.append("Normal")
    else:
        attackClassifier.append("Attack")
        #Updating the attack column within the organisedFile data frame with the values of the attackClassifier variable.
organisedFile['Attack'] = attackClassifier

#Retrieving the unique values that are within the 'Attack' column, within the organisedFile data frame.
organisedFile['Attack'].unique()

#EDA - VISUALIZATION
#Used to provide visual insights on the dataset.
#Returns the binary version of 43 and is displayed in a figure that is 20x30 inches (Width x Height).
organisedFile.hist(bins = 43, figsize = (20,30));
#PROTOCOL TYPE
#Displays a figure that is 16x4 inches (Width x Height).
plt.figure(figsize = (16,4))
#Countplot is used to show the count of observation from datasets labelled as 'attack' observed in the KDD data set. The x-axis is labelled as 'attack'.
#Data distinction is sperated by the 'protocolType' column.
sns.countplot(x = 'attack', data = organisedFile, hue = 'protocolType')
#Rotating the location of the x-axis by 45 degrees.
plt.xticks(rotation = 45)
#Setting the title of the figure to 'Attack Counts over Protocol Type', with a fontsize of 16.
plt.title('Attack Counts over Protocol Type', fontdict = {'fontsize':16})
#Displaying the figure to the screen
plt.show()

organisedFile["protocolType"].value_counts(normalize = True)
#SERVICE USED GENERAL
#Displays a figure that is 20x8 inches (Width x Height).
plt.figure(figsize = (20,8))
#Countplot is used to show the count of observation of data labelled as 'service' observed in the KDD data set. The x-axis is labelled as 'service'.
ax = sns.countplot(x = 'service', data = organisedFile)
#Rotated labels.
ax.set_xticklabels(ax.get_xticklabels(), rotation = 45, ha = 'right')
#Setting the x-axis label as 'Service'
plt.xlabel('Service')
#Setting the y-axis label as 'Count'
plt.ylabel('Count')
#Setting the title of the figure to 'Count of Service'
plt.title('Count of Service')
plt.grid(True)
#Displaying the figure to the screen
plt.show()
#SERVICE USED EFFECT ON ATTACKS
#Displays a figure that is 20x8 inches (Width x Height).
plt.figure(figsize = (20,8))
ax = sns.countplot(x = 'service', hue = 'attack', data = organisedFile)
#Rotated labels.
ax.set_xticklabels(ax.get_xticklabels(), rotation = 45, ha = 'right')
plt.xlabel('service')
plt.ylabel('Count')
plt.title('Distribution of Attacks by Service')
plt.legend(title = 'Attack Type')
#Displays a grid line on every data point.
plt.grid(True)
#Displaying the figure to the screen
plt.show()
#KERNEL DESTINY ESTIMATE (KDE) PLOT OF DURATION BY FLAG
#Displays a figure that is 12x8 inches (Width x Height).
plt.figure(figsize = (12,8))
#The displot function is used to visualise the univariate and bivariate distribution of data as a Kernal Destiny Estimate (KDE) plot.
#The duration coumn is used as the variable on the x-axis.
#The flags column is used to determine the colour of the plot elements.

sns.displot(
    data = organisedFile,
    x = "duration",
    hue = "flag",
    kind = "kde",
    height = 6,
    multiple = "fill",
    clip = (0,None),
    palette = "ch:rot=-.25, hue = 1, light = 0.75",
)
plt.title('Kernal Density Estimate (KDE) Plot of Duration by Flag')
plt.grid(True)
#Displaying the figure to the screen
plt.show()
#DISTRIBUTION OF ATTACK TYPES BY GUEST LOGIN
#Displays a figure that is 10x6 inches (Width x Height).
plt.figure(figsize = (10,6))
sns.countplot(x = 'isGuestLogin', hue = 'attack', data = organisedFile, palette = 'Set2')
#The x-axis is given the label 'Is Guest Login'
plt.xlabel('Is Guest Login')
#The y-axis is given the label 'Count'
plt.ylabel('Count')
#Setting the title of the figure to 'Distribution of Attack Type by Guest Login'
plt.title('Distribution of Attack Type by Guest Login')
#The title of the legends for the graph is 'Attack Type'
plt.legend(title = 'Attack Type')
plt.grid(True)
#Displaying the figure to the screen
plt.show()

#PREPROCESSING
#ENCODING
catFeatures = organisedFile.select_dtypes(include = 'object').columns
catFeatures
#TRAIN-TEST-SPLIT
#FEATURE ENGINEERING
#FEATURE SELECTION
#SCALNG

#MODEL BUILD
#HYPERPARAMETER TUNING
#FINAL MODEL
#EVALUATION

#FEATURE IMPORTANCE