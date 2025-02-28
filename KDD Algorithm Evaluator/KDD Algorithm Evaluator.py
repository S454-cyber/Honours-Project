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
readTrainFile = pd.read_csv ('KDDTrain+.txt') 
#Variable df_0 is using the .copy() method to create copies of the "KDDTrain+.txt" file.
#New variable name of df has been given.
organisedFile = readTrainFile.copy()
#ADJUSTING COLUMNS
#Giving names to each column of the KDD datset to make it easier to identify value category.
columns = (['duration' #Duration of connection in seconds
            ,'protocolType' #Protocol used for the connection (ICMP, UDP, TCP, etc.)
            ,'service' #Destination port that is mapped to a service (HTTP, FTP, HTTPS, etc.)
            ,'flag' #Normal or error status flag of connection
            ,'sourceByte' #Number of data, in bytes, from source to destination
            ,'destinationByte' #Number of data bytes from destination to source
            ,'land' #'1' represents if the connection is from/to the same host/port; else '0'
            ,'wrongFragment' #Number of 'wrong' fragments (values 0,1,3)
            ,'urgent' #Number of urgent packets
            ,'hot' #Number of 'hot' indicators (bro-ids feature)
            ,'numberFailedLogins' #Number of failed login attempts
            ,'loggedIn' #'1' indicates if sucessfully logged, else '0'
            ,'numberCompromised' #Number of 'compromised' conditions
            ,'rootShell' #'1' indicates if root shell is obtained, otherwise '0'
            ,'suAttempted' #'1' indicates if "Super User Root" command was attempted, otherwise '0'
            ,'numRoot' #Number of root acesses 
            ,'numberFileCreations' #Number of file creation operations
            ,'numberShells' #Number of shell prompts
            ,'numberAccessFiles' #Number of operations on the acess control files
            ,'numberOutboundCommands' #Number of outbound commands within an ftp session
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
        attackClassifier.append("normal")
    else:
        attackClassifier.append("attack")
        #Updating the attack column within the organisedFile data frame with the values of the attackClassifier variable.
organisedFile['attack'] = attackClassifier

#Retrieving the unique values that are within the 'Attack' column, within the organisedFile data frame.
organisedFile['attack'].unique()

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
ax.set_xticklabels(ax.get_xticklabels(), rotation = 45, ha = "right")
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

from sklearn import preprocessing
labelEncoder = preprocessing.LabelEncoder()
clm = ['protocolType', 'service', 'flag', 'attack']
for x in clm:
    organisedFile[x] = labelEncoder.fit_transform(organisedFile[x])

#TRAIN-TEST-SPLIT
from sklearn.model_selection import train_test_split

x = organisedFile.drop(["attack"], axis=1)
y = organisedFile["attack"]

xTrain, xTest, yTrain, yTest = train_test_split(x, y, test_size=0.1, random_state=43)

trainIndex = xTrain.columns
trainIndex

#FEATURE ENGINEERING
from sklearn.feature_selection import mutual_info_classif
mutalInfo = mutual_info_classif(xTrain, yTrain)
mutalInfo = pd.Series(mutalInfo)
mutalInfo.index = trainIndex
mutalInfo.sort_values(ascending=False)

mutalInfo.sort_values(ascending=False).plot.bar(figsize=(20, 5));

#FEATURE SELECTION
from sklearn.feature_selection import SelectKBest
selectFeatures = SelectKBest(mutual_info_classif, k = 30)
selectFeatures.fit(xTrain, yTrain)
trainIndex[selectFeatures.get_support()]

#Select top features to be used for training
columns = ['duration','protocolType','service','flag','sourceByte','destinationByte','wrongFragment','hot','loggedIn','numberCompromised','count','srvCount','serrorRate','srvSerrorRate','rerrorRate']

xTrain = xTrain[columns]
xTest = xTest[columns]

#SCALNG
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()

#Transform is done to prevent data leakage
xTrain = scaler.fit_transform(xTrain)
xTest = scaler.fit_transform(xTest)

#MODEL BUILD
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, recall_score, precision_score, f1_score, roc_auc_score

def evaluationMetric (model, xTrain, yTrain, xTest, yTest):
    yTrainPrediction = model.predict(xTrain)
    yPrediction = model.predict(xTest)

    print ("Test Set")
    print(confusion_matrix(yTest, yPrediction))
    print(classification_report(yTest, yPrediction))
    print()
    print("Train Set")
    print(confusion_matrix(yTrain, yTrainPrediction))
    print(classification_report(yTrain, yTrainPrediction))

#Logistic Regression
from sklearn.linear_model import LogisticRegression
logisticModel = LogisticRegression(random_state = 42)
logistic = logisticModel.fit(xTrain, yTrain)

evaluationMetric(logisticModel, xTrain, yTrain, xTest, yTest)

#Support Vector Machine
from sklearn import svm
supportVectorModel = svm.SVC()
supportvector = supportVectorModel.fit (xTrain, yTrain)

evaluationMetric(supportVectorModel, xTrain, yTrain, xTest, yTest)

#Decision Tree

#K-Nearest Neighbour

#Naive Bayes

#K-Means

#Principal Component Analysis

#Logistic Regression

#Singular Value Decomposition

#Apriori

#Isolation Forest

#HYPERPARAMETER TUNING
#FINAL MODEL
#EVALUATION

#FEATURE IMPORTANCE