#Source Used to Build Foundation of Code: https://www.kaggle.com/code/eneskosar19/intrusion-detection-system-nsl-kdd#6.3-EVALUATION
#To run this code, please copy into a local environment with the full data set listed.
#To run with the full dataset, change line 23 "KDDTrain+.txt" > "KDDCupp99_full.txt" and have associated .txt file in same folder as code.

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
pd.set_option ('display.float_format', lambda x: '%.3f' % x)
plt.rcParams ["figure.figsize"] = (10,6) 

#Reading the "KDDTrain+.txt"[chnage to name of dataset being used] and creating a copy of the dataset to assign column names to.
readTrainFile = pd.read_csv ('KDDTrain+.txt') 
organisedFile = readTrainFile.copy()
#Naming each column of dataset.
columns = (['duration' #Duration of connection in seconds
            ,'protocolType' #Protocol used for the connection (ICMP, UDP, TCP, etc.)
            ,'service' #Destination port that is mapped to a service (HTTP, FTP, HTTPS, etc.)
            ,'flag' #Normal or error status flag of connection (SF, S0 & REJ)
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
            ,'isHotLogin' #'1' is the login belongs to a 'hot' list (e.g. root, admin); else 0
            ,'isGuestLogin' #'1' is if the login is a 'guest' login (e.g. guest, anonymous, etc.); else 0
            ,'count' #The number of connections to the same host as current connections in past two seconds
            ,'srvCount' #The number of connections tot he same service as the curent connection in the past two seconds
            ,'serrorRate' #The percetage(%) of connections that have 'SYN' errors
            ,'srvSerrorRate' #The percetage(%) of connections that have 'SYN' errors
            ,'rerrorRate' #The percetage(%) of connections that have 'REJ' errors
            ,'srvRerrorRate' #The percetage(%) of connections that have 'REJ' errors
            ,'sameSrvRate' #The percentage(%) of connections to the same services
            ,'diffSrvRate' #The percentage(%) of connections to different services
            ,'srvDiffHostRate' #The percentage(%) of connections to different hosts
            ,'destinationHostCount' #The count of the connections that have the same destination host
            ,'destinationHostSrvCount' #The count of the connections that have the same destination host and using the same service
            ,'destinationHostSameSrvCount' #The percentage(%) of connections having the same destination port and using the same service
            ,'destinationHostDiffSrvCount' #The percentage(%) of different services on the current host
            ,'destinationHostSameSourcePortRate' #The percentage(%) of connections to the current host having the same source port
            ,'destinationHostSrvDifferentHostRate' #The percentage(%) of connections to the same service coming from a different host
            ,'destinationHostSerrorRate' #The percentage(%) of connections to the current host that have an S0 error
            ,'destinationHostSrvSerrorRate' #The percentage(%) of connections to the current host and specified service that have an S0 error
            ,'destinationHostRerrorRate' #The percentage(%) of connections to the current host that have an RST error
            ,'destinationHostSrvRerrorRate' #The percentage(%) of connections to the  current host and specified service
            ,'attack' #Classifying whether the attack was considered normal or an anomaly 
            ,'level']) #Classifying the level of the attack
#Assigning the columsn to the dataset, displaying the first 10 entries to the screen and displaying information about the dataset.
organisedFile.columns = columns
organisedFile.head(10)
organisedFile.info()
organisedFile.describe().T

#Finds total sum of data points where the data value is null/empty.
organisedFile.isnull().sum()
#Creating a helper function which will find the total sum of unique values across all columns of the dataset.
def uniqueValues(organisedFile, columns):
    for columnName in columns:
        print(f"column: {columnName}\n{'-'*30}")
        uniqueValues = organisedFile[columnName].unique()
        valueCounts = organisedFile[columnName].value_counts()
        print(f"Unique Values ({len(uniqueValues)}): {uniqueValues}\n")
        print(f"Value Counts:\n{valueCounts}\n{'='*40}\n")

#Displaying the unique features of the data types as well as including the object of the column to the screen. 
#Provides total sum of duplicated values in the dataset.
catFeatures = organisedFile.select_dtypes(include='object').columns
uniqueValues(organisedFile, catFeatures)
organisedFile.duplicated().sum()

#Obtains current shape of array and specifying the figure size, in inches.
#Displaying data as a box plot graph with a specified layout and figure size, displayed to the screen.
organisedFile.shape
plt.figure(figsize=(20,40))
organisedFile.plot(kind='box', subplots=True, layout=(8,5), figsize=(20,40))
plt.show()

#Classifies whether a log entry is an anomaly or not and appending to the list attackClassifier.
attackClassifier = []
for i in organisedFile.attack:
    if i == 'normal':
        attackClassifier.append("normal")
    else:
        attackClassifier.append("attack")
organisedFile['attack'] = attackClassifier
#Displays unique attack entries within the dataset.
organisedFile['attack'].unique()