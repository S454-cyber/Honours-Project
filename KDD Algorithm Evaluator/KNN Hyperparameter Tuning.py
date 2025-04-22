import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
from time import time
warnings.filterwarnings ('ignore')

pd.set_option ('display.float_format', lambda x: '%.3f' % x)
plt.rcParams ["figure.figsize"] = (10,6) 

#READING DATASET & ADJSUTING COLUMNS
readTrainFile = pd.read_csv ('KDDTrain+.txt')
organisedFile = readTrainFile.copy()
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
organisedFile.columns = columns
organisedFile.head(10)
organisedFile.info()
organisedFile.describe().T

#DATA CLEANING
organisedFile.isnull().sum()
def uniqueValues(organisedFile, columns):
    for columnName in columns:
        print(f"column: {columnName}\n{'-'*30}")
        uniqueValues = organisedFile[columnName].unique()
        valueCounts = organisedFile[columnName].value_counts()
        print(f"Unique Values ({len(uniqueValues)}): {uniqueValues}\n")
        print(f"Value Counts:\n{valueCounts}\n{'='*40}\n")
catFeatures = organisedFile.select_dtypes(include='object').columns
uniqueValues(organisedFile, catFeatures)

organisedFile.duplicated().sum()

organisedFile.shape
plt.figure(figsize=(20,40))
organisedFile.plot(kind='box', subplots=True, layout=(8,5), figsize=(20,40))
plt.show()
attackClassifier = []
for i in organisedFile.attack:
    if i == 'normal':
        attackClassifier.append("normal")
    else:
        attackClassifier.append("attack")
organisedFile['attack'] = attackClassifier
organisedFile['attack'].unique()\

#PREPROCESSING
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

#TOP FEATURES FOR TRAINING
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
    print(classification_report(yTest, yPrediction, digits=6))
    print()
    print("Train Set")
    print(confusion_matrix(yTrain, yTrainPrediction))
    print(classification_report(yTrain, yTrainPrediction, digits=6))

#HYPERPARAMETER TUNING
from sklearn.model_selection import GridSearchCV
from  sklearn.model_selection import RepeatedStratifiedKFold

#K-Nearest Neighbour (Check Parameters)
#SOURCE: https://machinelearningmastery.com/hyperparameters-for-classification-machine-learning-algorithms/
from sklearn.neighbors import KNeighborsClassifier
knnModel = KNeighborsClassifier()
n_neighbour = range(1, 21)
weights = ['uniform', 'distance']
metric = ['euclidean','manhattan','minkowski']

knnGrid = dict(n_neighbour=n_neighbour, weights=weights, metric=metric)
knnCV = RepeatedStratifiedKFold(n_splits=10, n_repeats=3, random_state=1)
gridSearchKNN = GridSearchCV(estimator=knnModel, param_grid=knnGrid, n_jobs=-1, cv=knnCV, scoring='accuracy', error_score=0)
start = time()
gridResultKNN = gridSearchKNN.fit(xTrain, yTrain)
end = time()
print("Best: %f using %s" % (gridResultKNN.best_score_, gridResultKNN.best_params_))
means = gridResultKNN.cv_results_['mean_test_score']
stds = gridResultKNN.cv_results_['std_test_score']
params = gridResultKNN.cv_results_['params']
for mean, stdev, param in zip(means, stds, params):
    print("%f (%f) with: %r" % (mean, stdev, param))
result = end - start
print('%.3f seconds' % result)
print("K-Nearest Neighbour Hyperparameter Tuning Done!")