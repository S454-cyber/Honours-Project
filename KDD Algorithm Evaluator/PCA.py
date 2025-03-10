#Testing out Principal Component Analysis
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings ('ignore')

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

#Data Standardisation
from sklearn.preprocessing import StandardScaler
columns = ['duration','protocolType','service','flag','sourceByte','destinationByte','wrongFragment','hot','loggedIn','numberCompromised','count','srvCount','serrorRate','srvSerrorRate','rerrorRate']
#Feature seperation
x = organisedFile.loc[:, columns].values
#Target seperation
y = organisedFile.loc[:, ['attack']].values
#Standardising the features
x = StandardScaler().fit_transform(x)